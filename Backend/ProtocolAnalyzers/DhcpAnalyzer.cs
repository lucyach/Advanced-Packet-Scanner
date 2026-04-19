using PacketDotNet;
using System.Net;
using System.Text;

namespace NetworkMonitor.Backend.ProtocolAnalyzers;

public static class DhcpAnalyzer
{
    private enum DhcpOpcode : byte
    {
        BootRequest = 1,
        BootReply = 2
    }

    private enum DhcpMessageType : byte
    {
        Discover = 1,
        Offer = 2,
        Request = 3,
        Decline = 4,
        Ack = 5,
        Nak = 6,
        Release = 7,
        Inform = 8
    }

    public static ProtocolAnalysisResult AnalyzeDhcp(UdpPacket udp, ProtocolAnalysisResult result)
    {
        result.Protocol = "DHCP";

        if (udp.PayloadData == null || udp.PayloadData.Length < 240)
        {
            result.Details = "DHCP (malformed - too short)";
            result.RiskScore += 15;
            return result;
        }

        try
        {
            var payload = udp.PayloadData;

            // Parse DHCP header
            var opcode = (DhcpOpcode)payload[0];
            var htype = payload[1]; // Hardware type
            var hlen = payload[2];  // Hardware address length
            var hops = payload[3];
            var xid = BitConverter.ToUInt32(payload, 4);
            var secs = BitConverter.ToUInt16(payload, 8);
            var flags = BitConverter.ToUInt16(payload, 10);
            
            // IP addresses
            var ciaddr = new IPAddress(payload.Skip(12).Take(4).ToArray()); // Client IP
            var yiaddr = new IPAddress(payload.Skip(16).Take(4).ToArray()); // Your IP
            var siaddr = new IPAddress(payload.Skip(20).Take(4).ToArray()); // Server IP
            var giaddr = new IPAddress(payload.Skip(24).Take(4).ToArray()); // Gateway IP

            // Client hardware address (MAC)
            var chaddr = payload.Skip(28).Take(hlen).ToArray();
            var macAddress = hlen == 6 ? 
                string.Join(":", chaddr.Select(b => b.ToString("X2"))) : 
                Convert.ToHexString(chaddr);

            result.Metadata["Opcode"] = opcode.ToString();
            result.Metadata["TransactionId"] = xid;
            result.Metadata["ClientIP"] = ciaddr.ToString();
            result.Metadata["YourIP"] = yiaddr.ToString();
            result.Metadata["ServerIP"] = siaddr.ToString();
            result.Metadata["GatewayIP"] = giaddr.ToString();
            result.Metadata["ClientMAC"] = macAddress;
            result.Metadata["Hops"] = hops;

            // Check for DHCP magic cookie (should be 0x63825363)
            if (payload.Length >= 240)
            {
                var magicCookie = BitConverter.ToUInt32(payload, 236);
                if (magicCookie != 0x63538263) // Note: byte order
                {
                    result.RiskScore += 25;
                    result.SecurityFlags.Add("Invalid DHCP magic cookie");
                }
            }

            // Parse DHCP options
            var messageType = DhcpMessageType.Discover; // Default
            var options = new Dictionary<byte, byte[]>();
            
            if (payload.Length > 240)
            {
                ParseDhcpOptions(payload.Skip(240).ToArray(), options);
                
                if (options.ContainsKey(53)) // DHCP Message Type
                {
                    messageType = (DhcpMessageType)options[53][0];
                    result.Metadata["MessageType"] = messageType.ToString();
                }
            }

            result.Details = $"DHCP {messageType}";
            
            if (opcode == DhcpOpcode.BootRequest)
            {
                result.Details += $" from {macAddress}";
            }
            else
            {
                result.Details += $" to {macAddress}";
                if (!yiaddr.Equals(IPAddress.Any))
                {
                    result.Details += $" | Offering: {yiaddr}";
                }
            }

            // Security analysis
            AnalyzeDhcpSecurity(opcode, messageType, options, giaddr, result);
            
            // Parse additional relevant options
            ParseRelevantOptions(options, result);
        }
        catch (Exception ex)
        {
            result.Details = $"DHCP parsing error: {ex.Message}";
            result.RiskScore += 20;
        }

        return result;
    }

    private static void ParseDhcpOptions(byte[] optionsData, Dictionary<byte, byte[]> options)
    {
        int offset = 0;
        
        while (offset < optionsData.Length)
        {
            byte optionType = optionsData[offset];
            offset++;

            if (optionType == 0) // Pad option
                continue;
                
            if (optionType == 255) // End option
                break;

            if (offset >= optionsData.Length)
                break;

            byte length = optionsData[offset];
            offset++;

            if (offset + length > optionsData.Length)
                break;

            var optionData = optionsData.Skip(offset).Take(length).ToArray();
            options[optionType] = optionData;
            
            offset += length;
        }
    }

    private static void ParseRelevantOptions(Dictionary<byte, byte[]> options, ProtocolAnalysisResult result)
    {
        // Option 1: Subnet Mask
        if (options.ContainsKey(1) && options[1].Length == 4)
        {
            var subnet = new IPAddress(options[1]);
            result.Metadata["SubnetMask"] = subnet.ToString();
        }

        // Option 3: Router
        if (options.ContainsKey(3) && options[3].Length >= 4)
        {
            var router = new IPAddress(options[3].Take(4).ToArray());
            result.Metadata["Router"] = router.ToString();
        }

        // Option 6: Domain Name Server
        if (options.ContainsKey(6) && options[6].Length >= 4)
        {
            var dnsServers = new List<string>();
            for (int i = 0; i < options[6].Length; i += 4)
            {
                if (i + 4 <= options[6].Length)
                {
                    var dns = new IPAddress(options[6].Skip(i).Take(4).ToArray());
                    dnsServers.Add(dns.ToString());
                }
            }
            result.Metadata["DNSServers"] = string.Join(", ", dnsServers);
        }

        // Option 12: Host Name
        if (options.ContainsKey(12))
        {
            var hostname = Encoding.ASCII.GetString(options[12]);
            result.Metadata["Hostname"] = hostname;
        }

        // Option 15: Domain Name
        if (options.ContainsKey(15))
        {
            var domain = Encoding.ASCII.GetString(options[15]);
            result.Metadata["Domain"] = domain;
        }

        // Option 50: Requested IP Address
        if (options.ContainsKey(50) && options[50].Length == 4)
        {
            var requestedIp = new IPAddress(options[50]);
            result.Metadata["RequestedIP"] = requestedIp.ToString();
        }

        // Option 54: Server Identifier
        if (options.ContainsKey(54) && options[54].Length == 4)
        {
            var serverId = new IPAddress(options[54]);
            result.Metadata["ServerIdentifier"] = serverId.ToString();
        }

        // Option 60: Vendor Class Identifier
        if (options.ContainsKey(60))
        {
            var vendorClass = Encoding.ASCII.GetString(options[60]);
            result.Metadata["VendorClass"] = vendorClass;
        }
    }

    private static void AnalyzeDhcpSecurity(DhcpOpcode opcode, DhcpMessageType messageType, 
        Dictionary<byte, byte[]> options, IPAddress gatewayIp, ProtocolAnalysisResult result)
    {
        // Check for rogue DHCP server indicators
        if (opcode == DhcpOpcode.BootReply && (messageType == DhcpMessageType.Offer || messageType == DhcpMessageType.Ack))
        {
            // Check if server identifier matches expected ranges
            if (options.ContainsKey(54) && options[54].Length == 4)
            {
                var serverId = new IPAddress(options[54]);
                if (IsUnusualDhcpServer(serverId))
                {
                    result.RiskScore += 30;
                    result.SecurityFlags.Add($"Unusual DHCP server: {serverId}");
                }
            }

            // Check for suspicious DNS servers
            if (options.ContainsKey(6))
            {
                for (int i = 0; i < options[6].Length; i += 4)
                {
                    if (i + 4 <= options[6].Length)
                    {
                        var dns = new IPAddress(options[6].Skip(i).Take(4).ToArray());
                        if (IsSuspiciousDnsServer(dns))
                        {
                            result.RiskScore += 25;
                            result.SecurityFlags.Add($"Suspicious DNS server: {dns}");
                        }
                    }
                }
            }

            // Check for suspicious gateway
            if (!gatewayIp.Equals(IPAddress.Any) && IsSuspiciousGateway(gatewayIp))
            {
                result.RiskScore += 20;
                result.SecurityFlags.Add($"Suspicious gateway: {gatewayIp}");
            }
        }

        // Check for DHCP starvation attack indicators
        if (messageType == DhcpMessageType.Discover || messageType == DhcpMessageType.Request)
        {
            // This would need to be tracked over time - for now, just flag high frequency
            result.Metadata["PotentialStarvationAttack"] = "Monitor frequency";
        }

        // Check for unusual vendor class
        if (options.ContainsKey(60))
        {
            var vendorClass = Encoding.ASCII.GetString(options[60]);
            if (IsUnusualVendorClass(vendorClass))
            {
                result.RiskScore += 15;
                result.SecurityFlags.Add($"Unusual vendor class: {vendorClass}");
            }
        }
    }

    private static bool IsUnusualDhcpServer(IPAddress serverIp)
    {
        // Check if server is in unexpected ranges
        var bytes = serverIp.GetAddressBytes();
        
        // Common DHCP server ranges are typically in router IPs
        // This is a basic check - you'd want to customize this based on your network
        return !IsPrivateIP(serverIp) || 
               (bytes[0] == 192 && bytes[1] == 168 && bytes[3] > 10 && bytes[3] < 250); // Unusual for DHCP server
    }

    private static bool IsSuspiciousDnsServer(IPAddress dnsIp)
    {
        // Check for known malicious DNS servers or unusual public DNS
        var suspiciousDns = new[]
        {
            "8.8.4.4", "1.1.1.1", "208.67.222.222" // These are legitimate, but might be suspicious in corporate environments
        };
        
        return !IsPrivateIP(dnsIp) && !suspiciousDns.Contains(dnsIp.ToString());
    }

    private static bool IsSuspiciousGateway(IPAddress gatewayIp)
    {
        // Gateway should typically be a private IP and commonly .1 or .254
        if (!IsPrivateIP(gatewayIp))
            return true;
            
        var bytes = gatewayIp.GetAddressBytes();
        var lastOctet = bytes[3];
        
        // Most gateways are .1, .254, or .2-.10
        return !(lastOctet == 1 || lastOctet == 254 || (lastOctet >= 2 && lastOctet <= 10));
    }

    private static bool IsUnusualVendorClass(string vendorClass)
    {
        // Check for unusual or suspicious vendor classes
        var suspiciousVendors = new[] { "MSFT", "android", "iPhone" };
        var lowerVendor = vendorClass.ToLower();
        
        // Very long vendor class strings might be suspicious
        if (vendorClass.Length > 50)
            return true;
            
        // Check for non-printable characters
        return vendorClass.Any(c => !char.IsControl(c) && c < 32);
    }

    private static bool IsPrivateIP(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        
        return bytes[0] switch
        {
            10 => true,
            172 => bytes[1] >= 16 && bytes[1] <= 31,
            192 => bytes[1] == 168,
            _ => false
        };
    }
}