using PacketDotNet;
using System.Text;

namespace NetworkMonitor.Backend.ProtocolAnalyzers;

public static class DnsAnalyzer
{
    private enum DnsOpcode
    {
        Query = 0,
        InverseQuery = 1,
        Status = 2,
        Notify = 4,
        Update = 5
    }

    private enum DnsResponseCode
    {
        NoError = 0,
        FormatError = 1,
        ServerFailure = 2,
        NameError = 3,
        NotImplemented = 4,
        Refused = 5
    }

    private enum DnsRecordType : ushort
    {
        A = 1,
        NS = 2,
        CNAME = 5,
        SOA = 6,
        PTR = 12,
        MX = 15,
        TXT = 16,
        AAAA = 28,
        SRV = 33
    }

    public static ProtocolAnalysisResult AnalyzeDnsUdp(UdpPacket udp, ProtocolAnalysisResult result)
    {
        result.Protocol = "DNS";

        if (udp.PayloadData == null || udp.PayloadData.Length < 12)
        {
            result.Details = "DNS (malformed - too short)";
            result.RiskScore += 20;
            return result;
        }

        return AnalyzeDnsPayload(udp.PayloadData, result);
    }

    public static ProtocolAnalysisResult AnalyzeDnsTcp(TcpPacket tcp, ProtocolAnalysisResult result)
    {
        result.Protocol = "DNS";

        if (tcp.PayloadData == null || tcp.PayloadData.Length < 14) // TCP DNS has 2-byte length prefix
        {
            result.Details = "DNS (malformed - too short)";
            result.RiskScore += 20;
            return result;
        }

        // Skip the 2-byte length prefix for TCP DNS
        var dnsData = tcp.PayloadData.Skip(2).ToArray();
        return AnalyzeDnsPayload(dnsData, result);
    }

    private static ProtocolAnalysisResult AnalyzeDnsPayload(byte[] payload, ProtocolAnalysisResult result)
    {
        try
        {
            if (payload.Length < 12)
            {
                result.Details = "DNS (insufficient data)";
                result.RiskScore += 15;
                return result;
            }

            // Parse DNS header
            var transactionId = (ushort)((payload[0] << 8) | payload[1]);
            var flags = (ushort)((payload[2] << 8) | payload[3]);
            var questions = (ushort)((payload[4] << 8) | payload[5]);
            var answers = (ushort)((payload[6] << 8) | payload[7]);
            var authority = (ushort)((payload[8] << 8) | payload[9]);
            var additional = (ushort)((payload[10] << 8) | payload[11]);

            // Parse flags
            var isResponse = (flags & 0x8000) != 0;
            var opcode = (DnsOpcode)((flags >> 11) & 0x0F);
            var authoritativeAnswer = (flags & 0x0400) != 0;
            var truncated = (flags & 0x0200) != 0;
            var recursionDesired = (flags & 0x0100) != 0;
            var recursionAvailable = (flags & 0x0080) != 0;
            var responseCode = (DnsResponseCode)(flags & 0x000F);

            result.Metadata["TransactionId"] = transactionId;
            result.Metadata["IsResponse"] = isResponse;
            result.Metadata["Opcode"] = opcode.ToString();
            result.Metadata["Questions"] = questions;
            result.Metadata["Answers"] = answers;
            result.Metadata["Authority"] = authority;
            result.Metadata["Additional"] = additional;

            if (isResponse)
            {
                result.Metadata["ResponseCode"] = responseCode.ToString();
                result.Details = $"DNS Response - {responseCode}";
                
                if (responseCode != DnsResponseCode.NoError)
                {
                    result.RiskScore += 5;
                    result.Details += $" (Error: {responseCode})";
                }
            }
            else
            {
                result.Details = $"DNS Query - {opcode}";
            }

            // Analyze questions section
            var offset = 12;
            var queryNames = new List<string>();

            for (int i = 0; i < questions && offset < payload.Length; i++)
            {
                var (name, newOffset) = ParseDomainName(payload, offset);
                queryNames.Add(name);
                
                if (newOffset + 4 <= payload.Length)
                {
                    var queryType = (DnsRecordType)((payload[newOffset] << 8) | payload[newOffset + 1]);
                    var queryClass = (ushort)((payload[newOffset + 2] << 8) | payload[newOffset + 3]);
                    
                    result.Metadata[$"Query{i}_Name"] = name;
                    result.Metadata[$"Query{i}_Type"] = queryType.ToString();
                    result.Metadata[$"Query{i}_Class"] = queryClass;
                    
                    offset = newOffset + 4;
                }
                else
                {
                    break;
                }
            }

            if (queryNames.Any())
            {
                result.Details += $" | {string.Join(", ", queryNames.Take(3))}";
                if (queryNames.Count > 3)
                    result.Details += $" (+{queryNames.Count - 3} more)";
            }

            // Security analysis
            AnalyzeDnsSecurity(queryNames, isResponse, responseCode, opcode, result);

            // Check for suspicious patterns
            if (truncated)
            {
                result.RiskScore += 10;
                result.SecurityFlags.Add("Truncated DNS message");
            }

            if (questions > 10)
            {
                result.RiskScore += 15;
                result.SecurityFlags.Add("Unusual number of DNS questions");
            }
        }
        catch (Exception ex)
        {
            result.Details = $"DNS parsing error: {ex.Message}";
            result.RiskScore += 25;
        }

        return result;
    }

    private static (string name, int offset) ParseDomainName(byte[] data, int startOffset)
    {
        var parts = new List<string>();
        var offset = startOffset;
        var jumped = false;
        var originalOffset = startOffset;

        while (offset < data.Length)
        {
            var length = data[offset];
            
            if (length == 0) // End of name
            {
                offset++;
                break;
            }
            else if ((length & 0xC0) == 0xC0) // Compression pointer
            {
                if (!jumped)
                {
                    originalOffset = offset + 2;
                    jumped = true;
                }
                
                var pointer = ((length & 0x3F) << 8) | data[offset + 1];
                offset = pointer;
                
                if (offset >= data.Length)
                    break;
            }
            else // Regular label
            {
                if (offset + length + 1 > data.Length)
                    break;
                
                var label = Encoding.ASCII.GetString(data, offset + 1, length);
                parts.Add(label);
                offset += length + 1;
            }
        }

        var domainName = string.Join(".", parts);
        var finalOffset = jumped ? originalOffset : offset;
        
        return (domainName, finalOffset);
    }

    private static void AnalyzeDnsSecurity(List<string> queryNames, bool isResponse, DnsResponseCode responseCode, DnsOpcode opcode, ProtocolAnalysisResult result)
    {
        // Limit analysis to prevent performance issues with many queries
        foreach (var name in queryNames.Take(10))
        {
            if (string.IsNullOrWhiteSpace(name)) continue;
            
            // Check for suspicious domain patterns
            if (IsSuspiciousDomain(name))
            {
                result.RiskScore += 25;
                result.SecurityFlags.Add($"Suspicious domain: {name}");
            }

            // Check for DNS tunneling indicators
            if (IsPotentialDnsTunneling(name))
            {
                result.RiskScore += 30;
                result.SecurityFlags.Add($"Potential DNS tunneling: {name}");
            }

            // Check for DGA (Domain Generation Algorithm) patterns
            if (IsPotentialDga(name))
            {
                result.RiskScore += 35;
                result.SecurityFlags.Add($"Potential DGA domain: {name}");
            }
        }

        // Check for DNS amplification attack patterns
        if (!isResponse && opcode == DnsOpcode.Query && queryNames.Any(n => n.Length > 50))
        {
            result.RiskScore += 20;
            result.SecurityFlags.Add("Potential DNS amplification query");
        }

        // Check response patterns
        if (isResponse && responseCode == DnsResponseCode.NameError && queryNames.Any())
        {
            result.SecurityFlags.Add("NXDOMAIN response");
        }
    }

    private static bool IsSuspiciousDomain(string domain)
    {
        if (string.IsNullOrEmpty(domain)) return false;

        // Check for known suspicious TLDs or patterns
        var suspiciousTlds = new[] { ".tk", ".ml", ".ga", ".cf", ".bit" };
        var suspiciousPatterns = new[] { "dyndns", "no-ip", "freedns" };

        return suspiciousTlds.Any(tld => domain.EndsWith(tld, StringComparison.OrdinalIgnoreCase)) ||
               suspiciousPatterns.Any(pattern => domain.Contains(pattern, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsPotentialDnsTunneling(string domain)
    {
        if (string.IsNullOrEmpty(domain)) return false;

        // DNS tunneling often uses long subdomains with encoded data
        var parts = domain.Split('.');
        
        // Check for unusually long subdomain labels
        if (parts.Any(part => part.Length > 40))
            return true;

        // Check for high entropy in subdomain (potential encoded data)
        var subdomain = parts.FirstOrDefault();
        if (subdomain != null && subdomain.Length > 20)
        {
            var entropy = CalculateEntropy(subdomain);
            if (entropy > 4.5) // High entropy suggests encoded data
                return true;
        }

        return false;
    }

    private static bool IsPotentialDga(string domain)
    {
        if (string.IsNullOrEmpty(domain)) return false;

        var parts = domain.Split('.');
        var mainDomain = parts.FirstOrDefault();
        
        if (mainDomain == null || mainDomain.Length < 8) return false;

        // DGA domains often have:
        // 1. High consonant-to-vowel ratio
        // 2. Random-looking character sequences
        // 3. Limited dictionary words

        var vowels = "aeiou";
        var consonantCount = mainDomain.Count(c => char.IsLetter(c) && !vowels.Contains(char.ToLower(c)));
        var vowelCount = mainDomain.Count(c => vowels.Contains(char.ToLower(c)));
        
        if (vowelCount == 0) return true; // No vowels is suspicious
        
        var consonantVowelRatio = (double)consonantCount / vowelCount;
        
        // High ratio suggests DGA
        return consonantVowelRatio > 3.0;
    }

    private static double CalculateEntropy(string input)
    {
        if (string.IsNullOrEmpty(input)) return 0;

        var charCounts = new Dictionary<char, int>();
        foreach (var c in input)
        {
            charCounts[c] = charCounts.GetValueOrDefault(c, 0) + 1;
        }

        double entropy = 0;
        foreach (var count in charCounts.Values)
        {
            var probability = (double)count / input.Length;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }
}