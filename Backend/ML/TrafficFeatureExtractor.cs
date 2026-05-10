using System.Collections.Concurrent;
using PacketDotNet;

namespace NetworkMonitor.Backend.ML;

/// <summary>
/// Extracts 40+ features from network packets for ML-based traffic classification.
/// Features include packet statistics, payload characteristics, and protocol information.
/// </summary>
public static class TrafficFeatureExtractor
{
    // Port categorization
    private static readonly HashSet<int> WellKnownPorts = new() { 20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 554, 587, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443 };
    private static readonly HashSet<int> GamingPorts = new() { 3074, 3478, 3479, 3480, 27015, 27036, 7777, 19132, 25565, 27960, 28960 };
    private static readonly HashSet<int> StreamingPorts = new() { 1935, 554, 1755, 1936, 8554, 1755, 135, 6667 };
    private static readonly HashSet<int> P2PPorts = new() { 6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 51413, 12345, 65432 };
    private static readonly HashSet<int> VoIPPorts = new() { 5060, 5061, 5062, 5063, 5064, 5090, 5091, 5100, 5101 };

    /// <summary>
    /// Extracts ML features from a packet for classification.
    /// Returns a feature vector with 40+ dimensions.
    /// </summary>
    public static TrafficFeatureVector ExtractFeatures(
        Packet packet,
        IPPacket ipPacket,
        string applicationProtocol,
        string appProtocolConfidence)
    {
        var features = new TrafficFeatureVector();

        try
        {
            // Extract basic packet information
            var srcPort = TryGetSourcePort(packet);
            var dstPort = TryGetDestinationPort(packet);
            var payload = GetPayload(packet);
            var packetSize = packet.Bytes.Length;
            var payloadSize = payload.Length;

            // 1-5: Packet size features
            features.PacketSize = packetSize;
            features.PayloadSize = payloadSize;
            features.PacketSizeCategory = CategorizePacketSize(packetSize);
            features.PayloadRatio = payloadSize > 0 ? (double)payloadSize / packetSize : 0;
            features.HeaderSize = packetSize - payloadSize;

            // 6-10: Port features
            features.SourcePort = srcPort;
            features.DestinationPort = dstPort;
            features.IsSourceWellKnown = WellKnownPorts.Contains(srcPort) ? 1f : 0f;
            features.IsDestinationWellKnown = WellKnownPorts.Contains(dstPort) ? 1f : 0f;
            features.PortDifference = Math.Abs(srcPort - dstPort);

            // 11-15: Protocol features
            features.ProtocolType = (int)ipPacket.Protocol;
            features.IsTCP = ipPacket.Protocol == ProtocolType.Tcp ? 1f : 0f;
            features.IsUDP = ipPacket.Protocol == ProtocolType.Udp ? 1f : 0f;
            features.IsICMP = ipPacket.Protocol == ProtocolType.Icmp ? 1f : 0f;
            features.TTL = ipPacket.TimeToLive;

            // 16-20: TCP-specific features
            if (packet.Extract<TcpPacket>() is TcpPacket tcp)
            {
                features.TCPFlagsSet = (int)tcp.AllFlags;
                features.IsTCPSyn = tcp.Synchronize ? 1f : 0f;
                features.IsTCPAck = tcp.Acknowledgment ? 1f : 0f;
                features.IsTCPFin = tcp.Finished ? 1f : 0f;
                features.IsTCPRst = tcp.Reset ? 1f : 0f;
                features.WindowSize = tcp.WindowSize;
            }

            // 21-25: Payload analysis
            features.PayloadEntropy = CalculateEntropy(payload);
            features.PayloadHasText = HasPrintableText(payload) ? 1f : 0f;
            features.PayloadHasNull = payload.Contains((byte)0) ? 1f : 0f;
            features.PayloadMeanByte = payload.Length > 0 ? payload.Average(b => (double)b) : 0;
            features.PayloadVariance = CalculateVariance(payload);

            // 26-30: Port category features
            features.IsGamingPort = (GamingPorts.Contains(srcPort) || GamingPorts.Contains(dstPort)) ? 1f : 0f;
            features.IsStreamingPort = (StreamingPorts.Contains(srcPort) || StreamingPorts.Contains(dstPort)) ? 1f : 0f;
            features.IsP2PPort = (P2PPorts.Contains(srcPort) || P2PPorts.Contains(dstPort)) ? 1f : 0f;
            features.IsVoIPPort = (VoIPPorts.Contains(srcPort) || VoIPPorts.Contains(dstPort)) ? 1f : 0f;
            features.IsHighPort = (srcPort > 49152 || dstPort > 49152) ? 1f : 0f;

            // 31-35: Application protocol features
            features.AppProtocolEncoded = EncodeProtocol(applicationProtocol);
            features.IsKnownProtocol = IsKnownProtocol(applicationProtocol) ? 1f : 0f;
            features.ProtocolConfidence = float.TryParse(appProtocolConfidence, out var conf) ? conf / 100f : 0.5f;
            features.IsEncrypted = IsLikelyEncrypted(payload, applicationProtocol) ? 1f : 0f;
            features.IsCompressed = IsLikelyCompressed(payload) ? 1f : 0f;

            // 36-40: IP-specific features
            features.SourceIPType = ClassifyIPType(ipPacket.SourceAddress.ToString());
            features.DestinationIPType = ClassifyIPType(ipPacket.DestinationAddress.ToString());
            features.IPTotalLength = ipPacket.TotalLength;
            features.IsFragmented = packet.Bytes.Length > 0 && (packet.Bytes[6] & 0x20) != 0 ? 1f : 0f;
            features.TTLBucket = CategorizeTTL(ipPacket.TimeToLive);

            return features;
        }
        catch (Exception ex)
        {
            // Return partially filled features on error
            return features;
        }
    }

    private static int CategorizePacketSize(int size)
    {
        return size switch
        {
            < 64 => 0,
            < 256 => 1,
            < 512 => 2,
            < 1024 => 3,
            < 1500 => 4,
            _ => 5
        };
    }

    private static double CalculateEntropy(byte[] data)
    {
        if (data.Length == 0) return 0;

        var freq = new int[256];
        foreach (var b in data)
            freq[b]++;

        double entropy = 0;
        var len = data.Length;
        for (int i = 0; i < 256; i++)
        {
            if (freq[i] == 0) continue;
            var p = freq[i] / (double)len;
            entropy -= p * Math.Log(p, 2);
        }

        return entropy;
    }

    private static double CalculateVariance(byte[] data)
    {
        if (data.Length < 2) return 0;

        var mean = data.Average(b => (double)b);
        var variance = data.Average(b => Math.Pow(b - mean, 2));
        return variance;
    }

    private static bool HasPrintableText(byte[] data)
    {
        var printableCount = data.Count(b => b >= 32 && b < 127);
        return printableCount > data.Length * 0.3;
    }

    private static int EncodeProtocol(string protocol)
    {
        return protocol.ToUpperInvariant() switch
        {
            "HTTP" => 1,
            "HTTPS" => 2,
            "FTP" => 3,
            "SSH" => 4,
            "TELNET" => 5,
            "SMTP" => 6,
            "POP3" => 7,
            "IMAP" => 8,
            "DNS" => 9,
            "DHCP" => 10,
            "NTP" => 11,
            "QUIC" => 12,
            "TLS" => 13,
            "RTSP" => 14,
            "RTP" => 15,
            "SIP" => 16,
            "STUN" => 17,
            "MDNS" => 18,
            "SSDP" => 19,
            "SMB" => 20,
            "RDP" => 21,
            "BITTORRENT" => 22,
            "TCP" => 23,
            "UDP" => 24,
            "ICMP" => 25,
            _ => 0 // Unknown
        };
    }

    private static bool IsKnownProtocol(string protocol)
    {
        var known = new[] { "HTTP", "HTTPS", "FTP", "SSH", "DNS", "SMTP", "POP3", "IMAP", "DHCP", "NTP", "QUIC", "TLS", "RTSP", "RTP", "SIP", "SMB", "RDP", "BitTorrent" };
        return known.Contains(protocol, StringComparer.OrdinalIgnoreCase);
    }

    private static bool IsLikelyEncrypted(byte[] payload, string protocol)
    {
        if (protocol.Equals("TLS", StringComparison.OrdinalIgnoreCase) ||
            protocol.Equals("HTTPS", StringComparison.OrdinalIgnoreCase) ||
            protocol.Equals("SSH", StringComparison.OrdinalIgnoreCase) ||
            protocol.Equals("QUIC", StringComparison.OrdinalIgnoreCase))
            return true;

        if (payload.Length < 2) return false;

        // Check for TLS handshake
        if (payload[0] == 0x16 && (payload[1] == 0x03 || payload[1] == 0x04))
            return true;

        // Check for SSH
        if (payload.Length > 4 && payload[0] == 0x53 && payload[1] == 0x53 && payload[2] == 0x48)
            return true;

        // High entropy suggests encryption
        var entropy = CalculateEntropy(payload);
        return entropy > 7.0;
    }

    private static bool IsLikelyCompressed(byte[] payload)
    {
        if (payload.Length < 2) return false;

        // GZIP magic bytes
        if (payload[0] == 0x1F && payload[1] == 0x8B) return true;

        // DEFLATE magic bytes
        if (payload[0] == 0x78 && (payload[1] == 0x9C || payload[1] == 0x01 || payload[1] == 0xDA)) return true;

        // Brotli magic bytes
        if (payload.Length >= 4 && payload[0] == 0xCE && payload[1] == 0xB2 && payload[2] == 0xCF && payload[3] == 0x81) return true;

        return false;
    }

    private static int ClassifyIPType(string ip)
    {
        if (string.IsNullOrEmpty(ip)) return 0;

        if (ip.StartsWith("192.168.") || ip.StartsWith("10.") || ip.StartsWith("172."))
            return 1; // Private
        if (ip.StartsWith("127."))
            return 2; // Loopback
        if (ip.StartsWith("169.254."))
            return 3; // Link-local
        if (ip.StartsWith("224.") || ip.StartsWith("225.") || ip.StartsWith("239."))
            return 4; // Multicast

        return 5; // Public
    }

    private static int CategorizeTTL(byte ttl)
    {
        return ttl switch
        {
            255 => 0,
            254 => 1,
            253 => 2,
            <= 128 => 3,
            <= 64 => 4,
            _ => 5
        };
    }

    private static int TryGetSourcePort(Packet packet)
    {
        return packet.Extract<TcpPacket>()?.SourcePort ?? packet.Extract<UdpPacket>()?.SourcePort ?? 0;
    }

    private static int TryGetDestinationPort(Packet packet)
    {
        return packet.Extract<TcpPacket>()?.DestinationPort ?? packet.Extract<UdpPacket>()?.DestinationPort ?? 0;
    }

    private static byte[] GetPayload(Packet packet)
    {
        return packet.Extract<TcpPacket>()?.PayloadData
            ?? packet.Extract<UdpPacket>()?.PayloadData
            ?? Array.Empty<byte>();
    }
}

/// <summary>
/// Feature vector for ML model input.
/// Contains 40+ features extracted from network packets.
/// </summary>
public class TrafficFeatureVector
{
    // Packet size features
    public int PacketSize { get; set; }
    public int PayloadSize { get; set; }
    public int PacketSizeCategory { get; set; }
    public double PayloadRatio { get; set; }
    public int HeaderSize { get; set; }

    // Port features
    public int SourcePort { get; set; }
    public int DestinationPort { get; set; }
    public float IsSourceWellKnown { get; set; }
    public float IsDestinationWellKnown { get; set; }
    public int PortDifference { get; set; }

    // Protocol features
    public int ProtocolType { get; set; }
    public float IsTCP { get; set; }
    public float IsUDP { get; set; }
    public float IsICMP { get; set; }
    public byte TTL { get; set; }

    // TCP-specific features
    public int TCPFlagsSet { get; set; }
    public float IsTCPSyn { get; set; }
    public float IsTCPAck { get; set; }
    public float IsTCPFin { get; set; }
    public float IsTCPRst { get; set; }
    public ushort WindowSize { get; set; }

    // Payload analysis
    public double PayloadEntropy { get; set; }
    public float PayloadHasText { get; set; }
    public float PayloadHasNull { get; set; }
    public double PayloadMeanByte { get; set; }
    public double PayloadVariance { get; set; }

    // Port category features
    public float IsGamingPort { get; set; }
    public float IsStreamingPort { get; set; }
    public float IsP2PPort { get; set; }
    public float IsVoIPPort { get; set; }
    public float IsHighPort { get; set; }

    // Application protocol features
    public int AppProtocolEncoded { get; set; }
    public float IsKnownProtocol { get; set; }
    public float ProtocolConfidence { get; set; }
    public float IsEncrypted { get; set; }
    public float IsCompressed { get; set; }

    // IP features
    public int SourceIPType { get; set; }
    public int DestinationIPType { get; set; }
    public ushort IPTotalLength { get; set; }
    public float IsFragmented { get; set; }
    public int TTLBucket { get; set; }
}
