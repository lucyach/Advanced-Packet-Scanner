using System.Text;
using PacketDotNet;
using NetworkMonitor.Backend.ML;

namespace NetworkMonitor.Backend.ProtocolAnalyzers;

public sealed record TrafficClassificationResult
{
    public string Category { get; init; } = "Unknown";
    public double Confidence { get; init; }
    public Dictionary<string, double> Scores { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public string ClassificationMethod { get; init; } = "Heuristic"; // "ML" or "Heuristic"
}

public static class TrafficIntelligenceAnalyzer
{
    private static readonly HashSet<int> P2pPorts = new() { 6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 51413 };
    private static readonly HashSet<int> GamingPorts = new() { 3074, 3478, 3479, 3480, 27015, 27036, 7777, 19132, 25565 };
    private static readonly HashSet<int> StreamingPorts = new() { 1935, 554, 1755, 1936, 8554 };

    // ML-based classifier (lazy initialized)
    private static readonly Lazy<MLTrafficClassifier> _mlClassifier = new(() =>
    {
        var classifier = new MLTrafficClassifier();
        classifier.LoadModel(); // Load if trained model exists
        return classifier;
    });

    private static MLTrafficClassifier MLClassifier => _mlClassifier.Value;
    private static bool _mlAvailable = true;

    /// <summary>
    /// Initializes the ML classifier. Should be called once during application startup.
    /// </summary>
    public static async Task InitializeMLClassifierAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            _ = MLClassifier; // Ensure lazy initialization
        }
        catch
        {
            _mlAvailable = false;
        }
    }

    /// <summary>
    /// Trains the ML classifier with collected samples.
    /// This should be called periodically or when sufficient samples are accumulated.
    /// </summary>
    public static async Task TrainMLClassifierAsync(MLTrainingData.TrafficDataset dataset, CancellationToken cancellationToken = default)
    {
        if (!_mlAvailable) return;

        try
        {
            var metrics = await MLClassifier.TrainAsync(dataset, cancellationToken);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"ML classifier training failed: {ex.Message}");
            _mlAvailable = false;
        }
    }

    public static void EnrichAnalysis(Packet packet, IPPacket ipPacket, ProtocolAnalysisResult result)
    {
        var applicationProtocol = DetectApplicationProtocol(packet, ipPacket, result);
        var srcPort = TryGetSourcePort(packet);
        var dstPort = TryGetDestinationPort(packet);
        var appProtocolConfidence = EstimateProtocolConfidence(applicationProtocol, packet, srcPort, dstPort);

        // Try ML classification first if available
        TrafficClassificationResult classification;
        if (_mlAvailable)
        {
            try
            {
                var features = TrafficFeatureExtractor.ExtractFeatures(packet, ipPacket, applicationProtocol, appProtocolConfidence.ToString());
                var mlPrediction = MLClassifier.Predict(features);
                
                if (mlPrediction.IsConfident)
                {
                    // Use ML classification
                    classification = new TrafficClassificationResult
                    {
                        Category = mlPrediction.PredictedClass,
                        Confidence = mlPrediction.Confidence,
                        Scores = mlPrediction.ClassProbabilities.ToDictionary(kvp => kvp.Key, kvp => (double)kvp.Value),
                        ClassificationMethod = "ML"
                    };
                }
                else
                {
                    // Fall back to heuristic if confidence is low
                    classification = ClassifyTrafficHeuristic(packet, ipPacket, applicationProtocol, srcPort, dstPort, result);
                    classification = classification with { ClassificationMethod = "Heuristic (Low ML confidence)" };
                }
            }
            catch
            {
                // Fall back to heuristic on ML error
                classification = ClassifyTrafficHeuristic(packet, ipPacket, applicationProtocol, srcPort, dstPort, result);
            }
        }
        else
        {
            // Use heuristic classification
            classification = ClassifyTrafficHeuristic(packet, ipPacket, applicationProtocol, srcPort, dstPort, result);
        }

        result.Metadata["ApplicationProtocol"] = applicationProtocol;
        result.Metadata["ApplicationProtocolConfidence"] = appProtocolConfidence;
        result.Metadata["TrafficClass"] = classification.Category;
        result.Metadata["TrafficClassConfidence"] = Math.Round(classification.Confidence, 2);
        result.Metadata["TrafficClassScores"] = classification.Scores;
        result.Metadata["TrafficClassificationMethod"] = classification.ClassificationMethod;

        if (result.Protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase) ||
            result.Protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase))
        {
            result.Protocol = applicationProtocol;
        }

        if (!result.Details.Contains("Class:", StringComparison.OrdinalIgnoreCase))
        {
            result.Details = string.IsNullOrWhiteSpace(result.Details)
                ? $"{applicationProtocol} traffic | Class: {classification.Category}"
                : $"{result.Details} | Class: {classification.Category} ({classification.Confidence:F0}%)";
        }
    }

    private static string DetectApplicationProtocol(Packet packet, IPPacket ipPacket, ProtocolAnalysisResult result)
    {
        var current = result.Protocol;
        if (!string.IsNullOrWhiteSpace(current) &&
            !current.Equals("TCP", StringComparison.OrdinalIgnoreCase) &&
            !current.Equals("UDP", StringComparison.OrdinalIgnoreCase) &&
            !current.Equals("ICMP", StringComparison.OrdinalIgnoreCase))
        {
            return current;
        }

        var srcPort = TryGetSourcePort(packet);
        var dstPort = TryGetDestinationPort(packet);
        var minPort = Math.Min(srcPort, dstPort);
        var payload = GetPayload(packet);
        var payloadText = ToAsciiPreview(payload, 220).ToUpperInvariant();

        if (ipPacket.Protocol == ProtocolType.Tcp)
        {
            if (payloadText.StartsWith("SSH-")) return "SSH";
            if (payloadText.StartsWith("RTSP/") || payloadText.StartsWith("OPTIONS RTSP") || payloadText.StartsWith("DESCRIBE RTSP")) return "RTSP";
            if (payloadText.StartsWith("SIP/2.0") || payloadText.StartsWith("INVITE ") || payloadText.StartsWith("REGISTER ")) return "SIP";
            if (payloadText.StartsWith("* OK") && payloadText.Contains("IMAP")) return "IMAP";
            if (payloadText.StartsWith("USER ") || payloadText.StartsWith("PASS ")) return "FTP";
            if (payloadText.StartsWith("EHLO ") || payloadText.StartsWith("HELO ") || payloadText.StartsWith("MAIL FROM:")) return "SMTP";
            if (payloadText.StartsWith("+OK") && (minPort == 110 || minPort == 995)) return "POP3";

            if (minPort == 22) return "SSH";
            if (minPort == 3389) return "RDP";
            if (minPort == 445) return "SMB";
            if (minPort == 143 || minPort == 993) return "IMAP";
            if (minPort == 110 || minPort == 995) return "POP3";
            if (minPort == 554 || minPort == 8554) return "RTSP";

            if (LooksLikeTls(payload)) return "TLS";
        }

        if (ipPacket.Protocol == ProtocolType.Udp)
        {
            if (minPort == 53) return "DNS";
            if (minPort == 67 || minPort == 68) return "DHCP";
            if (minPort == 123) return "NTP";
            if (minPort == 5353) return "mDNS";
            if (minPort == 1900) return "SSDP";
            if (minPort == 3478 || minPort == 5349)
            {
                return LooksLikeStun(payload) ? "STUN" : "UDP";
            }

            if (minPort == 443 || minPort == 784)
            {
                if (LooksLikeQuic(payload)) return "QUIC";
            }

            if (LooksLikeSip(payloadText)) return "SIP";
            if (LooksLikeRtp(payload)) return "RTP";
        }

        if (LooksLikeBitTorrent(payload, payloadText, srcPort, dstPort))
        {
            return "BitTorrent";
        }

        return ipPacket.Protocol switch
        {
            ProtocolType.Icmp => "ICMP",
            ProtocolType.Tcp => "TCP",
            ProtocolType.Udp => "UDP",
            _ => ipPacket.Protocol.ToString()
        };
    }

    private static TrafficClassificationResult ClassifyTrafficHeuristic(
        Packet packet,
        IPPacket ipPacket,
        string appProtocol,
        int srcPort,
        int dstPort,
        ProtocolAnalysisResult result)
    {
        var packetSize = packet.Bytes.Length;
        var payloadLength = GetPayload(packet).Length;
        var minPort = Math.Min(srcPort, dstPort);

        var scores = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase)
        {
            ["Web"] = 0.2,
            ["Streaming"] = 0.2,
            ["Gaming"] = 0.2,
            ["P2P"] = 0.2,
            ["VoIP"] = 0.2,
            ["FileTransfer"] = 0.2,
            ["RemoteAccess"] = 0.2,
            ["Infrastructure"] = 0.2,
            ["Messaging"] = 0.2,
            ["Unknown"] = 0.1
        };

        switch (appProtocol.ToUpperInvariant())
        {
            case "HTTP":
            case "HTTPS":
            case "TLS":
            case "DNS":
            case "QUIC":
                scores["Web"] += 2.4;
                break;
            case "RTSP":
            case "RTP":
                scores["Streaming"] += 2.6;
                break;
            case "BITTORRENT":
                scores["P2P"] += 3.0;
                break;
            case "SIP":
            case "STUN":
                scores["VoIP"] += 2.8;
                break;
            case "FTP":
            case "SMB":
                scores["FileTransfer"] += 2.8;
                break;
            case "SSH":
            case "RDP":
                scores["RemoteAccess"] += 2.8;
                break;
            case "DHCP":
            case "NTP":
            case "MDNS":
            case "SSDP":
            case "ICMP":
                scores["Infrastructure"] += 2.2;
                break;
            case "SMTP":
            case "IMAP":
            case "POP3":
                scores["Messaging"] += 2.2;
                break;
        }

        if (StreamingPorts.Contains(srcPort) || StreamingPorts.Contains(dstPort))
        {
            scores["Streaming"] += 1.1;
        }

        if (GamingPorts.Contains(srcPort) || GamingPorts.Contains(dstPort))
        {
            scores["Gaming"] += 1.8;
            if (ipPacket.Protocol == ProtocolType.Udp)
            {
                scores["Gaming"] += 0.7;
            }
        }

        if (P2pPorts.Contains(srcPort) || P2pPorts.Contains(dstPort))
        {
            scores["P2P"] += 1.8;
        }

        if (ipPacket.Protocol == ProtocolType.Udp && packetSize <= 220)
        {
            scores["Gaming"] += 0.6;
            scores["VoIP"] += 0.4;
        }

        if (packetSize >= 1000)
        {
            scores["Streaming"] += 0.5;
            scores["FileTransfer"] += 0.6;
        }

        if (payloadLength <= 64 && ipPacket.Protocol == ProtocolType.Tcp)
        {
            scores["RemoteAccess"] += 0.3;
        }

        if (minPort <= 1024)
        {
            scores["Infrastructure"] += 0.2;
        }

        if (result.SecurityFlags.Any(flag => flag.Contains("flood", StringComparison.OrdinalIgnoreCase)))
        {
            scores["Unknown"] += 0.8;
        }

        var normalized = Softmax(scores);
        var best = normalized.OrderByDescending(kvp => kvp.Value).First();

        return new TrafficClassificationResult
        {
            Category = best.Key,
            Confidence = best.Value,
            Scores = normalized
                .OrderByDescending(kvp => kvp.Value)
                .Take(5)
                .ToDictionary(kvp => kvp.Key, kvp => kvp.Value, StringComparer.OrdinalIgnoreCase),
            ClassificationMethod = "Heuristic"
        };
    }

    private static Dictionary<string, double> Softmax(Dictionary<string, double> scores)
    {
        var max = scores.Values.Max();
        var weighted = scores.ToDictionary(
            kvp => kvp.Key,
            kvp => Math.Exp(kvp.Value - max),
            StringComparer.OrdinalIgnoreCase);

        var sum = weighted.Values.Sum();
        if (sum <= 0)
        {
            return scores.ToDictionary(kvp => kvp.Key, _ => 0d, StringComparer.OrdinalIgnoreCase);
        }

        return weighted.ToDictionary(
            kvp => kvp.Key,
            kvp => Math.Round((kvp.Value / sum) * 100d, 2),
            StringComparer.OrdinalIgnoreCase);
    }

    private static double EstimateProtocolConfidence(string appProtocol, Packet packet, int srcPort, int dstPort)
    {
        if (appProtocol is "HTTP" or "DNS" or "DHCP" or "FTP" or "SMTP" or "SSH")
        {
            return 95;
        }

        if (appProtocol is "QUIC" or "RTP" or "SIP" or "BitTorrent")
        {
            return 82;
        }

        if (srcPort <= 1024 || dstPort <= 1024)
        {
            return packet.Bytes.Length > 0 ? 74 : 62;
        }

        return 55;
    }

    private static bool LooksLikeTls(byte[] payload)
    {
        return payload.Length >= 5 && payload[0] == 0x16 && payload[1] == 0x03;
    }

    private static bool LooksLikeQuic(byte[] payload)
    {
        if (payload.Length < 6)
        {
            return false;
        }

        var firstByte = payload[0];
        var longHeader = (firstByte & 0x80) == 0x80;
        var fixedBit = (firstByte & 0x40) == 0x40;
        return longHeader && fixedBit;
    }

    private static bool LooksLikeStun(byte[] payload)
    {
        return payload.Length >= 20 && payload[4] == 0x21 && payload[5] == 0x12 && payload[6] == 0xA4 && payload[7] == 0x42;
    }

    private static bool LooksLikeSip(string payloadText)
    {
        return payloadText.StartsWith("SIP/2.0") ||
               payloadText.StartsWith("INVITE ") ||
               payloadText.StartsWith("REGISTER ") ||
               payloadText.Contains(" VIA: SIP/2.0");
    }

    private static bool LooksLikeRtp(byte[] payload)
    {
        if (payload.Length < 12)
        {
            return false;
        }

        var versionBits = (payload[0] & 0xC0) >> 6;
        if (versionBits != 2)
        {
            return false;
        }

        var payloadType = payload[1] & 0x7F;
        return payloadType <= 127;
    }

    private static bool LooksLikeBitTorrent(byte[] payload, string payloadText, int srcPort, int dstPort)
    {
        if (payload.Length > 20 && payload[0] == 19 && payloadText.Contains("BITTORRENT PROTOCOL"))
        {
            return true;
        }

        if (payloadText.Contains("INFO_HASH") || payloadText.Contains("PEER_ID") || payloadText.Contains("GET /ANNOUNCE"))
        {
            return true;
        }

        return P2pPorts.Contains(srcPort) || P2pPorts.Contains(dstPort);
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
        var tcpPayload = packet.Extract<TcpPacket>()?.PayloadData;
        if (tcpPayload is { Length: > 0 })
        {
            return tcpPayload;
        }

        var udpPayload = packet.Extract<UdpPacket>()?.PayloadData;
        if (udpPayload is { Length: > 0 })
        {
            return udpPayload;
        }

        return Array.Empty<byte>();
    }

    private static string ToAsciiPreview(byte[] data, int maxLength)
    {
        if (data.Length == 0)
        {
            return string.Empty;
        }

        var length = Math.Min(maxLength, data.Length);
        var text = Encoding.ASCII.GetString(data, 0, length);
        var chars = text.Select(ch => char.IsControl(ch) && ch != '\r' && ch != '\n' && ch != '\t' ? ' ' : ch).ToArray();
        return new string(chars);
    }
}
