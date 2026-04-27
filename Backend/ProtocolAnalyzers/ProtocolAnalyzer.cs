using PacketDotNet;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using NetworkMonitor.Backend;

namespace NetworkMonitor.Backend.ProtocolAnalyzers;

public class ProtocolAnalysisResult
{
    public string Protocol { get; set; } = string.Empty;
    public string Details { get; set; } = string.Empty;
    public Dictionary<string, object> Metadata { get; set; } = new();
    public List<string> SecurityFlags { get; set; } = new();
    public int RiskScore { get; set; } = 0; // 0-100 scale
}

public static class ProtocolAnalyzer
{
    public static ProtocolAnalysisResult AnalyzePacket(Packet packet, IPPacket ipPacket)
    {
        var result = new ProtocolAnalysisResult
        {
            Protocol = ipPacket.Protocol.ToString(),
            Metadata = new Dictionary<string, object>
            {
                ["SourceIP"] = ipPacket.SourceAddress.ToString(),
                ["DestinationIP"] = ipPacket.DestinationAddress.ToString(),
                ["PacketSize"] = packet.Bytes.Length,
                ["Timestamp"] = DateTime.Now
            }
        };

        try
        {
            switch (ipPacket.Protocol)
            {
                case ProtocolType.Tcp:
                    AnalyzeTcp(packet, ipPacket, result);
                    break;
                case ProtocolType.Udp:
                    AnalyzeUdp(packet, ipPacket, result);
                    break;
                case ProtocolType.Icmp:
                    AnalyzeIcmp(packet, result);
                    break;
                default:
                    result.Details = $"Unknown protocol: {ipPacket.Protocol}";
                    break;
            }
        }
        catch (Exception ex)
        {
            result.Details = $"Analysis error: {ex.Message}";
            result.RiskScore = 10; // Slight risk for unparseable packets
        }

        return result;
    }

    private static void AnalyzeTcp(Packet packet, IPPacket ipPacket, ProtocolAnalysisResult result)
    {
        var tcp = packet.Extract<TcpPacket>();
        if (tcp == null) return;

        result.Metadata["SourcePort"] = tcp.SourcePort;
        result.Metadata["DestinationPort"] = tcp.DestinationPort;
        result.Metadata["Flags"] = GetTcpFlags(tcp);
        result.Metadata["SequenceNumber"] = tcp.SequenceNumber;
        result.Metadata["AcknowledgmentNumber"] = tcp.AcknowledgmentNumber;
        result.Metadata["WindowSize"] = tcp.WindowSize;

        // Analyze based on port
        var port = Math.Min(tcp.SourcePort, tcp.DestinationPort);
        switch (port)
        {
            case 80:
            case 8080:
            case 8000:
                result = HttpAnalyzer.AnalyzeHttp(tcp, result);
                break;
            case 443:
            case 8443:
                result = SslTlsAnalyzer.AnalyzeSslTls(tcp, result);
                break;
            case 21:
                result = FtpAnalyzer.AnalyzeFtp(tcp, result);
                break;
            case 25:
            case 587:
            case 465:
            case 2525:
                result = SmtpAnalyzer.AnalyzeSmtp(tcp, result);
                break;
            case 53:
                result = DnsAnalyzer.AnalyzeDnsTcp(tcp, result);
                break;
            default:
                result.Details = $"TCP {tcp.SourcePort} → {tcp.DestinationPort}";
                if (tcp.PayloadData?.Length > 0)
                {
                    result = PayloadAnalyzer.AnalyzeGenericPayload(tcp.PayloadData, result);
                }
                break;
        }

        if (tcp.PayloadData?.Length > 0)
        {
            result = PayloadAnalyzer.AnalyzePayloadWithFilters(tcp.PayloadData, result, BuildPayloadFilterOptions());
        }
    }

    private static void AnalyzeUdp(Packet packet, IPPacket ipPacket, ProtocolAnalysisResult result)
    {
        var udp = packet.Extract<UdpPacket>();
        if (udp == null) return;

        result.Metadata["SourcePort"] = udp.SourcePort;
        result.Metadata["DestinationPort"] = udp.DestinationPort;
        result.Metadata["Length"] = udp.Length;

        var port = Math.Min(udp.SourcePort, udp.DestinationPort);
        switch (port)
        {
            case 53:
                result = DnsAnalyzer.AnalyzeDnsUdp(udp, result);
                break;
            case 67:
            case 68:
                result = DhcpAnalyzer.AnalyzeDhcp(udp, result);
                break;
            default:
                result.Details = $"UDP {udp.SourcePort} → {udp.DestinationPort}";
                if (udp.PayloadData?.Length > 0)
                {
                    result = PayloadAnalyzer.AnalyzeGenericPayload(udp.PayloadData, result);
                }
                break;
        }

        if (udp.PayloadData?.Length > 0)
        {
            result = PayloadAnalyzer.AnalyzePayloadWithFilters(udp.PayloadData, result, BuildPayloadFilterOptions());
        }
    }

    private static void AnalyzeIcmp(Packet packet, ProtocolAnalysisResult result)
    {
        var icmp = packet.Extract<IcmpV4Packet>();
        if (icmp == null) return;

        result.Metadata["Type"] = icmp.TypeCode;
        result.Details = $"ICMP {icmp.TypeCode}";

        if (icmp.TypeCode == IcmpV4TypeCode.EchoRequest)
        {
            result.Details = "ICMP Echo Request (Ping)";
        }
        else if (icmp.TypeCode == IcmpV4TypeCode.EchoReply)
        {
            result.Details = "ICMP Echo Reply (Ping Response)";
        }
    }

    private static string GetTcpFlags(TcpPacket tcp)
    {
        var flags = new List<string>();
        if (tcp.Synchronize) flags.Add("SYN");
        if (tcp.Acknowledgment) flags.Add("ACK");
        if (tcp.Finished) flags.Add("FIN");
        if (tcp.Reset) flags.Add("RST");
        if (tcp.Push) flags.Add("PSH");
        if (tcp.Urgent) flags.Add("URG");
        return string.Join(",", flags);
    }

    private static PayloadFilterOptions BuildPayloadFilterOptions()
    {
        var config = AppConfig.Instance;
        return new PayloadFilterOptions
        {
            Enabled = config.PayloadFilteringEnabled,
            CaseSensitive = false,
            MaxPreviewLength = config.PayloadPreviewLength,
            BlockedKeywords = config.BlockedPayloadKeywords.ToList(),
            BlockedRegexPatterns = config.BlockedPayloadPatterns.ToList()
        };
    }
}