using NetworkMonitor.Backend.ProtocolAnalyzers;

namespace NetworkMonitor.Backend;

// This class carries data from C# to HTML
// Think of it as a "container" for information
public class DataModel
{
    // These properties will be available in the HTML using @Model.PropertyName
    public string Message { get; set; } = string.Empty;
    public string CurrentTime { get; set; } = string.Empty;
    public string ComputerName { get; set; } = string.Empty;
    public List<string> Packets { get; set; } = new();
    public List<EnhancedPacketInfo> EnhancedPackets { get; set; } = new();
    public int TotalPacketsCaptured { get; set; } = 0;
    public List<string> Alerts { get; set; } = new();
    public List<SecurityAlert> SecurityAlerts { get; set; } = new();
    public PacketStatistics Statistics { get; set; } = new();
}

public class EnhancedPacketInfo
{
    public DateTime Timestamp { get; set; }
    public string SourceIP { get; set; } = string.Empty;
    public string DestinationIP { get; set; } = string.Empty;
    public string SourceHostName { get; set; } = string.Empty;
    public string DestinationHostName { get; set; } = string.Empty;
    public GeoLocationInfo? SourceGeoLocation { get; set; }
    public GeoLocationInfo? DestinationGeoLocation { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public int Size { get; set; }
    public string Details { get; set; } = string.Empty;
    public int RiskScore { get; set; }
    public List<string> SecurityFlags { get; set; } = new();
    public Dictionary<string, object> Metadata { get; set; } = new();
    public string FormattedDisplay { get; set; } = string.Empty;
}

public class SecurityAlert
{
    public DateTime Timestamp { get; set; }
    public string AlertType { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string SourceIP { get; set; } = string.Empty;
    public string DestinationIP { get; set; } = string.Empty;
    public int Severity { get; set; } // 1-10 scale
    public Dictionary<string, object> Context { get; set; } = new();
}

public class PacketStatistics
{
    public int TotalPackets { get; set; }
    public long TotalBytes { get; set; }
    public int HighRiskPackets { get; set; }
    public int MediumRiskPackets { get; set; }
    public int LowRiskPackets { get; set; }
    public Dictionary<string, int> ProtocolCounts { get; set; } = new();
    public Dictionary<string, int> ApplicationProtocolCounts { get; set; } = new();
    public Dictionary<string, int> TrafficClassificationCounts { get; set; } = new();
    public Dictionary<string, int> SecurityFlagCounts { get; set; } = new();
    public double AverageRiskScore { get; set; }
    public double ProtocolDiversityEntropy { get; set; }
    public BandwidthUtilizationMetrics Bandwidth { get; set; } = new();
    public NetworkPerformanceMetrics Performance { get; set; } = new();
    public BaselineSnapshot Baseline { get; set; } = new();
    public TrafficPatternAnalytics PatternAnalytics { get; set; } = new();
    public TrafficAnomalyReport AnomalyReport { get; set; } = new();
    public List<DeviceFingerprint> DeviceFingerprints { get; set; } = new();
    public NetworkTopologyMap TopologyMap { get; set; } = new();
    public DateTime LastUpdate { get; set; }
}

public class BaselineMetric
{
    public string Name { get; set; } = string.Empty;
    public double Mean { get; set; }
    public double StandardDeviation { get; set; }
    public int Samples { get; set; }
}

public class BaselineSnapshot
{
    public bool IsEstablished { get; set; }
    public int WarmupWindows { get; set; }
    public int MinimumWindowsRequired { get; set; }
    public DateTime LastUpdatedUtc { get; set; }
    public List<BaselineMetric> Metrics { get; set; } = new();
}

public class TrafficPatternAnalytics
{
    public double PacketRatePerSecond { get; set; }
    public double BytesPerSecond { get; set; }
    public int UniqueSourceIps { get; set; }
    public int UniqueDestinationIps { get; set; }
    public int UniqueConversations { get; set; }
    public double HighRiskPacketRatioPercent { get; set; }
    public double AveragePacketSizeBytes { get; set; }
    public Dictionary<string, double> ClassificationDistributionPercent { get; set; } = new();
    public Dictionary<string, double> ApplicationProtocolDistributionPercent { get; set; } = new();
}

public class TrafficAnomalyMetric
{
    public string Metric { get; set; } = string.Empty;
    public double CurrentValue { get; set; }
    public double BaselineMean { get; set; }
    public double BaselineStdDev { get; set; }
    public double ZScore { get; set; }
    public string Severity { get; set; } = "Info";
    public string Direction { get; set; } = "Stable";
}

public class TrafficAnomalyReport
{
    public bool BaselineReady { get; set; }
    public int TotalAnomalies { get; set; }
    public string OverallSeverity { get; set; } = "None";
    public DateTime GeneratedAtUtc { get; set; }
    public List<TrafficAnomalyMetric> Metrics { get; set; } = new();
}

public class GeoLocationInfo
{
    public string Country { get; set; } = "Unknown";
    public string Region { get; set; } = "Unknown";
    public string City { get; set; } = "Unknown";
    public string Isp { get; set; } = "Unknown";
    public double? Latitude { get; set; }
    public double? Longitude { get; set; }
    public bool IsPrivate { get; set; }
    public string DisplayName =>
        IsPrivate
            ? "Private/Local Network"
            : string.Join(", ", new[] { City, Region, Country }.Where(v => !string.IsNullOrWhiteSpace(v) && v != "Unknown"));
}

public class TopTalkerMetric
{
    public string IPAddress { get; set; } = string.Empty;
    public string HostName { get; set; } = string.Empty;
    public long Bytes { get; set; }
    public double MegabitsPerSecond { get; set; }
}

public class BandwidthUtilizationMetrics
{
    public double CurrentMbps { get; set; }
    public double AverageMbps { get; set; }
    public double PeakMbps { get; set; }
    public double PacketsPerSecond { get; set; }
    public Dictionary<string, double> ProtocolBandwidthMbps { get; set; } = new();
    public List<TopTalkerMetric> TopTalkers { get; set; } = new();
}

public class NetworkPerformanceMetrics
{
    public double AveragePacketSizeBytes { get; set; }
    public double EstimatedJitterMs { get; set; }
    public double AverageTcpHandshakeRttMs { get; set; }
    public double IcmpReplyRatePercent { get; set; }
    public long TotalObservedBytes { get; set; }
}

public class DeviceFingerprint
{
    public string IPAddress { get; set; } = string.Empty;
    public string HostName { get; set; } = string.Empty;
    public string ProbableOS { get; set; } = "Unknown";
    public string DeviceType { get; set; } = "Unknown";
    public string TrafficProfile { get; set; } = "Unknown";
    public bool IsPrivate { get; set; }
    public GeoLocationInfo? GeoLocation { get; set; }
    public List<int> ObservedPorts { get; set; } = new();
    public List<string> ObservedProtocols { get; set; } = new();
    public Dictionary<string, int> ProtocolDistribution { get; set; } = new();
    public long BytesSent { get; set; }
    public long BytesReceived { get; set; }
    public int PacketCount { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
}

public class TopologyNodeInfo
{
    public string NodeId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string HostName { get; set; } = string.Empty;
    public string DeviceType { get; set; } = "Unknown";
    public GeoLocationInfo? GeoLocation { get; set; }
    public int Degree { get; set; }
    public long TotalBytes { get; set; }
    public DateTime LastSeen { get; set; }
}

public class TopologyLinkInfo
{
    public string SourceNodeId { get; set; } = string.Empty;
    public string DestinationNodeId { get; set; } = string.Empty;
    public string DominantProtocol { get; set; } = string.Empty;
    public int PacketCount { get; set; }
    public long TotalBytes { get; set; }
    public double CurrentMbps { get; set; }
    public DateTime LastSeen { get; set; }
}

public class NetworkTopologyMap
{
    public List<TopologyNodeInfo> Nodes { get; set; } = new();
    public List<TopologyLinkInfo> Links { get; set; } = new();
    public int TotalNodes { get; set; }
    public int TotalLinks { get; set; }
}