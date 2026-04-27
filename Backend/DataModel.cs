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
    public int HighRiskPackets { get; set; }
    public int MediumRiskPackets { get; set; }
    public int LowRiskPackets { get; set; }
    public Dictionary<string, int> ProtocolCounts { get; set; } = new();
    public Dictionary<string, int> SecurityFlagCounts { get; set; } = new();
    public double AverageRiskScore { get; set; }
    public DateTime LastUpdate { get; set; }
}