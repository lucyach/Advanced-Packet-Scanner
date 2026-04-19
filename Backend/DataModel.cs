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
    public int TotalPacketsCaptured { get; set; } = 0;
    public List<string> Alerts { get; set; } = new();
}