using System.Text.Json;

namespace NetworkMonitor.Backend;

public class AppConfig
{
    private const string CONFIG_FILE = "config.json";
    
    public int MaxPackets { get; set; } = 5000;
    public int MaxAlerts { get; set; } = 300;
    public int PacketSaveCount { get; set; } = 100;
    
    private static AppConfig? _instance;
    private static readonly object _lock = new();
    
    public static AppConfig Instance
    {
        get
        {
            if (_instance == null)
            {
                lock (_lock)
                {
                    _instance ??= LoadConfig();
                }
            }
            return _instance;
        }
    }
    
    private static AppConfig LoadConfig()
    {
        try
        {
            if (File.Exists(CONFIG_FILE))
            {
                string json = File.ReadAllText(CONFIG_FILE);
                var config = JsonSerializer.Deserialize<AppConfig>(json);
                if (config != null)
                    return config;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error loading config: {ex.Message}");
        }
        
        // Return default config if loading fails
        return new AppConfig();
    }
    
    public void Save()
    {
        try
        {
            var options = new JsonSerializerOptions { WriteIndented = true };
            string json = JsonSerializer.Serialize(this, options);
            File.WriteAllText(CONFIG_FILE, json);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error saving config: {ex.Message}");}
    }
    
    public void UpdateLimits(int maxPackets, int maxAlerts)
    {
        MaxPackets = Math.Max(1, maxPackets); // Ensure minimum of 1
        MaxAlerts = Math.Max(1, maxAlerts);   // Ensure minimum of 1
        Save();
    }
    
    public void UpdatePacketSaveCount(int packetSaveCount)
    {
        PacketSaveCount = Math.Max(1, packetSaveCount); // Ensure minimum of 1
        Save();
    }
}