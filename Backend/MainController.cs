using NetworkMonitor.Backend;
using NetworkMonitor.Backend.ProtocolAnalyzers;
using SharpPcap;
using PacketDotNet;
using System.Net;
using System;
using System.Linq;
using System.Collections.Generic;

namespace NetworkMonitor.Backend;

public class MainController
{
    private static ICaptureDevice? device = null;
    private static readonly object packetLock = new();

    private static List<string> packets = new();
    private static List<EnhancedPacketInfo> enhancedPackets = new();
    private static List<string> alerts = new();
    private static List<SecurityAlert> securityAlerts = new();

    private static Dictionary<string, List<DateTime>> packetFrequency = new();
    private static Dictionary<string, HashSet<int>> portTracking = new();
    private static Dictionary<string, int> synTracking = new();
    private static Dictionary<string, int> icmpTracking = new();
    private static Dictionary<string, DateTime> lastAlertTime = new();
    private static PacketStatistics statistics = new();

    private const int SYN_FLOOD_THRESHOLD = 200;
    private const int PORT_SCAN_THRESHOLD = 30;
    private const int ICMP_FLOOD_THRESHOLD = 150;
    private const int UDP_FLOOD_THRESHOLD = 400;

    private static readonly TimeSpan WINDOW = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan ALERT_COOLDOWN = TimeSpan.FromSeconds(15);

    public static List<ICaptureDevice> AvailableDevices { get; private set; } = new();
    public static ICaptureDevice? CurrentDevice => device;

    static MainController()
    {
        try
        {
            ListDevices();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error listing devices: {ex.Message}");
        }
    }

    private static void ResetData()
    {
        lock (packetLock)
        {
            packets.Clear();
            enhancedPackets.Clear();
            alerts.Clear();
            securityAlerts.Clear();
            packetFrequency.Clear();
            portTracking.Clear();
            synTracking.Clear();
            icmpTracking.Clear();
            lastAlertTime.Clear();
            statistics = new PacketStatistics { LastUpdate = DateTime.Now };
        }
    }

    public DataModel GetDashboardData()
    {
        var model = new DataModel
        {
            Message = device != null ? $"Monitoring: {device.Description}" : "No device selected",
            CurrentTime = DateTime.Now.ToString("HH:mm:ss"),
            ComputerName = Environment.MachineName
        };

        lock (packetLock)
        {
            model.TotalPacketsCaptured = enhancedPackets.Count;

            // Legacy packet display for compatibility
            model.Packets = packets.Any()
                ? packets.ToList()
                : new List<string> { device != null ? "🔄 Waiting for network packets..." : "❌ No device selected" };

            // Enhanced packet information
            model.EnhancedPackets = enhancedPackets.TakeLast(100).ToList();

            // Legacy alerts
            model.Alerts = alerts.TakeLast(20).ToList();

            // Enhanced security alerts
            model.SecurityAlerts = securityAlerts.TakeLast(50).ToList();

            // Update statistics
            UpdateStatistics();
            model.Statistics = statistics;
        }

        return model;
    }

    public static void ListDevices()
    {
        AvailableDevices = CaptureDeviceList.Instance.Cast<ICaptureDevice>().ToList();

        if (!AvailableDevices.Any())
            Console.WriteLine("No network adapters found. Ensure Npcap is installed and run as admin.");
    }

    public static bool StartCapture(ICaptureDevice selectedDevice)
    {
        try
        {
            // Only reset data if switching to a different device
            if (device != selectedDevice)
            {
                device?.StopCapture();
                device?.Close();

                ResetData();
            }
            else if (device != null)
            {
                // Already capturing on this device, no need to restart
                return true;
            }

            device = selectedDevice;
            device.OnPacketArrival += OnPacketArrival;

            device.Open(DeviceModes.Promiscuous, 1000);
            device.StartCapture();

            Console.WriteLine($"Started capture on: {device.Description}");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to start capture: {ex.Message}");
            device = null;
            return false;
        }
    }

    public static void PauseCapture()
    {
        try
        {
            device?.StopCapture();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error pausing capture: {ex.Message}");
        }
    }

    public static void PlayCapture()
    {
        try
        {
            device?.StartCapture();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error resuming capture: {ex.Message}");
        }
    }

    private static void OnPacketArrival(object sender, PacketCapture e)
    {
        try
        {
            var raw = e.GetPacket();
            if (raw == null) return;

            var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);
            var ip = packet.Extract<IPPacket>();
            if (ip == null) return;

            var src = ip.SourceAddress.ToString();
            var dst = ip.DestinationAddress.ToString();
            var proto = ip.Protocol.ToString();

            lock (packetLock)
            {
                // Enhanced packet analysis first
                var analysisResult = ProtocolAnalyzer.AnalyzePacket(packet, ip);
                
                // Skip private IP traffic for public internet analysis only
                // Still analyze private traffic for internal threats
                bool isPrivateTraffic = IsPrivateIP(src) || IsPrivateIP(dst);
                if (isPrivateTraffic)
                {
                    analysisResult.Metadata["TrafficType"] = "Internal";
                }
                else
                {
                    analysisResult.Metadata["TrafficType"] = "External";
                    // Legacy packet tracking for external traffic
                    TrackFrequency(src);
                    HandleTcp(packet, src);
                    HandleUdp(packet, src);
                    HandleIcmp(packet, src);
                }
                
                var enhancedPacket = new EnhancedPacketInfo
                {
                    Timestamp = DateTime.Now,
                    SourceIP = src,
                    DestinationIP = dst,
                    Protocol = analysisResult.Protocol,
                    Size = packet.Bytes.Length,
                    Details = analysisResult.Details,
                    RiskScore = analysisResult.RiskScore,
                    SecurityFlags = analysisResult.SecurityFlags,
                    Metadata = analysisResult.Metadata,
                    FormattedDisplay = FormatEnhancedPacketDisplay(analysisResult, src, dst, packet.Bytes.Length)
                };

                enhancedPackets.Add(enhancedPacket);

                // Legacy packet display for compatibility
                var httpInfo = HandleHttp(packet);
                var len = packet.Bytes.Length;

                if (httpInfo != null)
                    packets.Add($"{DateTime.Now:HH:mm:ss} | HTTP | {src} → {dst} | {httpInfo} | {len} bytes");
                else
                    packets.Add($"{DateTime.Now:HH:mm:ss} | {proto} | {src} → {dst} | {len} bytes");

                // Generate security alerts based on analysis
                ProcessSecurityFlags(enhancedPacket);

                // Maintain size limits
                if (enhancedPackets.Count > AppConfig.Instance.MaxPackets)
                    enhancedPackets.RemoveAt(0);

                if (packets.Count > AppConfig.Instance.MaxPackets)
                    packets.RemoveAt(0);

                if (securityAlerts.Count > AppConfig.Instance.MaxAlerts)
                    securityAlerts.RemoveAt(0);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Packet analysis error: {ex.Message}");
        }
    }

    private static bool IsPrivateIP(string ip)
    {
        if (!IPAddress.TryParse(ip, out var address))
            return false;

        byte[] bytes = address.GetAddressBytes();

        return bytes[0] switch
        {
            10 => true,
            172 => bytes[1] >= 16 && bytes[1] <= 31,
            192 => bytes[1] == 168,
            _ => false
        };
    }

    private static void TrackFrequency(string src)
    {
        var now = DateTime.Now;

        if (!packetFrequency.ContainsKey(src))
            packetFrequency[src] = new List<DateTime>();

        packetFrequency[src].Add(now);

        packetFrequency[src] = packetFrequency[src]
            .Where(t => t > now - WINDOW)
            .ToList();
    }

    private static void HandleTcp(Packet packet, string src)
    {
        var tcp = packet.Extract<TcpPacket>();
        if (tcp == null) return;

        if (!portTracking.ContainsKey(src))
            portTracking[src] = new HashSet<int>();

        portTracking[src].Add(tcp.DestinationPort);

        if (tcp.Synchronize && !tcp.Acknowledgment)
        {
            if (!synTracking.ContainsKey(src))
                synTracking[src] = 0;

            synTracking[src]++;

            if (synTracking[src] > SYN_FLOOD_THRESHOLD)
                AddAlertOnce($"🚨 SYN Flood detected from {src}", src);
        }

        if (portTracking[src].Count > PORT_SCAN_THRESHOLD)
            AddAlertOnce($"⚠ Port scan detected from {src}", src);
    }

    private static void HandleUdp(Packet packet, string src)
    {
        var udp = packet.Extract<UdpPacket>();
        if (udp == null) return;

        if (packetFrequency[src].Count > UDP_FLOOD_THRESHOLD)
            AddAlertOnce($"🚨 UDP Flood suspected from {src}", src);
    }

    private static void HandleIcmp(Packet packet, string src)
    {
        var icmp = packet.Extract<IcmpV4Packet>();
        if (icmp == null) return;

        if (icmp.TypeCode == IcmpV4TypeCode.EchoRequest)
        {
            if (!icmpTracking.ContainsKey(src))
                icmpTracking[src] = 0;

            icmpTracking[src]++;

            if (icmpTracking[src] > ICMP_FLOOD_THRESHOLD)
                AddAlertOnce($"⚠ ICMP Flood detected from {src}", src);
        }
    }

    private static string? HandleHttp(Packet packet)
    {
        var tcp = packet.Extract<TcpPacket>();
        if (tcp == null) return null;

        if (tcp.PayloadData == null || tcp.PayloadData.Length == 0)
            return null;

        if (tcp.SourcePort != 80 && tcp.DestinationPort != 80)
            return null;

        try
        {
            var payload = System.Text.Encoding.ASCII.GetString(tcp.PayloadData);
            var lines = payload.Split("\r\n");

            if (lines.Length == 0)
                return null;

            var firstLine = lines[0];
            string host = "";

            foreach (var line in lines)
            {
                if (line.StartsWith("Host:"))
                {
                    host = line.Replace("Host:", "").Trim();
                    break;
                }
            }

            if (firstLine.StartsWith("GET") || firstLine.StartsWith("POST") ||
                firstLine.StartsWith("PUT") || firstLine.StartsWith("DELETE"))
            {
                var parts = firstLine.Split(' ');
                if (parts.Length >= 2)
                {
                    var method = parts[0];
                    var url = parts[1];

                    if (!string.IsNullOrEmpty(host))
                        return $"{method} {url} | Host: {host}";
                    else
                        return $"{method} {url}";
                }
            }

            if (firstLine.StartsWith("HTTP/"))
            {
                var parts = firstLine.Split(' ');
                if (parts.Length >= 2)
                    return $"Status {parts[1]}";
            }
        }
        catch { }

        return null;
    }

    private static void AddAlertOnce(string message, string key)
    {
        var now = DateTime.Now;

        if (lastAlertTime.ContainsKey(key) &&
            (now - lastAlertTime[key]) < ALERT_COOLDOWN)
            return;

        lastAlertTime[key] = now;

        if (alerts.Count > AppConfig.Instance.MaxAlerts)
            alerts.RemoveAt(0);

        alerts.Add($"[{now:HH:mm:ss}] {message}");
    }

    // Additional methods for enhanced alert management
    public static List<string> GetAllAlerts()
    {
        lock (packetLock)
        {
            return new List<string>(alerts);
        }
    }

    public static int GetAlertCount()
    {
        lock (packetLock)
        {
            return alerts.Count;
        }
    }

    public static Dictionary<string, int> GetAlertStats()
    {
        lock (packetLock)
        {
            var stats = new Dictionary<string, int>
            {
                ["SYN Flood"] = alerts.Count(a => a.Contains("SYN Flood")),
                ["Port Scan"] = alerts.Count(a => a.Contains("Port scan")),
                ["UDP Flood"] = alerts.Count(a => a.Contains("UDP Flood")),
                ["ICMP Flood"] = alerts.Count(a => a.Contains("ICMP Flood")),
                ["Total"] = alerts.Count
            };
            return stats;
        }
    }

    public static void ClearAlerts()
    {
        lock (packetLock)
        {
            alerts.Clear();
            // Also clear tracking data to reset threat detection counters
            synTracking.Clear();
            icmpTracking.Clear();
            lastAlertTime.Clear();
            // Note: We keep portTracking and packetFrequency as they're used for ongoing detection
        }
    }

    public static void ClearPackets()
    {
        lock (packetLock)
        {
            packets.Clear();
            enhancedPackets.Clear();
        }
    }

    // New helper methods for enhanced packet analysis
    private static string FormatEnhancedPacketDisplay(ProtocolAnalysisResult analysis, string src, string dst, int size)
    {
        var riskIndicator = analysis.RiskScore switch
        {
            >= 50 => "🔴",
            >= 25 => "🟡",
            >= 10 => "🟠",
            _ => "🟢"
        };

        var flagsDisplay = analysis.SecurityFlags.Any() ? 
            $" | ⚠️ {string.Join(", ", analysis.SecurityFlags.Take(2))}" : "";

        return $"{DateTime.Now:HH:mm:ss} | {riskIndicator} {analysis.Protocol} | {src} → {dst} | {analysis.Details} | {size} bytes{flagsDisplay}";
    }

    private static void ProcessSecurityFlags(EnhancedPacketInfo packet)
    {
        if (packet.SecurityFlags.Any() || packet.RiskScore >= 25)
        {
            var severity = CalculateSeverity(packet.RiskScore, packet.SecurityFlags);
            
            var alert = new SecurityAlert
            {
                Timestamp = packet.Timestamp,
                AlertType = DetermineAlertType(packet.SecurityFlags, packet.Protocol),
                Description = $"{packet.Protocol}: {string.Join(", ", packet.SecurityFlags.Take(3))}",
                SourceIP = packet.SourceIP,
                DestinationIP = packet.DestinationIP,
                Severity = severity,
                Context = new Dictionary<string, object>
                {
                    ["RiskScore"] = packet.RiskScore,
                    ["Protocol"] = packet.Protocol,
                    ["PacketSize"] = packet.Size,
                    ["SecurityFlags"] = packet.SecurityFlags
                }
            };

            securityAlerts.Add(alert);

            // Also add to legacy alerts for compatibility
            if (severity >= 7)
            {
                AddAlertOnce($"🚨 High Risk: {alert.Description}", packet.SourceIP);
            }
            else if (severity >= 5)
            {
                AddAlertOnce($"⚠️ Medium Risk: {alert.Description}", packet.SourceIP);
            }
        }
    }

    private static int CalculateSeverity(int riskScore, List<string> flags)
    {
        var severity = Math.Min(10, Math.Max(1, riskScore / 10));
        
        // Adjust based on specific flags
        if (flags.Any(f => f.Contains("SSL") || f.Contains("TLS") || f.Contains("certificate")))
            severity = Math.Min(10, severity + 2);
        
        if (flags.Any(f => f.Contains("injection") || f.Contains("XSS")))
            severity = Math.Min(10, severity + 3);
            
        return severity;
    }

    private static string DetermineAlertType(List<string> flags, string protocol)
    {
        if (flags.Any(f => f.Contains("certificate") || f.Contains("SSL") || f.Contains("TLS")))
            return "Certificate/Encryption";
        
        if (flags.Any(f => f.Contains("injection") || f.Contains("XSS")))
            return "Code Injection";
            
        if (flags.Any(f => f.Contains("suspicious") || f.Contains("malicious")))
            return "Malicious Activity";
            
        if (flags.Any(f => f.Contains("flood") || f.Contains("scan")))
            return "Network Attack";
            
        return $"{protocol} Security";
    }

    private static void UpdateStatistics()
    {
        statistics.TotalPackets = enhancedPackets.Count;
        statistics.HighRiskPackets = enhancedPackets.Count(p => p.RiskScore >= 50);
        statistics.MediumRiskPackets = enhancedPackets.Count(p => p.RiskScore >= 25 && p.RiskScore < 50);
        statistics.LowRiskPackets = enhancedPackets.Count(p => p.RiskScore < 25);
        
        statistics.ProtocolCounts = enhancedPackets
            .GroupBy(p => p.Protocol)
            .ToDictionary(g => g.Key, g => g.Count());
            
        statistics.SecurityFlagCounts = enhancedPackets
            .SelectMany(p => p.SecurityFlags)
            .GroupBy(f => f)
            .ToDictionary(g => g.Key, g => g.Count());
            
        statistics.AverageRiskScore = enhancedPackets.Any() ? 
            enhancedPackets.Average(p => p.RiskScore) : 0;
            
        statistics.LastUpdate = DateTime.Now;
    }

    //Saves a count of packets to a file. Uses CSV or .txt
    public static bool SaveLastPacketsToFile(int count, string? filePath, bool csv)
    {
        if (count <= 0) 
            return false;
        //get downloads folder as default if filepath is null
        if (string.IsNullOrEmpty(filePath))
        {
            var userpath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var downloads = Path.Combine(userpath, "Downloads");
            var defaultname = "default";
            if (csv == true) defaultname = "Saved_packets.csv";
            else defaultname = "Saved_packets.txt";
            filePath = Path.Combine(downloads, defaultname);
                
        }
        List<string> packetsToSave;
        lock (packetLock)
        {
            int start = Math.Max(0, packets.Count - count);
            packetsToSave = [.. packets.Skip(start)];
        }
        try
        {
            var TruePath = Path.GetFullPath(filePath);
            if (TruePath == null)
            {
                Console.WriteLine("Invalid file path.");
                return false;
            }
            var directoryofTruePath = Path.GetDirectoryName(TruePath);
            if (directoryofTruePath == null || !Directory.Exists(directoryofTruePath))
            {
                Console.WriteLine("Directory does not exist.");
                return false;
            }

            Directory.CreateDirectory(directoryofTruePath);

            //If its not a csv, save as a .txt file

            if (!csv)
            {
                File.WriteAllLines(TruePath, packetsToSave);
            }
            else
            {
                //Save as a CSV file
            }
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error saving packets to file: {ex.Message}");
            return false;
        }

    }
}