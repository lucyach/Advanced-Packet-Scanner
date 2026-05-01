using NetworkMonitor.Backend;
using NetworkMonitor.Backend.ProtocolAnalyzers;
using SharpPcap;
using PacketDotNet;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System;
using System.Linq;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace NetworkMonitor.Backend;

public class MainController
{
    private sealed class BandwidthSample
    {
        public DateTime TimestampUtc { get; set; }
        public int Bytes { get; set; }
        public string SourceIP { get; set; } = string.Empty;
        public string Protocol { get; set; } = string.Empty;
    }

    private sealed class TopologyEdgeTracker
    {
        public string SourceIP { get; set; } = string.Empty;
        public string DestinationIP { get; set; } = string.Empty;
        public int PacketCount { get; set; }
        public long TotalBytes { get; set; }
        public DateTime LastSeenUtc { get; set; }
        public Queue<BandwidthSample> Samples { get; } = new();
        public Dictionary<string, int> ProtocolCounts { get; } = new(StringComparer.OrdinalIgnoreCase);

        public void AddSample(BandwidthSample sample, TimeSpan window)
        {
            PacketCount++;
            TotalBytes += sample.Bytes;
            LastSeenUtc = sample.TimestampUtc;
            Samples.Enqueue(sample);

            if (!ProtocolCounts.TryAdd(sample.Protocol, 1))
            {
                ProtocolCounts[sample.Protocol]++;
            }

            while (Samples.Count > 0 && sample.TimestampUtc - Samples.Peek().TimestampUtc > window)
            {
                Samples.Dequeue();
            }
        }

        public double GetCurrentMbps(TimeSpan window)
        {
            if (window.TotalSeconds <= 0 || Samples.Count == 0)
            {
                return 0;
            }

            var bytes = Samples.Sum(s => s.Bytes);
            return (bytes * 8d) / window.TotalSeconds / 1_000_000d;
        }

        public string GetDominantProtocol()
        {
            return ProtocolCounts.Count == 0
                ? "Unknown"
                : ProtocolCounts.OrderByDescending(kvp => kvp.Value).First().Key;
        }
    }

    private static ICaptureDevice? device = null;
    private static readonly object packetLock = new();
    private static readonly HttpClient geoLookupClient = new() { Timeout = TimeSpan.FromSeconds(2) };
    private static readonly SemaphoreSlim geoLookupLimiter = new(3, 3);

    private static List<string> packets = new();
    private static List<EnhancedPacketInfo> enhancedPackets = new();
    private static List<string> alerts = new();
    private static List<SecurityAlert> securityAlerts = new();

    private static Dictionary<string, List<DateTime>> packetFrequency = new();
    private static Dictionary<string, HashSet<int>> portTracking = new();
    private static Dictionary<string, int> synTracking = new();
    private static Dictionary<string, int> icmpTracking = new();
    private static Dictionary<string, DateTime> lastAlertTime = new();
    private static Dictionary<string, GeoLocationInfo> geoIpCache = new(StringComparer.OrdinalIgnoreCase);
    private static Dictionary<string, string> reverseDnsCache = new(StringComparer.OrdinalIgnoreCase);
    private static HashSet<string> geoLookupInProgress = new(StringComparer.OrdinalIgnoreCase);
    private static HashSet<string> dnsLookupInProgress = new(StringComparer.OrdinalIgnoreCase);
    private static Dictionary<string, DeviceFingerprint> deviceFingerprints = new(StringComparer.OrdinalIgnoreCase);
    private static Dictionary<string, TopologyNodeInfo> topologyNodes = new(StringComparer.OrdinalIgnoreCase);
    private static Dictionary<string, HashSet<string>> nodeNeighbors = new(StringComparer.OrdinalIgnoreCase);
    private static Dictionary<string, TopologyEdgeTracker> topologyEdges = new(StringComparer.OrdinalIgnoreCase);
    private static Queue<BandwidthSample> bandwidthSamples = new();
    private static Queue<DateTime> packetArrivalTimes = new();
    private static Queue<double> jitterSamplesMs = new();
    private static Dictionary<string, long> bytesBySourceIp = new(StringComparer.OrdinalIgnoreCase);
    private static Dictionary<string, DateTime> pendingTcpSyn = new(StringComparer.OrdinalIgnoreCase);
    private static List<double> tcpHandshakeRttsMs = new();
    private static int icmpEchoRequests = 0;
    private static int icmpEchoReplies = 0;
    private static long totalObservedBytes = 0;
    private static DateTime captureStartUtc = DateTime.UtcNow;
    private static DateTime? lastPacketSeenUtc = null;
    private static double peakBandwidthMbps = 0;
    private static PacketStatistics statistics = new();

    private const int SYN_FLOOD_THRESHOLD = 200;
    private const int PORT_SCAN_THRESHOLD = 30;
    private const int ICMP_FLOOD_THRESHOLD = 150;
    private const int UDP_FLOOD_THRESHOLD = 400;
    private const int MAX_RTT_SAMPLES = 120;
    private const int MAX_JITTER_SAMPLES = 120;

    private static readonly TimeSpan WINDOW = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan ALERT_COOLDOWN = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan METRICS_WINDOW = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan PACKET_RATE_WINDOW = TimeSpan.FromSeconds(10);

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
            geoIpCache.Clear();
            reverseDnsCache.Clear();
            geoLookupInProgress.Clear();
            dnsLookupInProgress.Clear();
            deviceFingerprints.Clear();
            topologyNodes.Clear();
            topologyEdges.Clear();
            nodeNeighbors.Clear();
            bandwidthSamples.Clear();
            packetArrivalTimes.Clear();
            jitterSamplesMs.Clear();
            bytesBySourceIp.Clear();
            pendingTcpSyn.Clear();
            tcpHandshakeRttsMs.Clear();
            icmpEchoRequests = 0;
            icmpEchoReplies = 0;
            totalObservedBytes = 0;
            peakBandwidthMbps = 0;
            captureStartUtc = DateTime.UtcNow;
            lastPacketSeenUtc = null;
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

    public DataModel GetDashboardDataFiltered(string? protocol, int? minRisk, int? maxRisk, string? payloadContains)
    {
        var data = GetDashboardData();
        var filtersApplied =
            !string.IsNullOrWhiteSpace(protocol) ||
            minRisk.HasValue ||
            maxRisk.HasValue ||
            !string.IsNullOrWhiteSpace(payloadContains);

        // Preserve true packet totals/rate behavior when caller is not filtering.
        if (!filtersApplied)
        {
            return data;
        }

        IEnumerable<EnhancedPacketInfo> filtered = data.EnhancedPackets;

        if (!string.IsNullOrWhiteSpace(protocol))
        {
            filtered = filtered.Where(p => p.Protocol.Contains(protocol, StringComparison.OrdinalIgnoreCase));
        }

        if (minRisk.HasValue)
        {
            filtered = filtered.Where(p => p.RiskScore >= minRisk.Value);
        }

        if (maxRisk.HasValue)
        {
            filtered = filtered.Where(p => p.RiskScore <= maxRisk.Value);
        }

        if (!string.IsNullOrWhiteSpace(payloadContains))
        {
            filtered = filtered.Where(p => PacketContainsValue(p, payloadContains));
        }

        var filteredPackets = filtered.ToList();
        data.EnhancedPackets = filteredPackets;
        data.TotalPacketsCaptured = filteredPackets.Count;
        data.SecurityAlerts = data.SecurityAlerts
            .Where(a => filteredPackets.Any(p => p.SourceIP == a.SourceIP && p.DestinationIP == a.DestinationIP))
            .ToList();

        return data;
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
            var packetTimestampUtc = DateTime.UtcNow;

            EnsureNetworkEnrichment(src);
            EnsureNetworkEnrichment(dst);

            lock (packetLock)
            {
                // Enhanced packet analysis first
                var analysisResult = ProtocolAnalyzer.AnalyzePacket(packet, ip);
                var size = packet.Bytes.Length;

                var sourceHost = reverseDnsCache.TryGetValue(src, out var srcHostName) ? srcHostName : string.Empty;
                var destinationHost = reverseDnsCache.TryGetValue(dst, out var dstHostName) ? dstHostName : string.Empty;
                var sourceGeo = geoIpCache.TryGetValue(src, out var srcGeo) ? srcGeo : null;
                var destinationGeo = geoIpCache.TryGetValue(dst, out var dstGeo) ? dstGeo : null;

                analysisResult.Metadata["SourceHostName"] = sourceHost;
                analysisResult.Metadata["DestinationHostName"] = destinationHost;
                if (sourceGeo != null)
                    analysisResult.Metadata["SourceGeo"] = sourceGeo.DisplayName;
                if (destinationGeo != null)
                    analysisResult.Metadata["DestinationGeo"] = destinationGeo.DisplayName;
                
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

                UpdatePerformanceTracking(packet, ip, src, dst, analysisResult.Protocol, size, packetTimestampUtc);
                UpdateTopologyAndFingerprinting(packet, ip, src, dst, analysisResult.Protocol, size, packetTimestampUtc);
                
                var enhancedPacket = new EnhancedPacketInfo
                {
                    Timestamp = DateTime.Now,
                    SourceIP = src,
                    DestinationIP = dst,
                    SourceHostName = sourceHost,
                    DestinationHostName = destinationHost,
                    SourceGeoLocation = sourceGeo,
                    DestinationGeoLocation = destinationGeo,
                    Protocol = analysisResult.Protocol,
                    Size = size,
                    Details = analysisResult.Details,
                    RiskScore = analysisResult.RiskScore,
                    SecurityFlags = analysisResult.SecurityFlags,
                    Metadata = analysisResult.Metadata,
                    FormattedDisplay = FormatEnhancedPacketDisplay(analysisResult, src, dst, size)
                };

                enhancedPackets.Add(enhancedPacket);

                // Legacy packet display for compatibility
                var httpInfo = HandleHttp(packet);
                var len = size;

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

        if (IPAddress.IsLoopback(address))
            return true;

        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            return address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast;

        byte[] bytes = address.GetAddressBytes();

        return bytes[0] switch
        {
            10 => true,
            172 => bytes[1] >= 16 && bytes[1] <= 31,
            192 => bytes[1] == 168,
            _ => false
        };
    }

    private static void EnsureNetworkEnrichment(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip))
            return;

        if (!IPAddress.TryParse(ip, out _))
            return;

        var shouldLookupGeo = false;
        var shouldLookupDns = false;

        lock (packetLock)
        {
            if (!geoIpCache.ContainsKey(ip))
            {
                if (IsPrivateIP(ip))
                {
                    geoIpCache[ip] = new GeoLocationInfo
                    {
                        Country = "Private Network",
                        Region = "Local",
                        City = "LAN",
                        Isp = "Local Network",
                        IsPrivate = true
                    };
                }
                else if (!geoLookupInProgress.Contains(ip))
                {
                    geoLookupInProgress.Add(ip);
                    shouldLookupGeo = true;
                }
            }

            if (!reverseDnsCache.ContainsKey(ip) && !dnsLookupInProgress.Contains(ip))
            {
                dnsLookupInProgress.Add(ip);
                shouldLookupDns = true;
            }
        }

        if (shouldLookupGeo)
            _ = Task.Run(() => ResolveGeoIpAsync(ip));

        if (shouldLookupDns)
            _ = Task.Run(() => ResolveReverseDnsAsync(ip));
    }

    private static async Task ResolveGeoIpAsync(string ip)
    {
        try
        {
            await geoLookupLimiter.WaitAsync();

            var response = await geoLookupClient.GetAsync($"https://ipwho.is/{ip}");
            response.EnsureSuccessStatusCode();
            var json = await response.Content.ReadAsStringAsync();

            var geo = ParseGeoLocation(json);

            lock (packetLock)
            {
                geoIpCache[ip] = geo;
            }
        }
        catch
        {
            lock (packetLock)
            {
                geoIpCache[ip] = new GeoLocationInfo
                {
                    Country = "Lookup Unavailable",
                    Region = "Unknown",
                    City = "Unknown",
                    Isp = "Unknown",
                    IsPrivate = false
                };
            }
        }
        finally
        {
            lock (packetLock)
            {
                geoLookupInProgress.Remove(ip);
            }

            geoLookupLimiter.Release();
        }
    }

    private static async Task ResolveReverseDnsAsync(string ip)
    {
        try
        {
            var entry = await Dns.GetHostEntryAsync(ip);
            var hostname = string.IsNullOrWhiteSpace(entry.HostName) ? "Unresolved" : entry.HostName;
            lock (packetLock)
            {
                reverseDnsCache[ip] = hostname;
            }
        }
        catch
        {
            lock (packetLock)
            {
                reverseDnsCache[ip] = "Unresolved";
            }
        }
        finally
        {
            lock (packetLock)
            {
                dnsLookupInProgress.Remove(ip);
            }
        }
    }

    private static GeoLocationInfo ParseGeoLocation(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var success = root.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
        if (!success)
        {
            return new GeoLocationInfo
            {
                Country = "Lookup Failed",
                Region = "Unknown",
                City = "Unknown",
                Isp = "Unknown",
                IsPrivate = false
            };
        }

        return new GeoLocationInfo
        {
            Country = root.TryGetProperty("country", out var country) ? country.GetString() ?? "Unknown" : "Unknown",
            Region = root.TryGetProperty("region", out var region) ? region.GetString() ?? "Unknown" : "Unknown",
            City = root.TryGetProperty("city", out var city) ? city.GetString() ?? "Unknown" : "Unknown",
            Isp = root.TryGetProperty("connection", out var connection) && connection.TryGetProperty("isp", out var isp)
                ? isp.GetString() ?? "Unknown"
                : "Unknown",
            Latitude = root.TryGetProperty("latitude", out var latitude) && latitude.TryGetDouble(out var latValue)
                ? latValue
                : null,
            Longitude = root.TryGetProperty("longitude", out var longitude) && longitude.TryGetDouble(out var lonValue)
                ? lonValue
                : null,
            IsPrivate = false
        };
    }

    private static void UpdatePerformanceTracking(Packet packet, IPPacket ip, string src, string dst, string protocol, int size, DateTime timestampUtc)
    {
        totalObservedBytes += size;

        if (!bytesBySourceIp.TryAdd(src, size))
        {
            bytesBySourceIp[src] += size;
        }

        var sample = new BandwidthSample
        {
            TimestampUtc = timestampUtc,
            Bytes = size,
            SourceIP = src,
            Protocol = protocol
        };

        bandwidthSamples.Enqueue(sample);
        while (bandwidthSamples.Count > 0 && timestampUtc - bandwidthSamples.Peek().TimestampUtc > METRICS_WINDOW)
        {
            bandwidthSamples.Dequeue();
        }

        packetArrivalTimes.Enqueue(timestampUtc);
        while (packetArrivalTimes.Count > 0 && timestampUtc - packetArrivalTimes.Peek() > PACKET_RATE_WINDOW)
        {
            packetArrivalTimes.Dequeue();
        }

        if (lastPacketSeenUtc.HasValue)
        {
            jitterSamplesMs.Enqueue((timestampUtc - lastPacketSeenUtc.Value).TotalMilliseconds);
            while (jitterSamplesMs.Count > MAX_JITTER_SAMPLES)
            {
                jitterSamplesMs.Dequeue();
            }
        }

        lastPacketSeenUtc = timestampUtc;

        TrackTcpHandshakeLatency(packet, src, dst, timestampUtc);
        TrackIcmpReplyRate(packet);
    }

    private static void TrackTcpHandshakeLatency(Packet packet, string src, string dst, DateTime timestampUtc)
    {
        var tcp = packet.Extract<TcpPacket>();
        if (tcp == null)
            return;

        if (tcp.Synchronize && !tcp.Acknowledgment)
        {
            var key = BuildTcpFlowKey(src, dst, tcp.DestinationPort);
            pendingTcpSyn[key] = timestampUtc;
            return;
        }

        if (tcp.Synchronize && tcp.Acknowledgment)
        {
            var reverseKey = BuildTcpFlowKey(dst, src, tcp.SourcePort);
            if (pendingTcpSyn.TryGetValue(reverseKey, out var synTime))
            {
                var rtt = (timestampUtc - synTime).TotalMilliseconds;
                tcpHandshakeRttsMs.Add(Math.Max(0, rtt));
                if (tcpHandshakeRttsMs.Count > MAX_RTT_SAMPLES)
                {
                    tcpHandshakeRttsMs.RemoveAt(0);
                }
                pendingTcpSyn.Remove(reverseKey);
            }
        }
    }

    private static string BuildTcpFlowKey(string sourceIp, string destinationIp, int serverPort)
    {
        return $"{sourceIp}->{destinationIp}:{serverPort}";
    }

    private static void TrackIcmpReplyRate(Packet packet)
    {
        var icmp = packet.Extract<IcmpV4Packet>();
        if (icmp == null)
            return;

        if (icmp.TypeCode == IcmpV4TypeCode.EchoRequest)
        {
            icmpEchoRequests++;
        }
        else if (icmp.TypeCode == IcmpV4TypeCode.EchoReply)
        {
            icmpEchoReplies++;
        }
    }

    private static void UpdateTopologyAndFingerprinting(Packet packet, IPPacket ip, string src, string dst, string protocol, int size, DateTime timestampUtc)
    {
        UpdateFingerprint(src, ip, packet, protocol, size, isSource: true, timestampUtc);
        UpdateFingerprint(dst, ip, packet, protocol, size, isSource: false, timestampUtc);

        UpdateTopologyNode(src, size, timestampUtc);
        UpdateTopologyNode(dst, size, timestampUtc);

        if (!nodeNeighbors.TryGetValue(src, out var srcNeighbors))
        {
            srcNeighbors = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            nodeNeighbors[src] = srcNeighbors;
        }
        srcNeighbors.Add(dst);

        if (!nodeNeighbors.TryGetValue(dst, out var dstNeighbors))
        {
            dstNeighbors = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            nodeNeighbors[dst] = dstNeighbors;
        }
        dstNeighbors.Add(src);

        var edgeKey = $"{src}->{dst}";
        if (!topologyEdges.TryGetValue(edgeKey, out var edgeTracker))
        {
            edgeTracker = new TopologyEdgeTracker
            {
                SourceIP = src,
                DestinationIP = dst
            };
            topologyEdges[edgeKey] = edgeTracker;
        }

        edgeTracker.AddSample(new BandwidthSample
        {
            TimestampUtc = timestampUtc,
            Bytes = size,
            SourceIP = src,
            Protocol = protocol
        }, METRICS_WINDOW);
    }

    private static void UpdateTopologyNode(string ip, int bytes, DateTime timestampUtc)
    {
        if (!topologyNodes.TryGetValue(ip, out var node))
        {
            topologyNodes[ip] = new TopologyNodeInfo
            {
                NodeId = ip,
                DisplayName = ip,
                LastSeen = timestampUtc,
                TotalBytes = bytes
            };
            return;
        }

        node.LastSeen = timestampUtc;
        node.TotalBytes += bytes;

        if (reverseDnsCache.TryGetValue(ip, out var hostName) && !string.IsNullOrWhiteSpace(hostName) && hostName != "Unresolved")
        {
            node.HostName = hostName;
            node.DisplayName = hostName;
        }

        if (geoIpCache.TryGetValue(ip, out var geo))
        {
            node.GeoLocation = geo;
        }

        if (nodeNeighbors.TryGetValue(ip, out var neighbors))
        {
            node.Degree = neighbors.Count;
        }

        if (deviceFingerprints.TryGetValue(ip, out var fingerprint))
        {
            node.DeviceType = fingerprint.DeviceType;
        }
    }

    private static void UpdateFingerprint(string ip, IPPacket ipPacket, Packet packet, string protocol, int size, bool isSource, DateTime timestampUtc)
    {
        if (!deviceFingerprints.TryGetValue(ip, out var fingerprint))
        {
            fingerprint = new DeviceFingerprint
            {
                IPAddress = ip,
                FirstSeen = timestampUtc,
                LastSeen = timestampUtc,
                IsPrivate = IsPrivateIP(ip)
            };
            deviceFingerprints[ip] = fingerprint;
        }

        fingerprint.PacketCount++;
        fingerprint.LastSeen = timestampUtc;

        if (isSource)
        {
            fingerprint.BytesSent += size;
        }
        else
        {
            fingerprint.BytesReceived += size;
        }

        if (!fingerprint.ObservedProtocols.Contains(protocol, StringComparer.OrdinalIgnoreCase))
        {
            fingerprint.ObservedProtocols.Add(protocol);
        }

        if (!fingerprint.ProtocolDistribution.TryAdd(protocol, 1))
        {
            fingerprint.ProtocolDistribution[protocol]++;
        }

        var tcp = packet.Extract<TcpPacket>();
        if (tcp != null)
        {
            var observedPort = isSource ? tcp.SourcePort : tcp.DestinationPort;
            if (!fingerprint.ObservedPorts.Contains(observedPort))
            {
                fingerprint.ObservedPorts.Add(observedPort);
            }
        }

        var udp = packet.Extract<UdpPacket>();
        if (udp != null)
        {
            var observedPort = isSource ? udp.SourcePort : udp.DestinationPort;
            if (!fingerprint.ObservedPorts.Contains(observedPort))
            {
                fingerprint.ObservedPorts.Add(observedPort);
            }
        }

        if (reverseDnsCache.TryGetValue(ip, out var hostName))
        {
            fingerprint.HostName = hostName;
        }

        if (geoIpCache.TryGetValue(ip, out var geoLocation))
        {
            fingerprint.GeoLocation = geoLocation;
        }

        fingerprint.ProbableOS = InferOperatingSystem(ipPacket.TimeToLive);
        fingerprint.DeviceType = InferDeviceType(fingerprint);
        fingerprint.TrafficProfile = InferTrafficProfile(fingerprint);
    }

    private static string InferOperatingSystem(int ttl)
    {
        return ttl switch
        {
            <= 64 => "Linux/Unix/IoT-like",
            <= 128 => "Windows-like",
            <= 255 => "Network appliance/router-like",
            _ => "Unknown"
        };
    }

    private static string InferDeviceType(DeviceFingerprint fingerprint)
    {
        var ports = fingerprint.ObservedPorts;
        if (ports.Contains(53) || ports.Contains(67) || ports.Contains(68) || ports.Contains(161))
            return "Infrastructure Device";

        if (ports.Contains(80) || ports.Contains(443) || ports.Contains(22) || ports.Contains(3389) || ports.Contains(445))
            return "Workstation/Server";

        if (fingerprint.ObservedProtocols.All(p => p.Equals("ICMP", StringComparison.OrdinalIgnoreCase)))
            return "Monitoring Endpoint";

        return fingerprint.IsPrivate ? "Internal Client" : "External Host";
    }

    private static string InferTrafficProfile(DeviceFingerprint fingerprint)
    {
        var distribution = fingerprint.ProtocolDistribution;
        if (distribution.Count == 0)
            return "Unknown";

        var top = distribution.OrderByDescending(kvp => kvp.Value).First().Key;
        return top.ToUpperInvariant() switch
        {
            "DNS" => "Name-resolution heavy",
            "TCP" => "Session-oriented",
            "UDP" => "Datagram/burst",
            "ICMP" => "Control/diagnostic",
            _ => $"{top} dominant"
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
            bandwidthSamples.Clear();
            packetArrivalTimes.Clear();
            jitterSamplesMs.Clear();
            bytesBySourceIp.Clear();
            pendingTcpSyn.Clear();
            tcpHandshakeRttsMs.Clear();
            icmpEchoRequests = 0;
            icmpEchoReplies = 0;
            totalObservedBytes = 0;
            peakBandwidthMbps = 0;
            captureStartUtc = DateTime.UtcNow;
            lastPacketSeenUtc = null;
            topologyEdges.Clear();
            topologyNodes.Clear();
            nodeNeighbors.Clear();
            deviceFingerprints.Clear();
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
        statistics.TotalBytes = enhancedPackets.Sum(p => (long)p.Size);
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

        var nowUtc = DateTime.UtcNow;
        statistics.Bandwidth = BuildBandwidthMetrics(nowUtc);
        statistics.Performance = BuildPerformanceMetrics();
        statistics.DeviceFingerprints = deviceFingerprints.Values
            .OrderByDescending(d => d.PacketCount)
            .Take(30)
            .Select(CloneFingerprint)
            .ToList();
        statistics.TopologyMap = BuildTopologyMap(nowUtc);
            
        statistics.LastUpdate = DateTime.Now;
    }

    private static BandwidthUtilizationMetrics BuildBandwidthMetrics(DateTime nowUtc)
    {
        while (bandwidthSamples.Count > 0 && nowUtc - bandwidthSamples.Peek().TimestampUtc > METRICS_WINDOW)
        {
            bandwidthSamples.Dequeue();
        }

        while (packetArrivalTimes.Count > 0 && nowUtc - packetArrivalTimes.Peek() > PACKET_RATE_WINDOW)
        {
            packetArrivalTimes.Dequeue();
        }

        var windowSeconds = METRICS_WINDOW.TotalSeconds;
        var totalBytesInWindow = bandwidthSamples.Sum(s => s.Bytes);
        var currentMbps = (totalBytesInWindow * 8d) / windowSeconds / 1_000_000d;
        var averageElapsedSeconds = Math.Max(1d, (nowUtc - captureStartUtc).TotalSeconds);
        var averageMbps = (totalObservedBytes * 8d) / averageElapsedSeconds / 1_000_000d;
        peakBandwidthMbps = Math.Max(peakBandwidthMbps, currentMbps);

        var protocolBandwidth = bandwidthSamples
            .GroupBy(s => s.Protocol)
            .ToDictionary(
                g => g.Key,
                g => (g.Sum(sample => sample.Bytes) * 8d) / windowSeconds / 1_000_000d,
                StringComparer.OrdinalIgnoreCase);

        var topTalkers = bytesBySourceIp
            .OrderByDescending(kvp => kvp.Value)
            .Take(10)
            .Select(kvp => new TopTalkerMetric
            {
                IPAddress = kvp.Key,
                HostName = reverseDnsCache.TryGetValue(kvp.Key, out var host) ? host : string.Empty,
                Bytes = kvp.Value,
                MegabitsPerSecond = (kvp.Value * 8d) / averageElapsedSeconds / 1_000_000d
            })
            .ToList();

        return new BandwidthUtilizationMetrics
        {
            CurrentMbps = currentMbps,
            AverageMbps = averageMbps,
            PeakMbps = peakBandwidthMbps,
            PacketsPerSecond = packetArrivalTimes.Count / Math.Max(1d, PACKET_RATE_WINDOW.TotalSeconds),
            ProtocolBandwidthMbps = protocolBandwidth,
            TopTalkers = topTalkers
        };
    }

    private static NetworkPerformanceMetrics BuildPerformanceMetrics()
    {
        var jitterMs = jitterSamplesMs.Count > 0 ? jitterSamplesMs.Average() : 0;
        var avgRttMs = tcpHandshakeRttsMs.Count > 0 ? tcpHandshakeRttsMs.Average() : 0;
        var icmpReplyRate = icmpEchoRequests > 0 ? (icmpEchoReplies * 100d / icmpEchoRequests) : 0;
        var avgPacketSize = enhancedPackets.Count > 0 ? enhancedPackets.Average(p => p.Size) : 0;

        return new NetworkPerformanceMetrics
        {
            AveragePacketSizeBytes = avgPacketSize,
            EstimatedJitterMs = jitterMs,
            AverageTcpHandshakeRttMs = avgRttMs,
            IcmpReplyRatePercent = icmpReplyRate,
            TotalObservedBytes = totalObservedBytes
        };
    }

    private static NetworkTopologyMap BuildTopologyMap(DateTime nowUtc)
    {
        var links = topologyEdges.Values
            .OrderByDescending(e => e.PacketCount)
            .Take(50)
            .Select(e => new TopologyLinkInfo
            {
                SourceNodeId = e.SourceIP,
                DestinationNodeId = e.DestinationIP,
                DominantProtocol = e.GetDominantProtocol(),
                PacketCount = e.PacketCount,
                TotalBytes = e.TotalBytes,
                CurrentMbps = e.GetCurrentMbps(METRICS_WINDOW),
                LastSeen = e.LastSeenUtc
            })
            .ToList();

        foreach (var node in topologyNodes.Values)
        {
            if (nodeNeighbors.TryGetValue(node.NodeId, out var neighbors))
            {
                node.Degree = neighbors.Count;
            }

            if (reverseDnsCache.TryGetValue(node.NodeId, out var hostName) && !string.IsNullOrWhiteSpace(hostName) && hostName != "Unresolved")
            {
                node.HostName = hostName;
                node.DisplayName = hostName;
            }

            if (geoIpCache.TryGetValue(node.NodeId, out var geo))
            {
                node.GeoLocation = geo;
            }

            if (deviceFingerprints.TryGetValue(node.NodeId, out var fingerprint))
            {
                node.DeviceType = fingerprint.DeviceType;
            }
        }

        var nodes = topologyNodes.Values
            .OrderByDescending(n => n.TotalBytes)
            .Take(80)
            .Select(n => new TopologyNodeInfo
            {
                NodeId = n.NodeId,
                DisplayName = string.IsNullOrWhiteSpace(n.DisplayName) ? n.NodeId : n.DisplayName,
                HostName = n.HostName,
                DeviceType = n.DeviceType,
                GeoLocation = n.GeoLocation,
                Degree = n.Degree,
                TotalBytes = n.TotalBytes,
                LastSeen = n.LastSeen
            })
            .ToList();

        return new NetworkTopologyMap
        {
            Nodes = nodes,
            Links = links,
            TotalNodes = topologyNodes.Count,
            TotalLinks = topologyEdges.Count
        };
    }

    private static DeviceFingerprint CloneFingerprint(DeviceFingerprint source)
    {
        return new DeviceFingerprint
        {
            IPAddress = source.IPAddress,
            HostName = source.HostName,
            ProbableOS = source.ProbableOS,
            DeviceType = source.DeviceType,
            TrafficProfile = source.TrafficProfile,
            IsPrivate = source.IsPrivate,
            GeoLocation = source.GeoLocation,
            ObservedPorts = source.ObservedPorts.OrderBy(p => p).ToList(),
            ObservedProtocols = source.ObservedProtocols.OrderBy(p => p).ToList(),
            ProtocolDistribution = source.ProtocolDistribution
                .OrderByDescending(kvp => kvp.Value)
                .ToDictionary(kvp => kvp.Key, kvp => kvp.Value, StringComparer.OrdinalIgnoreCase),
            BytesSent = source.BytesSent,
            BytesReceived = source.BytesReceived,
            PacketCount = source.PacketCount,
            FirstSeen = source.FirstSeen,
            LastSeen = source.LastSeen
        };
    }

    private static bool PacketContainsValue(EnhancedPacketInfo packet, string value)
    {
        if (packet.Details.Contains(value, StringComparison.OrdinalIgnoreCase))
            return true;

        if (packet.SecurityFlags.Any(f => f.Contains(value, StringComparison.OrdinalIgnoreCase)))
            return true;

        foreach (var item in packet.Metadata.Values)
        {
            var text = item?.ToString();
            if (!string.IsNullOrWhiteSpace(text) && text.Contains(value, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
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