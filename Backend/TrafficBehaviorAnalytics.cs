namespace NetworkMonitor.Backend;

public sealed class TrafficAnalyticsSnapshot
{
    public Dictionary<string, int> ApplicationProtocolCounts { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, int> TrafficClassificationCounts { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public double ProtocolDiversityEntropy { get; init; }
    public BaselineSnapshot Baseline { get; init; } = new();
    public TrafficPatternAnalytics PatternAnalytics { get; init; } = new();
    public TrafficAnomalyReport AnomalyReport { get; init; } = new();
}

public sealed class TrafficBehaviorAnalyticsEngine
{
    private sealed class TrafficObservation
    {
        public DateTime TimestampUtc { get; init; }
        public int PacketSize { get; init; }
        public int RiskScore { get; init; }
        public string SourceIP { get; init; } = string.Empty;
        public string DestinationIP { get; init; } = string.Empty;
        public string Protocol { get; init; } = "Unknown";
        public string ApplicationProtocol { get; init; } = "Unknown";
        public string Classification { get; init; } = "Unknown";
    }

    private sealed class BaselineTracker
    {
        private readonly double _alpha;

        public BaselineTracker(double alpha)
        {
            _alpha = alpha;
        }

        public double Mean { get; private set; }
        public double Variance { get; private set; }
        public int Samples { get; private set; }

        public double StdDev => Math.Sqrt(Math.Max(Variance, 0.0001));

        public void Update(double value)
        {
            if (Samples == 0)
            {
                Mean = value;
                Variance = 0;
                Samples = 1;
                return;
            }

            var delta = value - Mean;
            Mean += _alpha * delta;
            Variance = (1 - _alpha) * (Variance + _alpha * delta * delta);
            Samples++;
        }
    }

    private readonly Queue<TrafficObservation> _observations = new();
    private readonly Dictionary<string, BaselineTracker> _baseline = new(StringComparer.OrdinalIgnoreCase);

    private readonly TimeSpan _window = TimeSpan.FromSeconds(60);
    private readonly int _minBaselineWindows;

    public TrafficBehaviorAnalyticsEngine(int minBaselineWindows = 25)
    {
        _minBaselineWindows = Math.Max(8, minBaselineWindows);
    }

    public void Reset()
    {
        _observations.Clear();
        _baseline.Clear();
    }

    public void ObservePacket(EnhancedPacketInfo packet, DateTime timestampUtc)
    {
        var appProtocol = ReadMetadataValue(packet.Metadata, "ApplicationProtocol", packet.Protocol);
        var trafficClass = ReadMetadataValue(packet.Metadata, "TrafficClass", "Unknown");

        _observations.Enqueue(new TrafficObservation
        {
            TimestampUtc = timestampUtc,
            PacketSize = packet.Size,
            RiskScore = packet.RiskScore,
            SourceIP = packet.SourceIP,
            DestinationIP = packet.DestinationIP,
            Protocol = packet.Protocol,
            ApplicationProtocol = appProtocol,
            Classification = trafficClass
        });

        Trim(timestampUtc);
    }

    public TrafficAnalyticsSnapshot BuildSnapshot(DateTime nowUtc)
    {
        Trim(nowUtc);

        if (_observations.Count == 0)
        {
            return new TrafficAnalyticsSnapshot
            {
                Baseline = new BaselineSnapshot
                {
                    IsEstablished = false,
                    WarmupWindows = 0,
                    MinimumWindowsRequired = _minBaselineWindows,
                    LastUpdatedUtc = nowUtc
                },
                PatternAnalytics = new TrafficPatternAnalytics(),
                AnomalyReport = new TrafficAnomalyReport
                {
                    BaselineReady = false,
                    GeneratedAtUtc = nowUtc,
                    OverallSeverity = "None"
                }
            };
        }

        var windowSeconds = Math.Max(1d, _window.TotalSeconds);
        var groupedApp = _observations
            .GroupBy(o => o.ApplicationProtocol)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);
        var groupedClass = _observations
            .GroupBy(o => o.Classification)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);

        var uniqueSources = _observations.Select(o => o.SourceIP).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var uniqueDestinations = _observations.Select(o => o.DestinationIP).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var uniqueConversations = _observations
            .Select(o => $"{o.SourceIP}->{o.DestinationIP}")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();

        var packetRate = _observations.Count / windowSeconds;
        var bytesPerSecond = _observations.Sum(o => (long)o.PacketSize) / windowSeconds;
        var avgPacketSize = _observations.Average(o => o.PacketSize);
        var highRiskRatio = _observations.Count == 0
            ? 0
            : (_observations.Count(o => o.RiskScore >= 50) * 100d / _observations.Count);

        var pattern = new TrafficPatternAnalytics
        {
            PacketRatePerSecond = Math.Round(packetRate, 3),
            BytesPerSecond = Math.Round(bytesPerSecond, 3),
            UniqueSourceIps = uniqueSources,
            UniqueDestinationIps = uniqueDestinations,
            UniqueConversations = uniqueConversations,
            HighRiskPacketRatioPercent = Math.Round(highRiskRatio, 2),
            AveragePacketSizeBytes = Math.Round(avgPacketSize, 2),
            ClassificationDistributionPercent = ToPercentDistribution(groupedClass, _observations.Count),
            ApplicationProtocolDistributionPercent = ToPercentDistribution(groupedApp, _observations.Count)
        };

        var metricValues = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase)
        {
            ["packet_rate"] = packetRate,
            ["bytes_per_second"] = bytesPerSecond,
            ["unique_sources"] = uniqueSources,
            ["unique_destinations"] = uniqueDestinations,
            ["unique_conversations"] = uniqueConversations,
            ["avg_packet_size"] = avgPacketSize,
            ["high_risk_ratio"] = highRiskRatio,
            ["protocol_entropy"] = ComputeEntropy(groupedApp)
        };

        var anomalies = new List<TrafficAnomalyMetric>();
        foreach (var (name, value) in metricValues)
        {
            if (!_baseline.TryGetValue(name, out var tracker))
            {
                tracker = new BaselineTracker(alpha: 0.18);
                _baseline[name] = tracker;
            }

            var isReady = tracker.Samples >= _minBaselineWindows;
            var zScore = isReady ? (value - tracker.Mean) / tracker.StdDev : 0;
            if (isReady && Math.Abs(zScore) >= 2.5)
            {
                anomalies.Add(new TrafficAnomalyMetric
                {
                    Metric = name,
                    CurrentValue = Math.Round(value, 4),
                    BaselineMean = Math.Round(tracker.Mean, 4),
                    BaselineStdDev = Math.Round(tracker.StdDev, 4),
                    ZScore = Math.Round(zScore, 3),
                    Severity = ToSeverity(zScore),
                    Direction = zScore > 0 ? "AboveBaseline" : "BelowBaseline"
                });
            }

            if (!isReady || Math.Abs(zScore) < 6.0)
            {
                tracker.Update(value);
            }
        }

        var warmup = _baseline.Values.Any() ? _baseline.Values.Min(v => v.Samples) : 0;
        var baselineReady = warmup >= _minBaselineWindows;

        var baseline = new BaselineSnapshot
        {
            IsEstablished = baselineReady,
            WarmupWindows = warmup,
            MinimumWindowsRequired = _minBaselineWindows,
            LastUpdatedUtc = nowUtc,
            Metrics = _baseline
                .OrderBy(kvp => kvp.Key)
                .Select(kvp => new BaselineMetric
                {
                    Name = kvp.Key,
                    Mean = Math.Round(kvp.Value.Mean, 4),
                    StandardDeviation = Math.Round(kvp.Value.StdDev, 4),
                    Samples = kvp.Value.Samples
                })
                .ToList()
        };

        var anomalyReport = new TrafficAnomalyReport
        {
            BaselineReady = baselineReady,
            GeneratedAtUtc = nowUtc,
            TotalAnomalies = anomalies.Count,
            OverallSeverity = CalculateOverallSeverity(anomalies),
            Metrics = anomalies
                .OrderByDescending(a => Math.Abs(a.ZScore))
                .ToList()
        };

        return new TrafficAnalyticsSnapshot
        {
            ApplicationProtocolCounts = groupedApp,
            TrafficClassificationCounts = groupedClass,
            ProtocolDiversityEntropy = Math.Round(metricValues["protocol_entropy"], 4),
            Baseline = baseline,
            PatternAnalytics = pattern,
            AnomalyReport = anomalyReport
        };
    }

    private static string ReadMetadataValue(Dictionary<string, object>? metadata, string key, string fallback)
    {
        if (metadata == null || !metadata.TryGetValue(key, out var value) || value == null)
        {
            return fallback;
        }

        var text = value.ToString();
        return string.IsNullOrWhiteSpace(text) ? fallback : text;
    }

    private void Trim(DateTime nowUtc)
    {
        while (_observations.Count > 0 && nowUtc - _observations.Peek().TimestampUtc > _window)
        {
            _observations.Dequeue();
        }
    }

    private static Dictionary<string, double> ToPercentDistribution(Dictionary<string, int> counts, int total)
    {
        if (total <= 0)
        {
            return new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        }

        return counts
            .OrderByDescending(kvp => kvp.Value)
            .ToDictionary(
                kvp => kvp.Key,
                kvp => Math.Round((kvp.Value * 100d) / total, 2),
                StringComparer.OrdinalIgnoreCase);
    }

    private static double ComputeEntropy(Dictionary<string, int> counts)
    {
        var total = counts.Values.Sum();
        if (total <= 0)
        {
            return 0;
        }

        double entropy = 0;
        foreach (var count in counts.Values)
        {
            var p = count / (double)total;
            if (p <= 0)
            {
                continue;
            }

            entropy -= p * Math.Log(p, 2);
        }

        return entropy;
    }

    private static string ToSeverity(double zScore)
    {
        var abs = Math.Abs(zScore);
        if (abs >= 5.0) return "Critical";
        if (abs >= 3.5) return "High";
        return "Medium";
    }

    private static string CalculateOverallSeverity(List<TrafficAnomalyMetric> anomalies)
    {
        if (anomalies.Count == 0)
        {
            return "None";
        }

        if (anomalies.Any(a => a.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase)))
        {
            return "Critical";
        }

        if (anomalies.Any(a => a.Severity.Equals("High", StringComparison.OrdinalIgnoreCase)))
        {
            return "High";
        }

        return "Medium";
    }
}
