using System.Collections.Concurrent;

namespace NetworkMonitor.Backend.ML;

/// <summary>
/// ML training data structures for traffic classification model.
/// </summary>
public class MLTrainingData
{
    /// <summary>
    /// Single training example for the ML model.
    /// </summary>
    public sealed class TrafficSample
    {
        // Input features
        public int PacketSize { get; set; }
        public int PayloadSize { get; set; }
        public int PacketSizeCategory { get; set; }
        public float PayloadRatio { get; set; }
        public int HeaderSize { get; set; }

        public int SourcePort { get; set; }
        public int DestinationPort { get; set; }
        public float IsSourceWellKnown { get; set; }
        public float IsDestinationWellKnown { get; set; }
        public int PortDifference { get; set; }

        public int ProtocolType { get; set; }
        public float IsTCP { get; set; }
        public float IsUDP { get; set; }
        public float IsICMP { get; set; }
        public int TTL { get; set; }

        public int TCPFlagsSet { get; set; }
        public float IsTCPSyn { get; set; }
        public float IsTCPAck { get; set; }
        public float IsTCPFin { get; set; }
        public float IsTCPRst { get; set; }
        public int WindowSize { get; set; }

        public float PayloadEntropy { get; set; }
        public float PayloadHasText { get; set; }
        public float PayloadHasNull { get; set; }
        public float PayloadMeanByte { get; set; }
        public float PayloadVariance { get; set; }

        public float IsGamingPort { get; set; }
        public float IsStreamingPort { get; set; }
        public float IsP2PPort { get; set; }
        public float IsVoIPPort { get; set; }
        public float IsHighPort { get; set; }

        public int AppProtocolEncoded { get; set; }
        public float IsKnownProtocol { get; set; }
        public float ProtocolConfidence { get; set; }
        public float IsEncrypted { get; set; }
        public float IsCompressed { get; set; }

        public int SourceIPType { get; set; }
        public int DestinationIPType { get; set; }
        public int IPTotalLength { get; set; }
        public float IsFragmented { get; set; }
        public int TTLBucket { get; set; }

        // Target label
        public string Label { get; set; } = "Unknown";
    }

    /// <summary>
    /// Aggregated training dataset for model training.
    /// </summary>
    public sealed class TrafficDataset
    {
        public List<TrafficSample> Samples { get; set; } = new();
        public Dictionary<string, int> LabelDistribution { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
        public int TotalSamples => Samples.Count;

        /// <summary>
        /// Validates dataset quality for training.
        /// </summary>
        public ValidationResult Validate()
        {
            var result = new ValidationResult();

            if (Samples.Count < 100)
            {
                result.IsValid = false;
                result.Issues.Add($"Insufficient samples: {Samples.Count} (minimum 100 required)");
            }

            var labelCounts = Samples.GroupBy(s => s.Label).ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);

            foreach (var (label, count) in labelCounts)
            {
                var ratio = count / (double)Samples.Count;
                if (ratio < 0.02)
                {
                    result.Issues.Add($"Class imbalance: '{label}' has only {ratio:P} ({count} samples)");
                }
            }

            if (labelCounts.Count < 5)
            {
                result.Issues.Add($"Too few classes: {labelCounts.Count} (should have at least 5)");
            }

            result.IsValid = result.Issues.Count == 0;
            result.SampleCount = Samples.Count;
            result.ClassCount = labelCounts.Count;
            result.LabelDistribution = labelCounts;

            return result;
        }

        /// <summary>
        /// Splits dataset into training and test sets.
        /// </summary>
        public (TrafficDataset Train, TrafficDataset Test) Split(double trainRatio = 0.8)
        {
            var shuffled = Samples.OrderBy(_ => Guid.NewGuid()).ToList();
            var splitIndex = (int)(shuffled.Count * trainRatio);

            var trainSamples = shuffled.Take(splitIndex).ToList();
            var testSamples = shuffled.Skip(splitIndex).ToList();

            return (
                new TrafficDataset { Samples = trainSamples },
                new TrafficDataset { Samples = testSamples }
            );
        }

        /// <summary>
        /// Balances dataset by undersampling majority classes.
        /// </summary>
        public TrafficDataset Balance()
        {
            var grouped = Samples.GroupBy(s => s.Label).ToList();
            var minCount = grouped.Min(g => g.Count());

            var balanced = grouped
                .SelectMany(g => g.OrderBy(_ => Guid.NewGuid()).Take(minCount))
                .ToList();

            return new TrafficDataset { Samples = balanced };
        }
    }

    /// <summary>
    /// Validation results for datasets.
    /// </summary>
    public sealed class ValidationResult
    {
        public bool IsValid { get; set; }
        public int SampleCount { get; set; }
        public int ClassCount { get; set; }
        public List<string> Issues { get; set; } = new();
        public Dictionary<string, int> LabelDistribution { get; set; } = new(StringComparer.OrdinalIgnoreCase);

        public override string ToString()
        {
            if (IsValid)
                return $"✓ Valid dataset: {SampleCount} samples, {ClassCount} classes";

            return $"✗ Invalid dataset: {string.Join("; ", Issues)}";
        }
    }

    /// <summary>
    /// Converts feature vectors to training samples.
    /// </summary>
    public static TrafficSample FromFeatureVector(TrafficFeatureVector features, string label)
    {
        return new TrafficSample
        {
            PacketSize = features.PacketSize,
            PayloadSize = features.PayloadSize,
            PacketSizeCategory = features.PacketSizeCategory,
            PayloadRatio = (float)features.PayloadRatio,
            HeaderSize = features.HeaderSize,
            SourcePort = features.SourcePort,
            DestinationPort = features.DestinationPort,
            IsSourceWellKnown = features.IsSourceWellKnown,
            IsDestinationWellKnown = features.IsDestinationWellKnown,
            PortDifference = features.PortDifference,
            ProtocolType = features.ProtocolType,
            IsTCP = features.IsTCP,
            IsUDP = features.IsUDP,
            IsICMP = features.IsICMP,
            TTL = features.TTL,
            TCPFlagsSet = features.TCPFlagsSet,
            IsTCPSyn = features.IsTCPSyn,
            IsTCPAck = features.IsTCPAck,
            IsTCPFin = features.IsTCPFin,
            IsTCPRst = features.IsTCPRst,
            WindowSize = features.WindowSize,
            PayloadEntropy = (float)features.PayloadEntropy,
            PayloadHasText = features.PayloadHasText,
            PayloadHasNull = features.PayloadHasNull,
            PayloadMeanByte = (float)features.PayloadMeanByte,
            PayloadVariance = (float)features.PayloadVariance,
            IsGamingPort = features.IsGamingPort,
            IsStreamingPort = features.IsStreamingPort,
            IsP2PPort = features.IsP2PPort,
            IsVoIPPort = features.IsVoIPPort,
            IsHighPort = features.IsHighPort,
            AppProtocolEncoded = features.AppProtocolEncoded,
            IsKnownProtocol = features.IsKnownProtocol,
            ProtocolConfidence = features.ProtocolConfidence,
            IsEncrypted = features.IsEncrypted,
            IsCompressed = features.IsCompressed,
            SourceIPType = features.SourceIPType,
            DestinationIPType = features.DestinationIPType,
            IPTotalLength = features.IPTotalLength,
            IsFragmented = features.IsFragmented,
            TTLBucket = features.TTLBucket,
            Label = label
        };
    }
}

/// <summary>
/// Manages training data collection and aggregation for model improvement.
/// </summary>
public class TrainingDataCollector
{
    private readonly ConcurrentBag<MLTrainingData.TrafficSample> _samples = new();
    private readonly int _maxSamples;
    private readonly ConcurrentDictionary<string, int> _labelCounts = new(StringComparer.OrdinalIgnoreCase);

    public TrainingDataCollector(int maxSamples = 100000)
    {
        _maxSamples = maxSamples;
    }

    public void AddSample(TrafficFeatureVector features, string label)
    {
        if (_samples.Count >= _maxSamples)
            return; // Stop collecting when limit reached

        var sample = MLTrainingData.FromFeatureVector(features, label);
        _samples.Add(sample);
        _labelCounts.AddOrUpdate(label, 1, (_, count) => count + 1);
    }

    public MLTrainingData.TrafficDataset BuildDataset()
    {
        return new MLTrainingData.TrafficDataset
        {
            Samples = _samples.ToList(),
            LabelDistribution = _labelCounts.ToDictionary(kvp => kvp.Key, kvp => kvp.Value)
        };
    }

    public void Clear()
    {
        _samples.Clear();
        _labelCounts.Clear();
    }

    public int SampleCount => _samples.Count;
    public IReadOnlyDictionary<string, int> LabelCounts => _labelCounts;
}
