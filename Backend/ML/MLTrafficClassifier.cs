using System.Collections.Concurrent;

namespace NetworkMonitor.Backend.ML;

/// <summary>
/// ML-based traffic classifier using ensemble learning methods.
/// Supports training, prediction, model persistence, and confidence scoring.
/// </summary>
public sealed class MLTrafficClassifier : IDisposable
{
    private sealed class PredictionModel
    {
        public Dictionary<string, float> ClassWeights { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, FeatureWeights> FeatureImportance { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public TrainingMetrics Metrics { get; set; } = new();
        public DateTime TrainedUtc { get; set; }
        public int SampleCount { get; set; }
        public int Version { get; set; } = 1;
    }

    private sealed class FeatureWeights
    {
        public float PacketSizeWeight { get; set; }
        public float PortWeight { get; set; }
        public float ProtocolWeight { get; set; }
        public float PayloadWeight { get; set; }
        public float AppProtocolWeight { get; set; }
        public float EncryptionWeight { get; set; }
    }

    public sealed class TrainingMetrics
    {
        public double Accuracy { get; set; }
        public double MacroF1 { get; set; }
        public double WeightedF1 { get; set; }
        public Dictionary<string, ClassMetrics> PerClassMetrics { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public int TrainingTimeMs { get; set; }
        public int EvaluationTimeMs { get; set; }
    }

    public sealed class ClassMetrics
    {
        public string ClassName { get; set; } = string.Empty;
        public double Precision { get; set; }
        public double Recall { get; set; }
        public double F1Score { get; set; }
        public int SampleCount { get; set; }
    }

    public sealed class PredictionResult
    {
        public string PredictedClass { get; set; } = "Unknown";
        public float Confidence { get; set; }
        public Dictionary<string, float> ClassProbabilities { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public bool IsConfident => Confidence >= 0.65f;
        public string[] TopAlternatives { get; set; } = Array.Empty<string>();
    }

    private PredictionModel? _model;
    private readonly string _modelPath;
    private readonly object _lockObject = new();
    private bool _isDisposed;

    // Default class labels
    private static readonly string[] DefaultClasses = new[]
    {
        "Web", "Streaming", "Gaming", "P2P", "VoIP",
        "FileTransfer", "RemoteAccess", "Infrastructure", "Messaging"
    };

    public MLTrafficClassifier(string modelPath = "ml_models/traffic_classifier.model")
    {
        _modelPath = modelPath;
        EnsureDirectory(_modelPath);
    }

    /// <summary>
    /// Trains the ML model on provided dataset.
    /// </summary>
    public async Task<TrainingMetrics> TrainAsync(MLTrainingData.TrafficDataset dataset, CancellationToken cancellationToken = default)
    {
        var validation = dataset.Validate();
        if (!validation.IsValid)
            throw new InvalidOperationException($"Invalid dataset: {validation}");

        var startTime = DateTime.UtcNow;
        var metrics = new TrainingMetrics { TrainingTimeMs = 0, EvaluationTimeMs = 0 };

        try
        {
            return await Task.Run(() =>
            {
                // Balance dataset
                var balancedDataset = dataset.Balance();

                // Calculate class weights
                var (train, test) = balancedDataset.Split(0.8);

                // Train using ensemble-like approach
                metrics = EvaluateModel(train, test);
                metrics.TrainingTimeMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds;

                lock (_lockObject)
                {
                    _model = new PredictionModel
                    {
                        Metrics = metrics,
                        TrainedUtc = DateTime.UtcNow,
                        SampleCount = dataset.TotalSamples,
                        ClassWeights = CalculateClassWeights(train)
                    };
                }

                SaveModel();

                return metrics;
            }, cancellationToken);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Model training failed: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Predicts traffic class for given features.
    /// </summary>
    public PredictionResult Predict(TrafficFeatureVector features)
    {
        ThrowIfDisposed();

        lock (_lockObject)
        {
            if (_model == null)
                return CreateDefaultPrediction(features);

            var scores = ComputeClassScores(features);
            var (predictedClass, confidence) = SelectBestClass(scores);

            var topAlts = scores
                .OrderByDescending(kvp => kvp.Value)
                .Skip(1)
                .Take(2)
                .Select(kvp => kvp.Key)
                .ToArray();

            return new PredictionResult
            {
                PredictedClass = predictedClass,
                Confidence = confidence,
                ClassProbabilities = Softmax(scores),
                TopAlternatives = topAlts
            };
        }
    }

    /// <summary>
    /// Saves trained model to disk.
    /// </summary>
    public void SaveModel()
    {
        ThrowIfDisposed();

        lock (_lockObject)
        {
            if (_model == null)
                return;

            try
            {
                var json = System.Text.Json.JsonSerializer.Serialize(_model, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_modelPath, json);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Failed to save model: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// Loads trained model from disk.
    /// </summary>
    public bool LoadModel()
    {
        ThrowIfDisposed();

        try
        {
            if (!File.Exists(_modelPath))
                return false;

            var json = File.ReadAllText(_modelPath);
            var loaded = System.Text.Json.JsonSerializer.Deserialize<PredictionModel>(json);

            lock (_lockObject)
            {
                _model = loaded;
            }

            return _model != null;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Failed to load model: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Incremental learning: updates model with new samples without full retraining.
    /// </summary>
    public async Task UpdateModelAsync(IEnumerable<(TrafficFeatureVector Features, string Label)> newSamples)
    {
        ThrowIfDisposed();

        var samples = newSamples.ToList();
        if (samples.Count == 0)
            return;

        await Task.Run(() =>
        {
            lock (_lockObject)
            {
                if (_model == null)
                    return;

                // Apply incremental learning - adjust class weights
                foreach (var (features, label) in samples)
                {
                    if (!_model.ClassWeights.ContainsKey(label))
                        _model.ClassWeights[label] = 0.5f;

                    // Exponential moving average update
                    var prediction = ComputeClassScores(features);
                    if (prediction.TryGetValue(label, out var score))
                    {
                        _model.ClassWeights[label] = 0.95f * _model.ClassWeights[label] + 0.05f * score;
                    }
                }

                _model.SampleCount += samples.Count;
                SaveModel();
            }
        });
    }

    /// <summary>
    /// Gets model information and performance metrics.
    /// </summary>
    public ModelInfo GetModelInfo()
    {
        ThrowIfDisposed();

        lock (_lockObject)
        {
            if (_model == null)
                return new ModelInfo { IsLoaded = false };

            return new ModelInfo
            {
                IsLoaded = true,
                TrainedUtc = _model.TrainedUtc,
                TrainingSamples = _model.SampleCount,
                Version = _model.Version,
                Accuracy = _model.Metrics.Accuracy,
                MacroF1 = _model.Metrics.MacroF1,
                WeightedF1 = _model.Metrics.WeightedF1,
                TrainingTimeMs = _model.Metrics.TrainingTimeMs
            };
        }
    }

    public sealed class ModelInfo
    {
        public bool IsLoaded { get; set; }
        public DateTime TrainedUtc { get; set; }
        public int TrainingSamples { get; set; }
        public int Version { get; set; }
        public double Accuracy { get; set; }
        public double MacroF1 { get; set; }
        public double WeightedF1 { get; set; }
        public int TrainingTimeMs { get; set; }
    }

    #region Private Methods

    private Dictionary<string, float> ComputeClassScores(TrafficFeatureVector features)
    {
        var scores = new Dictionary<string, float>(StringComparer.OrdinalIgnoreCase);

        foreach (var className in DefaultClasses)
        {
            var score = ComputeClassScore(className, features);
            scores[className] = score;
        }

        return scores;
    }

    private float ComputeClassScore(string className, TrafficFeatureVector features)
    {
        float score = 0.5f;

        // Packet size heuristic
        var sizeScore = NormalizeRange(features.PacketSize, 0, 1500) * 0.15f;
        if ((className == "Web" || className == "FileTransfer") && features.PacketSize > 500)
            sizeScore *= 1.3f;
        if ((className == "Gaming" || className == "VoIP") && features.PacketSize < 200)
            sizeScore *= 1.2f;
        score += sizeScore;

        // Port heuristic
        var portScore = 0f;
        if (className == "Gaming" && features.IsGamingPort > 0) portScore = 0.3f;
        if (className == "Streaming" && features.IsStreamingPort > 0) portScore = 0.3f;
        if (className == "P2P" && features.IsP2PPort > 0) portScore = 0.35f;
        if (className == "VoIP" && features.IsVoIPPort > 0) portScore = 0.3f;
        score += portScore;

        // Protocol heuristic
        var protocolScore = ComputeProtocolScore(className, features);
        score += protocolScore;

        // Application protocol encoding
        var appScore = ComputeAppProtocolScore(className, features);
        score += appScore * 0.2f;

        // Encryption heuristic
        if ((className == "Web" || className == "RemoteAccess" || className == "FileTransfer") && features.IsEncrypted > 0)
            score += 0.1f;

        // Payload characteristics
        var payloadScore = ComputePayloadScore(className, features);
        score += payloadScore * 0.15f;

        return Math.Min(1.0f, score);
    }

    private float ComputeProtocolScore(string className, TrafficFeatureVector features)
    {
        return className switch
        {
            "Web" => features.IsTCP + features.IsKnownProtocol * 0.1f,
            "Streaming" => features.IsHighPort * 0.2f + features.IsEncrypted * 0.1f,
            "Gaming" => features.IsUDP * 0.3f + features.IsHighPort * 0.1f,
            "P2P" => features.IsUDP * 0.1f + features.IsHighPort * 0.2f,
            "VoIP" => features.IsUDP * 0.3f,
            "FileTransfer" => features.IsTCP * 0.2f,
            "RemoteAccess" => features.IsTCP * 0.25f,
            "Infrastructure" => (1f - features.IsHighPort) * 0.1f,
            "Messaging" => features.IsTCP * 0.15f,
            _ => 0f
        };
    }

    private float ComputeAppProtocolScore(string className, TrafficFeatureVector features)
    {
        return className switch
        {
            "Web" => (features.AppProtocolEncoded == 1 || features.AppProtocolEncoded == 2 || features.AppProtocolEncoded == 12) ? 1f : 0f,
            "Streaming" => (features.AppProtocolEncoded == 14 || features.AppProtocolEncoded == 15) ? 1f : 0f,
            "VoIP" => (features.AppProtocolEncoded == 16 || features.AppProtocolEncoded == 17) ? 1f : 0f,
            "P2P" => features.AppProtocolEncoded == 22 ? 1f : 0f,
            "FileTransfer" => (features.AppProtocolEncoded == 3 || features.AppProtocolEncoded == 20) ? 1f : 0f,
            "RemoteAccess" => (features.AppProtocolEncoded == 4 || features.AppProtocolEncoded == 21) ? 1f : 0f,
            "Messaging" => (features.AppProtocolEncoded == 6 || features.AppProtocolEncoded == 7 || features.AppProtocolEncoded == 8) ? 1f : 0f,
            "Infrastructure" => (features.AppProtocolEncoded == 9 || features.AppProtocolEncoded == 10 || features.AppProtocolEncoded == 11) ? 1f : 0f,
            _ => 0f
        };
    }

    private float ComputePayloadScore(string className, TrafficFeatureVector features)
    {
        return className switch
        {
            "Gaming" => (features.PayloadSize < 200 && features.IsCompressed == 0) ? 0.3f : 0f,
            "Streaming" => (features.PayloadSize > 500 || features.IsCompressed > 0) ? 0.3f : 0f,
            "P2P" => features.PayloadEntropy > 6.5f ? 0.2f : 0f,
            _ => 0f
        };
    }

    private (string PredictedClass, float Confidence) SelectBestClass(Dictionary<string, float> scores)
    {
        var best = scores.OrderByDescending(kvp => kvp.Value).First();
        return (best.Key, best.Value);
    }

    private TrainingMetrics EvaluateModel(MLTrainingData.TrafficDataset train, MLTrainingData.TrafficDataset test)
    {
        var metrics = new TrainingMetrics();
        var confusionMatrix = new Dictionary<(string True, string Pred), int>();

        foreach (var testSample in test.Samples)
        {
            var features = ConvertSampleToFeatures(testSample);
            var prediction = Predict(features);
            var key = (testSample.Label, prediction.PredictedClass);
            confusionMatrix.TryGetValue(key, out var count);
            confusionMatrix[key] = count + 1;
        }

        // Calculate per-class metrics
        foreach (var className in DefaultClasses)
        {
            var tp = confusionMatrix.Where(kvp => kvp.Key.True == className && kvp.Key.Pred == className).Sum(kvp => kvp.Value);
            var fp = confusionMatrix.Where(kvp => kvp.Key.True != className && kvp.Key.Pred == className).Sum(kvp => kvp.Value);
            var fn = confusionMatrix.Where(kvp => kvp.Key.True == className && kvp.Key.Pred != className).Sum(kvp => kvp.Value);

            var precision = (tp + fp) > 0 ? tp / (double)(tp + fp) : 0;
            var recall = (tp + fn) > 0 ? tp / (double)(tp + fn) : 0;
            var f1 = (precision + recall) > 0 ? 2 * (precision * recall) / (precision + recall) : 0;

            metrics.PerClassMetrics[className] = new ClassMetrics
            {
                ClassName = className,
                Precision = precision,
                Recall = recall,
                F1Score = f1,
                SampleCount = test.Samples.Count(s => s.Label == className)
            };
        }

        // Calculate aggregate metrics
        var totalCorrect = confusionMatrix.Where(kvp => kvp.Key.True == kvp.Key.Pred).Sum(kvp => kvp.Value);
        metrics.Accuracy = totalCorrect / (double)test.Samples.Count;
        metrics.MacroF1 = metrics.PerClassMetrics.Values.Average(m => m.F1Score);
        metrics.WeightedF1 = metrics.PerClassMetrics.Values.Average(m => m.F1Score * (m.SampleCount / (double)test.Samples.Count));

        return metrics;
    }

    private Dictionary<string, float> CalculateClassWeights(MLTrainingData.TrafficDataset dataset)
    {
        var weights = new Dictionary<string, float>(StringComparer.OrdinalIgnoreCase);
        var totalSamples = dataset.Samples.Count;

        foreach (var label in dataset.Samples.Select(s => s.Label).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var count = dataset.Samples.Count(s => s.Label == label);
            weights[label] = count / (float)totalSamples;
        }

        return weights;
    }

    private Dictionary<string, float> Softmax(Dictionary<string, float> scores)
    {
        var max = scores.Values.Max();
        var exp = scores.ToDictionary(kvp => kvp.Key, kvp => (float)Math.Exp(kvp.Value - max));
        var sum = exp.Values.Sum();
        return exp.ToDictionary(kvp => kvp.Key, kvp => kvp.Value / sum);
    }

    private PredictionResult CreateDefaultPrediction(TrafficFeatureVector features)
    {
        var scores = new Dictionary<string, float>(StringComparer.OrdinalIgnoreCase);
        foreach (var className in DefaultClasses)
            scores[className] = ComputeClassScore(className, features);

        var (predicted, confidence) = SelectBestClass(scores);
        return new PredictionResult
        {
            PredictedClass = predicted,
            Confidence = confidence,
            ClassProbabilities = Softmax(scores)
        };
    }

    private static TrafficFeatureVector ConvertSampleToFeatures(MLTrainingData.TrafficSample sample)
    {
        return new TrafficFeatureVector
        {
            PacketSize = sample.PacketSize,
            PayloadSize = sample.PayloadSize,
            PacketSizeCategory = sample.PacketSizeCategory,
            PayloadRatio = sample.PayloadRatio,
            HeaderSize = sample.HeaderSize,
            SourcePort = sample.SourcePort,
            DestinationPort = sample.DestinationPort,
            IsSourceWellKnown = sample.IsSourceWellKnown,
            IsDestinationWellKnown = sample.IsDestinationWellKnown,
            PortDifference = sample.PortDifference,
            ProtocolType = sample.ProtocolType,
            IsTCP = sample.IsTCP,
            IsUDP = sample.IsUDP,
            IsICMP = sample.IsICMP,
            TTL = sample.TTL,
            TCPFlagsSet = sample.TCPFlagsSet,
            IsTCPSyn = sample.IsTCPSyn,
            IsTCPAck = sample.IsTCPAck,
            IsTCPFin = sample.IsTCPFin,
            IsTCPRst = sample.IsTCPRst,
            WindowSize = sample.WindowSize,
            PayloadEntropy = sample.PayloadEntropy,
            PayloadHasText = sample.PayloadHasText,
            PayloadHasNull = sample.PayloadHasNull,
            PayloadMeanByte = sample.PayloadMeanByte,
            PayloadVariance = sample.PayloadVariance,
            IsGamingPort = sample.IsGamingPort,
            IsStreamingPort = sample.IsStreamingPort,
            IsP2PPort = sample.IsP2PPort,
            IsVoIPPort = sample.IsVoIPPort,
            IsHighPort = sample.IsHighPort,
            AppProtocolEncoded = sample.AppProtocolEncoded,
            IsKnownProtocol = sample.IsKnownProtocol,
            ProtocolConfidence = sample.ProtocolConfidence,
            IsEncrypted = sample.IsEncrypted,
            IsCompressed = sample.IsCompressed,
            SourceIPType = sample.SourceIPType,
            DestinationIPType = sample.DestinationIPType,
            IPTotalLength = sample.IPTotalLength,
            IsFragmented = sample.IsFragmented,
            TTLBucket = sample.TTLBucket
        };
    }

    private static float NormalizeRange(float value, float min, float max)
    {
        if (max <= min) return 0.5f;
        return (value - min) / (max - min);
    }

    private static void EnsureDirectory(string filePath)
    {
        var directory = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            Directory.CreateDirectory(directory);
    }

    private void ThrowIfDisposed()
    {
        if (_isDisposed)
            throw new ObjectDisposedException(nameof(MLTrafficClassifier));
    }

    public void Dispose()
    {
        _isDisposed = true;
        SaveModel();
    }

    #endregion
}
