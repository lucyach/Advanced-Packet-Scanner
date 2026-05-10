using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text;

namespace NetworkMonitor.Backend;

/// <summary>
/// Certificate pinning mechanism to detect man-in-the-middle (MITM) attacks.
/// Pins certificates and public keys for domains and alerts when they change.
/// </summary>
public class CertificatePinning
{
    private static readonly string PinStorePath = Path.Combine(AppContext.BaseDirectory, "pinned_certificates.json");
    private readonly Dictionary<string, CertificatePin> _pinnedCertificates = new();
    private readonly object _lock = new object();

    /// <summary>
    /// Represents a pinned certificate/public key for a domain
    /// </summary>
    public record CertificatePin(
        string Domain,
        string SubjectHash,
        string PublicKeyHash,
        string CertificateThumbprint,
        DateTime FirstSeenUtc,
        DateTime LastUpdatedUtc,
        string IssuedBy,
        DateTime ExpiresUtc,
        string TlsVersion,
        bool IsVerified);

    /// <summary>
    /// Result of pinning verification
    /// </summary>
    public record PinVerificationResult(
        bool IsValid,
        bool IsPinned,
        bool IsNewPin,
        bool ChangedSubject,
        bool ChangedPublicKey,
        bool ChangedThumbprint,
        string? PreviousThumbprint,
        int DaysSincePinned,
        string Message);

    public CertificatePinning()
    {
        LoadPins();
    }

    /// <summary>
    /// Add or update a certificate pin for a domain
    /// </summary>
    public void PinCertificate(string domain, X509Certificate2 certificate, string tlsVersion)
    {
        lock (_lock)
        {
            var pin = CreatePin(domain, certificate, tlsVersion, isNewPin: !_pinnedCertificates.ContainsKey(domain.ToLowerInvariant()));
            _pinnedCertificates[domain.ToLowerInvariant()] = pin;
            SavePins();
        }
    }

    /// <summary>
    /// Verify a certificate against pinned values
    /// </summary>
    public PinVerificationResult VerifyPin(string domain, X509Certificate2 certificate, string tlsVersion)
    {
        domain = domain.ToLowerInvariant();

        lock (_lock)
        {
            if (!_pinnedCertificates.TryGetValue(domain, out var pinnedPin))
            {
                // No pin exists, create one
                PinCertificate(domain, certificate, tlsVersion);
                return new PinVerificationResult(
                    IsValid: true,
                    IsPinned: false,
                    IsNewPin: true,
                    ChangedSubject: false,
                    ChangedPublicKey: false,
                    ChangedThumbprint: false,
                    PreviousThumbprint: null,
                    DaysSincePinned: 0,
                    Message: $"New certificate pinned for {domain}"
                );
            }

            // Compare certificate details
            var currentSubjectHash = GetCertificateSubjectHash(certificate);
            var currentPublicKeyHash = GetPublicKeyHash(certificate);
            var currentThumbprint = certificate.Thumbprint;

            var subjectChanged = currentSubjectHash != pinnedPin.SubjectHash;
            var publicKeyChanged = currentPublicKeyHash != pinnedPin.PublicKeyHash;
            var thumbprintChanged = currentThumbprint != pinnedPin.CertificateThumbprint;

            bool isValid = !subjectChanged && !publicKeyChanged && !thumbprintChanged;
            int daysSincePinned = (int)(DateTime.UtcNow - pinnedPin.FirstSeenUtc).TotalDays;

            string message;
            if (isValid)
            {
                message = $"Certificate verified for {domain} (pinned {daysSincePinned} days ago)";
            }
            else
            {
                var issues = new List<string>();
                if (subjectChanged) issues.Add("Subject changed");
                if (publicKeyChanged) issues.Add("Public key changed");
                if (thumbprintChanged) issues.Add("Thumbprint changed");

                message = $"PINNING VIOLATION detected for {domain}: {string.Join(", ", issues)} - possible MITM attack!";
            }

            return new PinVerificationResult(
                IsValid: isValid,
                IsPinned: true,
                IsNewPin: false,
                ChangedSubject: subjectChanged,
                ChangedPublicKey: publicKeyChanged,
                ChangedThumbprint: thumbprintChanged,
                PreviousThumbprint: pinnedPin.CertificateThumbprint,
                DaysSincePinned: daysSincePinned,
                Message: message
            );
        }
    }

    /// <summary>
    /// Get all pinned certificates
    /// </summary>
    public List<CertificatePin> GetAllPins()
    {
        lock (_lock)
        {
            return _pinnedCertificates.Values.ToList();
        }
    }

    /// <summary>
    /// Get pinned certificate for a specific domain
    /// </summary>
    public CertificatePin? GetPin(string domain)
    {
        lock (_lock)
        {
            _pinnedCertificates.TryGetValue(domain.ToLowerInvariant(), out var pin);
            return pin;
        }
    }

    /// <summary>
    /// Remove a pinned certificate
    /// </summary>
    public bool RemovePin(string domain)
    {
        lock (_lock)
        {
            bool removed = _pinnedCertificates.Remove(domain.ToLowerInvariant());
            if (removed)
                SavePins();
            return removed;
        }
    }

    /// <summary>
    /// Clear all pinned certificates
    /// </summary>
    public void ClearAllPins()
    {
        lock (_lock)
        {
            _pinnedCertificates.Clear();
            SavePins();
        }
    }

    /// <summary>
    /// Get statistics about pinned certificates
    /// </summary>
    public PinStatistics GetStatistics()
    {
        lock (_lock)
        {
            var pins = _pinnedCertificates.Values.ToList();
            
            if (pins.Count == 0)
                return new PinStatistics(0, 0, 0, 0, 0, 0);

            var now = DateTime.UtcNow;
            var expiredCount = pins.Count(p => p.ExpiresUtc < now);
            var expiringCount = pins.Count(p => p.ExpiresUtc < now.AddDays(30) && p.ExpiresUtc >= now);
            var unverifiedCount = pins.Count(p => !p.IsVerified);
            var oldestDays = (int)(now - pins.Min(p => p.FirstSeenUtc)).TotalDays;
            var newestDays = (int)(now - pins.Max(p => p.FirstSeenUtc)).TotalDays;

            return new PinStatistics(
                TotalPinned: pins.Count,
                ExpiredCertificates: expiredCount,
                ExpiringIn30Days: expiringCount,
                UnverifiedPins: unverifiedCount,
                OldestPinDays: oldestDays,
                NewestPinDays: newestDays
            );
        }
    }

    private CertificatePin CreatePin(string domain, X509Certificate2 certificate, string tlsVersion, bool isNewPin)
    {
        return new CertificatePin(
            Domain: domain,
            SubjectHash: GetCertificateSubjectHash(certificate),
            PublicKeyHash: GetPublicKeyHash(certificate),
            CertificateThumbprint: certificate.Thumbprint ?? string.Empty,
            FirstSeenUtc: DateTime.UtcNow,
            LastUpdatedUtc: DateTime.UtcNow,
            IssuedBy: certificate.Issuer,
            ExpiresUtc: certificate.NotAfter.ToUniversalTime(),
            TlsVersion: tlsVersion,
            IsVerified: VerifyCertificateChain(certificate)
        );
    }

    private string GetCertificateSubjectHash(X509Certificate2 cert)
    {
        try
        {
            var subjectBytes = Encoding.UTF8.GetBytes(cert.Subject);
            using (var sha256 = SHA256.Create())
            {
                var hash = sha256.ComputeHash(subjectBytes);
                return Convert.ToHexString(hash);
            }
        }
        catch
        {
            return string.Empty;
        }
    }

    private string GetPublicKeyHash(X509Certificate2 certificate)
    {
        try
        {
            var publicKeyBytes = certificate.PublicKey.EncodedKeyValue.RawData;
            using (var sha256 = SHA256.Create())
            {
                var hash = sha256.ComputeHash(publicKeyBytes);
                return Convert.ToHexString(hash);
            }
        }
        catch
        {
            return string.Empty;
        }
    }

    private bool VerifyCertificateChain(X509Certificate2 certificate)
    {
        try
        {
            var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid |
                                                   X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown |
                                                   X509VerificationFlags.IgnoreRootRevocationUnknown;
            return chain.Build(certificate);
        }
        catch
        {
            return false;
        }
    }

    private void SavePins()
    {
        try
        {
            var pinsToSave = _pinnedCertificates.Values.ToList();
            var json = JsonSerializer.Serialize(pinsToSave, new JsonSerializerOptions { WriteIndented = true });
            
            var directory = Path.GetDirectoryName(PinStorePath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(PinStorePath, json);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error saving pins: {ex.Message}");
        }
    }

    private void LoadPins()
    {
        try
        {
            if (!File.Exists(PinStorePath))
                return;

            var json = File.ReadAllText(PinStorePath);
            var pins = JsonSerializer.Deserialize<List<CertificatePin>>(json) ?? new();
            
            foreach (var pin in pins)
            {
                _pinnedCertificates[pin.Domain.ToLowerInvariant()] = pin;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error loading pins: {ex.Message}");
        }
    }
}

public record PinStatistics(
    int TotalPinned,
    int ExpiredCertificates,
    int ExpiringIn30Days,
    int UnverifiedPins,
    int OldestPinDays,
    int NewestPinDays);
