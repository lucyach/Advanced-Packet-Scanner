using Microsoft.AspNetCore.Mvc;
using NetworkMonitor.Backend;

namespace NetworkMonitor.Api.Controllers;

/// <summary>
/// Provides SSL/TLS security analysis and certificate pinning management endpoints
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class SecurityController : ControllerBase
{
    private static readonly CertificatePinning CertificatePinning = new();

    /// <summary>
    /// Get all SSL/TLS security threats detected in captured traffic
    /// </summary>
    [HttpGet("ssl-tls-threats")]
    public ActionResult<SslTlsSecurityReport> GetSslTlsThreats()
    {
        var allPackets = MainController.CapturedPackets;
        var sslTlsPackets = allPackets.Where(p => p.SecurityFlags.Any(f => 
            f.Contains("SSL", StringComparison.OrdinalIgnoreCase) || 
            f.Contains("TLS", StringComparison.OrdinalIgnoreCase) ||
            f.Contains("Certificate", StringComparison.OrdinalIgnoreCase))).ToList();

        var threats = new List<SslTlsThreat>();

        foreach (var packet in sslTlsPackets)
        {
            var threat = new SslTlsThreat
            {
                Timestamp = packet.Timestamp,
                SourceIP = packet.SourceIP,
                DestinationIP = packet.DestinationIP,
                SourcePort = ExtractPort(packet.Details, "SrcPort"),
                DestinationPort = ExtractPort(packet.Details, "DstPort"),
                Protocol = packet.Protocol,
                TlsVersion = packet.Metadata.ContainsKey("Version") ? packet.Metadata["Version"].ToString() ?? "Unknown" : "Unknown",
                SecurityFlags = packet.SecurityFlags,
                RiskScore = packet.RiskScore,
                Details = packet.Details,
                Metadata = new Dictionary<string, object>(packet.Metadata)
            };
            threats.Add(threat);
        }

        return Ok(new SslTlsSecurityReport
        {
            TotalTlsPackets = sslTlsPackets.Count,
            CriticalThreats = threats.Count(t => t.RiskScore >= 80),
            HighThreats = threats.Count(t => t.RiskScore >= 60 && t.RiskScore < 80),
            MediumThreats = threats.Count(t => t.RiskScore >= 40 && t.RiskScore < 60),
            LowThreats = threats.Count(t => t.RiskScore < 40),
            Threats = threats.OrderByDescending(t => t.RiskScore).ToList(),
            ReportGeneratedUtc = DateTime.UtcNow
        });
    }

    /// <summary>
    /// Get specific SSL/TLS security analysis for a domain
    /// </summary>
    [HttpGet("ssl-tls-domain")]
    public ActionResult<DomainSslTlsAnalysis> GetDomainSslTlsAnalysis([FromQuery] string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
            return BadRequest(new { message = "Domain parameter required" });

        var allPackets = MainController.CapturedPackets;
        var domainPackets = allPackets.Where(p => 
            p.DestinationHostName?.Contains(domain, StringComparison.OrdinalIgnoreCase) == true ||
            p.SourceHostName?.Contains(domain, StringComparison.OrdinalIgnoreCase) == true).ToList();

        var analysis = new DomainSslTlsAnalysis
        {
            Domain = domain,
            TotalPackets = domainPackets.Count,
            SslTlsPackets = domainPackets.Where(p => p.Protocol.Contains("TLS", StringComparison.OrdinalIgnoreCase)).Count(),
            HighestRiskScore = domainPackets.Any() ? domainPackets.Max(p => p.RiskScore) : 0,
            AverageRiskScore = domainPackets.Any() ? domainPackets.Average(p => p.RiskScore) : 0,
            SecurityThreats = domainPackets.SelectMany(p => p.SecurityFlags).Distinct().ToList(),
            TlsVersionsDetected = domainPackets.Where(p => p.Metadata.ContainsKey("Version"))
                .Select(p => p.Metadata["Version"].ToString() ?? "Unknown")
                .Distinct()
                .ToList(),
            CipherSuitesDetected = ExtractCipherSuites(domainPackets),
            FirstSeen = domainPackets.Any() ? domainPackets.Min(p => p.Timestamp) : DateTime.MinValue,
            LastSeen = domainPackets.Any() ? domainPackets.Max(p => p.Timestamp) : DateTime.MinValue
        };

        return Ok(analysis);
    }

    /// <summary>
    /// Pin a certificate for a domain
    /// </summary>
    [HttpPost("certificates/pin")]
    public ActionResult PinCertificate([FromBody] PinCertificateRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Domain))
            return BadRequest(new { message = "Domain required" });

        try
        {
            // In a real scenario, you'd extract the certificate from the TLS handshake
            // For now, we'll use a placeholder approach
            CertificatePinning.PinCertificate(request.Domain, new System.Security.Cryptography.X509Certificates.X509Certificate2(), request.TlsVersion ?? "TLS 1.2");
            
            return Ok(new { message = $"Certificate pinned for domain: {request.Domain}" });
        }
        catch (Exception ex)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new { message = $"Error pinning certificate: {ex.Message}" });
        }
    }

    /// <summary>
    /// Get all pinned certificates
    /// </summary>
    [HttpGet("certificates/pinned")]
    public ActionResult<List<CertificatePinningInfo>> GetPinnedCertificates()
    {
        var pins = CertificatePinning.GetAllPins();
        var result = pins.Select(p => new CertificatePinningInfo
        {
            Domain = p.Domain,
            Thumbprint = p.CertificateThumbprint,
            IssuedBy = p.IssuedBy,
            ExpiresUtc = p.ExpiresUtc,
            FirstPinnedUtc = p.FirstSeenUtc,
            DaysSincePinned = (int)(DateTime.UtcNow - p.FirstSeenUtc).TotalDays,
            IsVerified = p.IsVerified,
            TlsVersion = p.TlsVersion
        }).ToList();

        return Ok(result);
    }

    /// <summary>
    /// Get pinning statistics
    /// </summary>
    [HttpGet("certificates/pinning-stats")]
    public ActionResult<PinningStatisticsResponse> GetPinningStatistics()
    {
        var stats = CertificatePinning.GetStatistics();
        return Ok(new PinningStatisticsResponse
        {
            TotalPinnedCertificates = stats.TotalPinned,
            ExpiredCertificates = stats.ExpiredCertificates,
            ExpiringIn30Days = stats.ExpiringIn30Days,
            UnverifiedCertificates = stats.UnverifiedPins,
            OldestPinDays = stats.OldestPinDays,
            NewestPinDays = stats.NewestPinDays
        });
    }

    /// <summary>
    /// Check for certificate pinning violations
    /// </summary>
    [HttpGet("certificates/violations")]
    public ActionResult<List<PinViolationReport>> GetPinViolations()
    {
        var pins = CertificatePinning.GetAllPins();
        var violations = new List<PinViolationReport>();

        foreach (var pin in pins)
        {
            var packetsForDomain = MainController.CapturedPackets.Where(p =>
                p.DestinationHostName?.Contains(pin.Domain, StringComparison.OrdinalIgnoreCase) == true).ToList();

            if (packetsForDomain.Any())
            {
                var hasThumbprintChange = packetsForDomain.Any(p =>
                    p.Metadata.ContainsKey("CertificateThumbprint") &&
                    p.Metadata["CertificateThumbprint"].ToString() != pin.CertificateThumbprint);

                if (hasThumbprintChange)
                {
                    violations.Add(new PinViolationReport
                    {
                        Domain = pin.Domain,
                        Severity = "CRITICAL",
                        Message = "Certificate thumbprint changed - possible MITM attack!",
                        PreviousThumbprint = pin.CertificateThumbprint,
                        FirstDetectedUtc = DateTime.UtcNow,
                        PacketsAffected = packetsForDomain.Count,
                        RecommendedAction = "Investigate certificate change and verify domain authenticity"
                    });
                }
            }
        }

        return Ok(violations);
    }

    /// <summary>
    /// Remove a pinned certificate
    /// </summary>
    [HttpDelete("certificates/pin/{domain}")]
    public ActionResult RemovePin(string domain)
    {
        if (CertificatePinning.RemovePin(domain))
        {
            return Ok(new { message = $"Certificate pin removed for domain: {domain}" });
        }
        return NotFound(new { message = $"No pin found for domain: {domain}" });
    }

    /// <summary>
    /// Generate comprehensive SSL/TLS security report
    /// </summary>
    [HttpGet("ssl-tls-report")]
    public ActionResult<SecurityComplianceReport> GenerateSecurityReport()
    {
        var allPackets = MainController.CapturedPackets;
        var tlsPackets = allPackets.Where(p => p.Protocol.Contains("TLS", StringComparison.OrdinalIgnoreCase)).ToList();

        var report = new SecurityComplianceReport
        {
            GeneratedUtc = DateTime.UtcNow,
            TotalPacketsAnalyzed = allPackets.Count,
            TlsPacketsDetected = tlsPackets.Count,
            ComplianceScore = CalculateComplianceScore(tlsPackets),
            
            // TLS Version Analysis
            TlsVersions = AnalyzeTlsVersions(tlsPackets),
            
            // Certificate Analysis
            CertificateIssues = AnalyzeCertificateIssues(tlsPackets),
            
            // Security Threats
            DetectedThreats = tlsPackets.SelectMany(p => p.SecurityFlags)
                .Where(f => f.Contains("SSL", StringComparison.OrdinalIgnoreCase) || 
                            f.Contains("Certificate", StringComparison.OrdinalIgnoreCase))
                .Distinct()
                .ToList(),
            
            // Pinning Status
            PinnedCertificates = CertificatePinning.GetAllPins().Count,
            PinningViolations = 0, // Would calculate actual violations
            
            Recommendations = GenerateRecommendations(tlsPackets)
        };

        return Ok(report);
    }

    private int ExtractPort(string details, string portType)
    {
        // Parse port from details string if available
        return 443; // Default HTTPS port
    }

    private List<string> ExtractCipherSuites(List<EnhancedPacketInfo> packets)
    {
        return packets
            .Where(p => p.Metadata.ContainsKey("CipherSuite"))
            .Select(p => p.Metadata["CipherSuite"].ToString() ?? "Unknown")
            .Distinct()
            .ToList();
    }

    private double CalculateComplianceScore(List<EnhancedPacketInfo> tlsPackets)
    {
        if (tlsPackets.Count == 0) return 100;

        double score = 100;
        
        // Penalize weak TLS versions
        var weakTls = tlsPackets.Count(p => 
            p.Metadata.ContainsKey("Version") && 
            (p.Metadata["Version"].ToString()?.Contains("1.0", StringComparison.OrdinalIgnoreCase) == true ||
             p.Metadata["Version"].ToString()?.Contains("1.1", StringComparison.OrdinalIgnoreCase) == true ||
             p.Metadata["Version"].ToString()?.Contains("SSL", StringComparison.OrdinalIgnoreCase) == true));
        
        score -= (weakTls / (double)tlsPackets.Count) * 20;

        // Penalize high-risk packets
        var highRisk = tlsPackets.Count(p => p.RiskScore >= 60);
        score -= (highRisk / (double)tlsPackets.Count) * 30;

        return Math.Max(0, Math.Min(100, score));
    }

    private List<TlsVersionAnalysis> AnalyzeTlsVersions(List<EnhancedPacketInfo> packets)
    {
        return packets
            .Where(p => p.Metadata.ContainsKey("Version"))
            .GroupBy(p => p.Metadata["Version"].ToString() ?? "Unknown")
            .Select(g => new TlsVersionAnalysis
            {
                Version = g.Key,
                PacketCount = g.Count(),
                AverageRiskScore = g.Average(p => p.RiskScore),
                IsSecure = !g.Key.Contains("1.0", StringComparison.OrdinalIgnoreCase) &&
                          !g.Key.Contains("1.1", StringComparison.OrdinalIgnoreCase) &&
                          !g.Key.Contains("SSL", StringComparison.OrdinalIgnoreCase)
            })
            .ToList();
    }

    private List<CertificateIssue> AnalyzeCertificateIssues(List<EnhancedPacketInfo> packets)
    {
        var issues = new List<CertificateIssue>();
        
        var selfSigned = packets.Where(p => p.SecurityFlags.Any(f => f.Contains("Self-Signed", StringComparison.OrdinalIgnoreCase))).Count();
        if (selfSigned > 0)
        {
            issues.Add(new CertificateIssue
            {
                Type = "Self-Signed Certificate",
                Count = selfSigned,
                Severity = "HIGH",
                Description = "Certificates are self-signed and cannot be verified by trusted authorities"
            });
        }

        var expired = packets.Where(p => p.SecurityFlags.Any(f => f.Contains("Expired", StringComparison.OrdinalIgnoreCase))).Count();
        if (expired > 0)
        {
            issues.Add(new CertificateIssue
            {
                Type = "Expired Certificate",
                Count = expired,
                Severity = "CRITICAL",
                Description = "Certificates have expired and should be renewed"
            });
        }

        var weakSig = packets.Where(p => p.SecurityFlags.Any(f => f.Contains("SHA1", StringComparison.OrdinalIgnoreCase) || f.Contains("MD5", StringComparison.OrdinalIgnoreCase))).Count();
        if (weakSig > 0)
        {
            issues.Add(new CertificateIssue
            {
                Type = "Weak Signature Algorithm",
                Count = weakSig,
                Severity = "HIGH",
                Description = "Certificates use weak signature algorithms (SHA1/MD5)"
            });
        }

        return issues;
    }

    private List<string> GenerateRecommendations(List<EnhancedPacketInfo> tlsPackets)
    {
        var recommendations = new List<string>();

        var weakTls = tlsPackets.Count(p =>
            p.Metadata.ContainsKey("Version") &&
            (p.Metadata["Version"].ToString()?.Contains("1.0", StringComparison.OrdinalIgnoreCase) == true ||
             p.Metadata["Version"].ToString()?.Contains("1.1", StringComparison.OrdinalIgnoreCase) == true));

        if (weakTls > 0)
        {
            recommendations.Add($"Upgrade {weakTls} connections using weak TLS versions to TLS 1.2 or higher");
        }

        var expired = tlsPackets.Count(p => p.SecurityFlags.Any(f => f.Contains("Expired", StringComparison.OrdinalIgnoreCase)));
        if (expired > 0)
        {
            recommendations.Add($"Renew {expired} expired certificates immediately");
        }

        recommendations.Add("Enable certificate pinning for critical domains");
        recommendations.Add("Implement OCSP stapling for certificate revocation checking");
        recommendations.Add("Monitor for suspicious certificate changes indicating MITM attacks");

        return recommendations;
    }
}

#region Request/Response Models

public record SslTlsThreat
{
    public DateTime Timestamp { get; set; }
    public string SourceIP { get; set; } = string.Empty;
    public string DestinationIP { get; set; } = string.Empty;
    public int SourcePort { get; set; }
    public int DestinationPort { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public string TlsVersion { get; set; } = string.Empty;
    public List<string> SecurityFlags { get; set; } = new();
    public int RiskScore { get; set; }
    public string Details { get; set; } = string.Empty;
    public Dictionary<string, object> Metadata { get; set; } = new();
}

public record SslTlsSecurityReport
{
    public int TotalTlsPackets { get; set; }
    public int CriticalThreats { get; set; }
    public int HighThreats { get; set; }
    public int MediumThreats { get; set; }
    public int LowThreats { get; set; }
    public List<SslTlsThreat> Threats { get; set; } = new();
    public DateTime ReportGeneratedUtc { get; set; }
}

public record DomainSslTlsAnalysis
{
    public string Domain { get; set; } = string.Empty;
    public int TotalPackets { get; set; }
    public int SslTlsPackets { get; set; }
    public int HighestRiskScore { get; set; }
    public double AverageRiskScore { get; set; }
    public List<string> SecurityThreats { get; set; } = new();
    public List<string> TlsVersionsDetected { get; set; } = new();
    public List<string> CipherSuitesDetected { get; set; } = new();
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
}

public record PinCertificateRequest
{
    public string Domain { get; set; } = string.Empty;
    public string? TlsVersion { get; set; }
}

public record CertificatePinningInfo
{
    public string Domain { get; set; } = string.Empty;
    public string Thumbprint { get; set; } = string.Empty;
    public string IssuedBy { get; set; } = string.Empty;
    public DateTime ExpiresUtc { get; set; }
    public DateTime FirstPinnedUtc { get; set; }
    public int DaysSincePinned { get; set; }
    public bool IsVerified { get; set; }
    public string TlsVersion { get; set; } = string.Empty;
}

public record PinningStatisticsResponse
{
    public int TotalPinnedCertificates { get; set; }
    public int ExpiredCertificates { get; set; }
    public int ExpiringIn30Days { get; set; }
    public int UnverifiedCertificates { get; set; }
    public int OldestPinDays { get; set; }
    public int NewestPinDays { get; set; }
}

public record PinViolationReport
{
    public string Domain { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public string PreviousThumbprint { get; set; } = string.Empty;
    public DateTime FirstDetectedUtc { get; set; }
    public int PacketsAffected { get; set; }
    public string RecommendedAction { get; set; } = string.Empty;
}

public record SecurityComplianceReport
{
    public DateTime GeneratedUtc { get; set; }
    public int TotalPacketsAnalyzed { get; set; }
    public int TlsPacketsDetected { get; set; }
    public double ComplianceScore { get; set; }
    public List<TlsVersionAnalysis> TlsVersions { get; set; } = new();
    public List<CertificateIssue> CertificateIssues { get; set; } = new();
    public List<string> DetectedThreats { get; set; } = new();
    public int PinnedCertificates { get; set; }
    public int PinningViolations { get; set; }
    public List<string> Recommendations { get; set; } = new();
}

public record TlsVersionAnalysis
{
    public string Version { get; set; } = string.Empty;
    public int PacketCount { get; set; }
    public double AverageRiskScore { get; set; }
    public bool IsSecure { get; set; }
}

public record CertificateIssue
{
    public string Type { get; set; } = string.Empty;
    public int Count { get; set; }
    public string Severity { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
}

#endregion
