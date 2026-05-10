using PacketDotNet;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Net;

namespace NetworkMonitor.Backend.ProtocolAnalyzers;

/// <summary>
/// Comprehensive SSL/TLS certificate analysis and validation engine.
/// Performs deep packet inspection, certificate chain validation, and security threat detection.
/// </summary>
public static class SslTlsAnalyzer
{
    private enum TlsRecordType : byte
    {
        ChangeCipherSpec = 20,
        Alert = 21,
        Handshake = 22,
        ApplicationData = 23
    }

    private enum TlsHandshakeType : byte
    {
        HelloRequest = 0,
        ClientHello = 1,
        ServerHello = 2,
        Certificate = 11,
        ServerKeyExchange = 12,
        CertificateRequest = 13,
        ServerHelloDone = 14,
        CertificateVerify = 15,
        ClientKeyExchange = 16,
        Finished = 20
    }

    private enum TlsExtensionType : ushort
    {
        ServerName = 0,
        SupportedGroups = 10,
        SignatureAlgorithms = 13,
        SupportedVersions = 43,
        PskKeyExchangeModes = 45,
        CertificateAuthorities = 47,
        OidFilters = 48,
        PostHandshakeAuth = 49,
        KeyShare = 51
    }

    // TLS/SSL Cipher Suite Database
    private static readonly Dictionary<ushort, CipherSuiteInfo> CipherSuites = BuildCipherSuiteDatabase();
    
    // Common certificate issuers database
    private static readonly HashSet<string> TrustedRootCAs = BuildTrustedCADatabase();
    
    // Certificate Transparency Log URLs (sample)
    private static readonly List<string> CTLogServers = new()
    {
        "https://ct.googleapis.com/logs/argon2023h/",
        "https://ct.googleapis.com/logs/argon2024h/",
        "https://ct.googleapis.com/logs/xenon2024/"
    };

    public static ProtocolAnalysisResult AnalyzeSslTls(TcpPacket tcp, ProtocolAnalysisResult result)
    {
        result.Protocol = "SSL/TLS";

        if (tcp.PayloadData == null || tcp.PayloadData.Length < 5)
        {
            result.Details = "SSL/TLS (insufficient data)";
            return result;
        }

        try
        {
            var payload = tcp.PayloadData;
            
            // Check if this looks like TLS
            if (payload[0] < 20 || payload[0] > 23)
            {
                result.Details = "Possible SSL/TLS (encrypted/unknown)";
                result.RiskScore += 5;
                return result;
            }

            var recordType = (TlsRecordType)payload[0];
            var majorVersion = payload[1];
            var minorVersion = payload[2];
            var length = (ushort)((payload[3] << 8) | payload[4]);

            result.Metadata["RecordType"] = recordType.ToString();
            result.Metadata["Version"] = $"{majorVersion}.{minorVersion}";
            result.Metadata["RecordLength"] = length;

            var versionString = GetTlsVersionString(majorVersion, minorVersion);
            result.Details = $"SSL/TLS {versionString} - {recordType}";

            // Analyze version security
            AnalyzeVersionSecurity(majorVersion, minorVersion, result);

            // If it's a handshake, try to analyze further
            if (recordType == TlsRecordType.Handshake && payload.Length > 9)
            {
                AnalyzeHandshake(payload, result);
            }
            else if (recordType == TlsRecordType.Alert && payload.Length > 7)
            {
                AnalyzeAlert(payload, result);
            }
            else if (recordType == TlsRecordType.ApplicationData)
            {
                result.Details += " (encrypted application data)";
            }
        }
        catch (Exception ex)
        {
            result.Details = $"SSL/TLS parsing error: {ex.Message}";
            result.RiskScore += 20;
        }

        return result;
    }

    private static void AnalyzeHandshake(byte[] payload, ProtocolAnalysisResult result)
    {
        if (payload.Length < 9) return;

        var handshakeType = (TlsHandshakeType)payload[5];
        var handshakeLength = (payload[6] << 16) | (payload[7] << 8) | payload[8];

        result.Metadata["HandshakeType"] = handshakeType.ToString();
        result.Metadata["HandshakeLength"] = handshakeLength;
        result.Details += $" - {handshakeType}";

        switch (handshakeType)
        {
            case TlsHandshakeType.ClientHello:
                AnalyzeClientHello(payload, result);
                break;
            case TlsHandshakeType.ServerHello:
                AnalyzeServerHello(payload, result);
                break;
            case TlsHandshakeType.Certificate:
                AnalyzeCertificate(payload, result);
                break;
        }
    }

    private static void AnalyzeClientHello(byte[] payload, ProtocolAnalysisResult result)
    {
        if (payload.Length < 43) return;

        try
        {
            // Skip to version (offset 9)
            var clientVersion = $"{payload[9]}.{payload[10]}";
            result.Metadata["ClientVersion"] = clientVersion;

            // Random (32 bytes) starts at offset 11
            var random = payload.Skip(11).Take(32).ToArray();
            result.Metadata["ClientRandom"] = Convert.ToHexString(random);

            // Session ID length at offset 43
            if (payload.Length > 43)
            {
                var sessionIdLength = payload[43];
                result.Metadata["SessionIdLength"] = sessionIdLength;

                // Try to extract cipher suites and extensions
                var offset = 44 + sessionIdLength;
                if (payload.Length > offset + 2)
                {
                    var cipherSuitesLength = (ushort)((payload[offset] << 8) | payload[offset + 1]);
                    result.Metadata["CipherSuitesCount"] = cipherSuitesLength / 2;
                    
                    // Analyze offered cipher suites
                    AnalyzeOfferedCipherSuites(payload, offset + 2, cipherSuitesLength, result);
                }

                // Parse TLS extensions
                try
                {
                    ParseTlsExtensions(payload, 44 + sessionIdLength + 2, result, isClientHello: true);
                }
                catch (Exception ex)
                {
                    result.SecurityFlags.Add($"Extensions parsing error: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            result.SecurityFlags.Add($"ClientHello parsing error: {ex.Message}");
        }
    }

    private static void AnalyzeServerHello(byte[] payload, ProtocolAnalysisResult result)
    {
        if (payload.Length < 43) return;

        try
        {
            var serverVersion = $"{payload[9]}.{payload[10]}";
            result.Metadata["ServerVersion"] = serverVersion;

            var random = payload.Skip(11).Take(32).ToArray();
            result.Metadata["ServerRandom"] = Convert.ToHexString(random);

            if (payload.Length > 43)
            {
                var sessionIdLength = payload[43];
                var offset = 44 + sessionIdLength;
                
                if (payload.Length > offset + 2)
                {
                    var selectedCipher = (ushort)((payload[offset] << 8) | payload[offset + 1]);
                    result.Metadata["SelectedCipher"] = $"0x{selectedCipher:X4}";
                    
                    // Analyze selected cipher
                    if (CipherSuites.TryGetValue(selectedCipher, out var cipherInfo))
                    {
                        result.Metadata["SelectedCipherName"] = cipherInfo.Name;
                        result.Metadata["CipherKeyExchange"] = cipherInfo.KeyExchange;
                        result.Metadata["CipherEncryption"] = cipherInfo.Encryption;
                        result.Metadata["CipherAuthentication"] = cipherInfo.Authentication;
                        result.Metadata["CipherStrength"] = cipherInfo.Strength;
                        
                        if (cipherInfo.IsWeak)
                        {
                            result.RiskScore += 30;
                            result.SecurityFlags.Add($"Weak cipher selected: {cipherInfo.Name}");
                        }
                    }
                    else if (IsWeakCipher(selectedCipher))
                    {
                        result.RiskScore += 30;
                        result.SecurityFlags.Add("Weak cipher selected");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            result.SecurityFlags.Add($"ServerHello parsing error: {ex.Message}");
        }
    }

    private static void AnalyzeCertificate(byte[] payload, ProtocolAnalysisResult result)
    {
        try
        {
            result.Details += " (Certificate chain)";
            
            if (payload.Length > 12)
            {
                var certChainLength = (payload[9] << 16) | (payload[10] << 8) | payload[11];
                result.Metadata["CertificateChainLength"] = certChainLength;
                
                // Try to extract and validate all certificates in the chain
                var certificateCount = 0;
                var offset = 15;
                
                while (offset < Math.Min(payload.Length, 15 + certChainLength) && certificateCount < 5)
                {
                    if (offset + 3 > payload.Length) break;
                    
                    var certLength = (payload[offset] << 16) | (payload[offset + 1] << 8) | payload[offset + 2];
                    offset += 3;
                    
                    if (offset + certLength > payload.Length) break;
                    
                    var certData = payload.Skip(offset).Take(certLength).ToArray();
                    
                    if (certificateCount == 0)
                    {
                        result.Metadata[$"ServerCertificateLength"] = certLength;
                        AnalyzeCertificateData(certData, result, certificateIndex: 0);
                    }
                    else
                    {
                        AnalyzeIntermediateCertificate(certData, result, certificateIndex: certificateCount);
                    }
                    
                    offset += certLength;
                    certificateCount++;
                }
                
                result.Metadata["CertificateChainDepth"] = certificateCount;
                ValidateCertificateChainStructure(certificateCount, result);
            }
        }
        catch (Exception ex)
        {
            result.SecurityFlags.Add($"Certificate analysis error: {ex.Message}");
            result.RiskScore += 10;
        }
    }

    private static void AnalyzeCertificateData(byte[] certData, ProtocolAnalysisResult result, int certificateIndex = 0)
    {
        try
        {
            var cert = new X509Certificate2(certData);
            var prefix = certificateIndex == 0 ? "" : $"Intermediate{certificateIndex}_";
            
            // Basic certificate information
            result.Metadata[$"{prefix}Subject"] = cert.Subject;
            result.Metadata[$"{prefix}Issuer"] = cert.Issuer;
            result.Metadata[$"{prefix}NotBefore"] = cert.NotBefore;
            result.Metadata[$"{prefix}NotAfter"] = cert.NotAfter;
            result.Metadata[$"{prefix}SerialNumber"] = cert.SerialNumber ?? "Unknown";
            result.Metadata[$"{prefix}Thumbprint"] = cert.Thumbprint ?? "Unknown";
            result.Metadata[$"{prefix}KeyAlgorithm"] = cert.PublicKey?.Oid?.FriendlyName ?? "Unknown";
            result.Metadata[$"{prefix}KeySize"] = cert.PublicKey?.Key?.KeySize ?? 0;
            result.Metadata[$"{prefix}SignatureAlgorithm"] = cert.SignatureAlgorithm?.FriendlyName ?? "Unknown";

            // Extract certificate extensions
            var dnsNames = ExtractDnsNames(cert);
            result.Metadata[$"{prefix}DnsNames"] = dnsNames;
            result.Metadata[$"{prefix}HasServerAuthenticationEku"] = HasServerAuthenticationEku(cert);
            result.Metadata[$"{prefix}IsCertificateAuthority"] = IsCertificateAuthority(cert);
            result.Metadata[$"{prefix}BasicConstraints"] = ExtractBasicConstraints(cert);

            // Extract and analyze extensions
            AnalyzeCertificateExtensions(cert, result, prefix);

            // Full certificate chain validation
            ValidateCertificateChain(cert, result, prefix);
            
            // Security checks - expiration
            if (cert.NotAfter < DateTime.Now)
            {
                result.RiskScore += 45;
                result.SecurityFlags.Add($"Expired certificate (expired: {cert.NotAfter:yyyy-MM-dd})");
            }
            else if (cert.NotAfter < DateTime.Now.AddDays(7))
            {
                result.RiskScore += 20;
                result.SecurityFlags.Add($"Certificate expires in less than 7 days ({cert.NotAfter:yyyy-MM-dd})");
            }
            else if (cert.NotAfter < DateTime.Now.AddDays(30))
            {
                result.RiskScore += 10;
                result.SecurityFlags.Add($"Certificate expires within 30 days ({cert.NotAfter:yyyy-MM-dd})");
            }

            // Check if certificate is not yet valid
            if (cert.NotBefore > DateTime.Now)
            {
                result.RiskScore += 35;
                result.SecurityFlags.Add($"Certificate not yet valid (valid from: {cert.NotBefore:yyyy-MM-dd})");
            }

            // Check for weak signature algorithms
            var signatureAlg = cert.SignatureAlgorithm?.FriendlyName?.ToLower() ?? "unknown";
            if (signatureAlg.Contains("sha1") || signatureAlg.Contains("md5") || signatureAlg.Contains("sha256rsa"))
            {
                result.RiskScore += 30;
                result.SecurityFlags.Add($"Weak signature algorithm: {signatureAlg}");
            }

            // Check key size and algorithm strength
            var keySize = cert.PublicKey?.Key?.KeySize ?? 0;
            if (keySize > 0 && keySize < 2048)
            {
                result.RiskScore += 30;
                result.SecurityFlags.Add($"Weak RSA key size: {keySize} bits (recommended: 2048+)");
            }
            else if (keySize > 0 && keySize < 256 && cert.PublicKey?.Oid?.FriendlyName?.Contains("ECDSA") == true)
            {
                result.RiskScore += 25;
                result.SecurityFlags.Add($"Weak ECDSA key size: {keySize} bits (recommended: 256+)");
            }

            // Self-signed certificate check
            if (cert.Subject == cert.Issuer && certificateIndex == 0)
            {
                result.RiskScore += 25;
                result.SecurityFlags.Add("Self-signed certificate detected");
            }

            // Public key pinning support (future enhancement tracking)
            result.Metadata[$"{prefix}PublicKeyHash"] = ComputePublicKeyHash(cert);

            // Certificate transparency support
            AnalyzeCertificateTransparency(cert, result, prefix);

            // OCSP stapling/revocation status (basic support)
            AnalyzeRevocationStatus(cert, result, prefix);

            result.Details += $" | Subject: {cert.GetNameInfo(X509NameType.SimpleName, false)}";
        }
        catch (Exception ex)
        {
            result.RiskScore += 20;
            result.SecurityFlags.Add($"Certificate analysis error: {ex.Message}");
        }
    }

    private static void AnalyzeIntermediateCertificate(byte[] certData, ProtocolAnalysisResult result, int certificateIndex)
    {
        try
        {
            AnalyzeCertificateData(certData, result, certificateIndex);
        }
        catch (Exception ex)
        {
            result.SecurityFlags.Add($"Intermediate certificate {certificateIndex} analysis error: {ex.Message}");
        }
    }

    private static void ValidateCertificateChainStructure(int chainDepth, ProtocolAnalysisResult result)
    {
        // Check for proper chain depth
        if (chainDepth > 10)
        {
            result.RiskScore += 10;
            result.SecurityFlags.Add("Unusually deep certificate chain (>10 certificates)");
        }
        
        if (chainDepth == 1)
        {
            var isSelfSigned = result.Metadata.TryGetValue("Intermediate1_Subject", out _) == false 
                && result.Metadata.TryGetValue("Subject", out var subject)
                && result.Metadata.TryGetValue("Issuer", out var issuer)
                && subject?.ToString() == issuer?.ToString();
            
            if (!isSelfSigned)
            {
                result.RiskScore += 5;
                result.SecurityFlags.Add("Single certificate without root CA in chain");
            }
        }
    }

    private static void AnalyzeCertificateExtensions(X509Certificate2 cert, ProtocolAnalysisResult result, string prefix)
    {
        try
        {
            var extensions = new List<string>();
            
            foreach (var ext in cert.Extensions)
            {
                extensions.Add($"{ext.Oid?.FriendlyName ?? ext.Oid?.Value} (Critical: {ext.Critical})");

                // Analyze specific critical extensions
                if (ext.Oid?.Value == "2.5.29.19") // Basic Constraints
                {
                    if (ext is X509BasicConstraintsExtension basic && basic.CertificateAuthority && basic.PathLengthConstraint >= 0)
                    {
                        result.Metadata[$"{prefix}PathLengthConstraint"] = basic.PathLengthConstraint;
                    }
                }
                else if (ext.Oid?.Value == "2.5.29.31") // CRL Distribution Points
                {
                    result.Metadata[$"{prefix}HasCrlDistributionPoint"] = true;
                }
                else if (ext.Oid?.Value == "1.3.6.1.5.5.7.1.1") // Authority Information Access (OCSP, CA Issuers)
                {
                    result.Metadata[$"{prefix}HasAuthorityInfoAccess"] = true;
                }
                else if (ext.Oid?.Value == "2.5.29.32") // Certificate Policies
                {
                    result.Metadata[$"{prefix}HasCertificatePolicies"] = true;
                }
            }
            
            result.Metadata[$"{prefix}Extensions"] = extensions;
        }
        catch (Exception ex)
        {
            result.SecurityFlags.Add($"Extension analysis error: {ex.Message}");
        }
    }

    private static void AnalyzeCertificateTransparency(X509Certificate2 cert, ProtocolAnalysisResult result, string prefix)
    {
        try
        {
            // Look for CT Precertificate SCT (Signed Certificate Timestamp) extension
            // OID: 1.3.6.1.4.1.11129.2.4.2
            bool hasCtExt = false;
            foreach (var ext in cert.Extensions)
            {
                if (ext.Oid?.Value == "1.3.6.1.4.1.11129.2.4.2")
                {
                    hasCtExt = true;
                    break;
                }
            }
            
            result.Metadata[$"{prefix}CertificateTransparencyLogged"] = hasCtExt;
            if (!hasCtExt && prefix == "")
            {
                result.SecurityFlags.Add("Certificate Transparency logs not detected (may indicate older cert)");
            }
        }
        catch (Exception ex)
        {
            result.SecurityFlags.Add($"CT analysis error: {ex.Message}");
        }
    }

    private static void AnalyzeRevocationStatus(X509Certificate2 cert, ProtocolAnalysisResult result, string prefix)
    {
        try
        {
            // Check for OCSP URL
            var hasOcsp = false;
            var hasCrl = false;
            
            foreach (var ext in cert.Extensions)
            {
                if (ext.Oid?.Value == "1.3.6.1.5.5.7.1.1") // AIA
                {
                    hasOcsp = true;
                }
                else if (ext.Oid?.Value == "2.5.29.31") // CRL Distribution Points
                {
                    hasCrl = true;
                }
            }
            
            result.Metadata[$"{prefix}SupportsOcsp"] = hasOcsp;
            result.Metadata[$"{prefix}SupportsCrl"] = hasCrl;
            
            if (!hasOcsp && !hasCrl && prefix == "")
            {
                result.RiskScore += 5;
                result.SecurityFlags.Add("No OCSP or CRL revocation information available");
            }
        }
        catch (Exception ex)
        {
            result.SecurityFlags.Add($"Revocation status analysis error: {ex.Message}");
        }
    }

    private static string ComputePublicKeyHash(X509Certificate2 cert)
    {
        try
        {
            using var sha256 = SHA256.Create();
            var keyBytes = cert.PublicKey.EncodedKeyValue.RawData;
            var hash = sha256.ComputeHash(keyBytes);
            return Convert.ToBase64String(hash);
        }
        catch
        {
            return "Unknown";
        }
    }

    private static string ExtractBasicConstraints(X509Certificate2 cert)
    {
        try
        {
            foreach (var ext in cert.Extensions)
            {
                if (ext is X509BasicConstraintsExtension basic)
                {
                    var ca = basic.CertificateAuthority ? "CA" : "End-Entity";
                    var pathLen = basic.PathLengthConstraint >= 0 ? $", PathLen={basic.PathLengthConstraint}" : "";
                    return $"{ca}{pathLen}";
                }
            }
        }
        catch { }
        return "Not Found";
    }

    private static void ParseTlsExtensions(byte[] payload, int startOffset, ProtocolAnalysisResult result, bool isClientHello)
    {
        try
        {
            if (startOffset + 2 > payload.Length) return;

            // For ClientHello, extensions list starts after compression methods
            // For ServerHello, extensions start right after ciphers
            var extensionsLength = (ushort)((payload[startOffset] << 8) | payload[startOffset + 1]);
            var offset = startOffset + 2;
            var extensionsEnd = offset + extensionsLength;

            var supportedExtensions = new List<string>();

            while (offset < extensionsEnd && offset < payload.Length)
            {
                if (offset + 4 > payload.Length) break;

                var extType = (TlsExtensionType)((payload[offset] << 8) | payload[offset + 1]);
                var extLength = (ushort)((payload[offset + 2] << 8) | payload[offset + 3]);
                offset += 4;

                if (offset + extLength > payload.Length) break;

                var extData = payload.Skip(offset).Take(extLength).ToArray();

                switch (extType)
                {
                    case TlsExtensionType.ServerName:
                        ParseServerNameIndication(extData, result);
                        supportedExtensions.Add("SNI");
                        break;
                    case TlsExtensionType.SupportedGroups:
                        ParseSupportedGroups(extData, result);
                        supportedExtensions.Add("SupportedGroups");
                        break;
                    case TlsExtensionType.SignatureAlgorithms:
                        ParseSignatureAlgorithms(extData, result);
                        supportedExtensions.Add("SignatureAlgorithms");
                        break;
                    case TlsExtensionType.SupportedVersions:
                        ParseSupportedVersions(extData, result);
                        supportedExtensions.Add("SupportedVersions");
                        break;
                    case TlsExtensionType.KeyShare:
                        supportedExtensions.Add("KeyShare (TLS 1.3)");
                        break;
                    case TlsExtensionType.PskKeyExchangeModes:
                        supportedExtensions.Add("PSKKeyExchange (TLS 1.3)");
                        break;
                }

                offset += extLength;
            }

            if (supportedExtensions.Count > 0)
            {
                result.Metadata["TlsExtensions"] = supportedExtensions;
            }
        }
        catch (Exception ex)
        {
            result.SecurityFlags.Add($"TLS extensions parsing error: {ex.Message}");
        }
    }

    private static void ParseServerNameIndication(byte[] extData, ProtocolAnalysisResult result)
    {
        try
        {
            if (extData.Length < 5) return;

            var serverNameListLength = (ushort)((extData[0] << 8) | extData[1]);
            var offset = 2;

            if (offset + 3 > extData.Length) return;

            var nameType = extData[offset]; // 0 = host_name
            var nameLength = (ushort)((extData[offset + 1] << 8) | extData[offset + 2]);
            offset += 3;

            if (offset + nameLength <= extData.Length)
            {
                var hostname = Encoding.ASCII.GetString(extData.Skip(offset).Take(nameLength).ToArray());
                result.Metadata["ServerNameIndication"] = hostname;
                result.Metadata["RequestedHostname"] = hostname;
            }
        }
        catch (Exception ex)
        {
            result.SecurityFlags.Add($"SNI parsing error: {ex.Message}");
        }
    }

    private static void ParseSupportedGroups(byte[] extData, ProtocolAnalysisResult result)
    {
        try
        {
            if (extData.Length < 2) return;

            var groupsLength = (ushort)((extData[0] << 8) | extData[1]);
            var groups = new List<string>();
            
            for (int i = 2; i < Math.Min(extData.Length, 2 + groupsLength); i += 2)
            {
                if (i + 1 >= extData.Length) break;
                var groupId = (ushort)((extData[i] << 8) | extData[i + 1]);
                groups.Add(GetEllipticCurveName(groupId));
            }

            result.Metadata["SupportedEllipticCurves"] = groups;
        }
        catch (Exception ex)
        {
            result.SecurityFlags.Add($"SupportedGroups parsing error: {ex.Message}");
        }
    }

    private static void ParseSignatureAlgorithms(byte[] extData, ProtocolAnalysisResult result)
    {
        try
        {
            if (extData.Length < 2) return;

            var algsLength = (ushort)((extData[0] << 8) | extData[1]);
            var algs = new List<string>();
            
            for (int i = 2; i < Math.Min(extData.Length, 2 + algsLength); i += 2)
            {
                if (i + 1 >= extData.Length) break;
                var algId = (ushort)((extData[i] << 8) | extData[i + 1]);
                algs.Add(GetSignatureAlgorithmName(algId));
            }

            result.Metadata["SupportedSignatureAlgorithms"] = algs;
        }
        catch (Exception ex)
        {
            result.SecurityFlags.Add($"SignatureAlgorithms parsing error: {ex.Message}");
        }
    }

    private static void ParseSupportedVersions(byte[] extData, ProtocolAnalysisResult result)
    {
        try
        {
            if (extData.Length < 2) return;

            var versionsLength = extData[0];
            var versions = new List<string>();
            
            for (int i = 1; i < Math.Min(extData.Length, 1 + versionsLength); i += 2)
            {
                if (i + 1 >= extData.Length) break;
                versions.Add(GetTlsVersionString(extData[i], extData[i + 1]));
            }

            result.Metadata["SupportedTlsVersions"] = versions;
        }
        catch (Exception ex)
        {
            result.SecurityFlags.Add($"SupportedVersions parsing error: {ex.Message}");
        }
    }

    private static void AnalyzeOfferedCipherSuites(byte[] payload, int offset, ushort length, ProtocolAnalysisResult result)
    {
        try
        {
            var offeredCiphers = new List<string>();
            var weakCount = 0;
            
            for (int i = offset; i < offset + length && i + 1 < payload.Length; i += 2)
            {
                var cipher = (ushort)((payload[i] << 8) | payload[i + 1]);
                
                if (CipherSuites.TryGetValue(cipher, out var cipherInfo))
                {
                    offeredCiphers.Add(cipherInfo.Name);
                    if (cipherInfo.IsWeak) weakCount++;
                }
                else if (IsWeakCipher(cipher))
                {
                    weakCount++;
                    offeredCiphers.Add($"0x{cipher:X4} (unknown)");
                }
            }

            result.Metadata["OfferedCipherSuites"] = offeredCiphers;
            
            if (weakCount > 0)
            {
                result.RiskScore += Math.Min(25, weakCount * 5);
                result.SecurityFlags.Add($"Weak cipher suites offered ({weakCount} weak suites)");
            }
        }
        catch (Exception ex)
        {
            result.SecurityFlags.Add($"Cipher suite analysis error: {ex.Message}");
        }
    }

    private static void ValidateCertificateChain(X509Certificate2 cert, ProtocolAnalysisResult result, string prefix)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.VerificationTime = DateTime.UtcNow;

        var valid = chain.Build(cert);
        result.Metadata[$"{prefix}CertificateChainValid"] = valid;

        if (!valid)
        {
            var issues = chain.ChainStatus
                .Select(s => s.StatusInformation?.Trim())
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Distinct()
                .ToList();

            result.Metadata[$"{prefix}CertificateChainIssues"] = issues;
            result.RiskScore += 25;
            result.SecurityFlags.Add($"Certificate chain validation failed: {string.Join("; ", issues)}");
        }
    }

    private static List<string> ExtractDnsNames(X509Certificate2 cert)
    {
        var dnsNames = new List<string>();
        foreach (var extension in cert.Extensions)
        {
            if (extension.Oid?.Value != "2.5.29.17")
                continue;

            var formatted = extension.Format(true);
            var lines = formatted.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var line in lines)
            {
                const string marker = "DNS Name=";
                var index = line.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
                if (index >= 0)
                {
                    dnsNames.Add(line[(index + marker.Length)..].Trim());
                }
            }
        }

        return dnsNames.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static bool HasServerAuthenticationEku(X509Certificate2 cert)
    {
        foreach (var extension in cert.Extensions)
        {
            if (extension is not X509EnhancedKeyUsageExtension eku)
                continue;

            foreach (var oid in eku.EnhancedKeyUsages)
            {
                if (oid.Value == "1.3.6.1.5.5.7.3.1")
                    return true;
            }
        }

        return false;
    }

    private static bool IsCertificateAuthority(X509Certificate2 cert)
    {
        foreach (var extension in cert.Extensions)
        {
            if (extension is X509BasicConstraintsExtension basic)
                return basic.CertificateAuthority;
        }

        return false;
    }

    private static void AnalyzeAlert(byte[] payload, ProtocolAnalysisResult result)
    {
        if (payload.Length < 7) return;

        var alertLevel = payload[5];
        var alertDescription = payload[6];

        result.Metadata["AlertLevel"] = alertLevel;
        result.Metadata["AlertDescription"] = alertDescription;

        var levelString = alertLevel == 1 ? "Warning" : "Fatal";
        result.Details += $" - {levelString} Alert ({alertDescription})";

        if (alertLevel == 2) // Fatal alert
        {
            result.RiskScore += 20;
            result.SecurityFlags.Add("TLS Fatal Alert");
        }
    }

    private static string GetTlsVersionString(byte major, byte minor)
    {
        return (major, minor) switch
        {
            (3, 0) => "SSL 3.0",
            (3, 1) => "TLS 1.0",
            (3, 2) => "TLS 1.1",
            (3, 3) => "TLS 1.2",
            (3, 4) => "TLS 1.3",
            _ => $"Unknown ({major}.{minor})"
        };
    }

    private static void AnalyzeVersionSecurity(byte major, byte minor, ProtocolAnalysisResult result)
    {
        switch ((major, minor))
        {
            case (3, 0): // SSL 3.0
                result.RiskScore += 50;
                result.SecurityFlags.Add("Deprecated SSL 3.0");
                break;
            case (3, 1): // TLS 1.0
                result.RiskScore += 30;
                result.SecurityFlags.Add("Deprecated TLS 1.0");
                break;
            case (3, 2): // TLS 1.1
                result.RiskScore += 20;
                result.SecurityFlags.Add("Deprecated TLS 1.1");
                break;
            case (3, 3): // TLS 1.2
                result.RiskScore += 0; // Acceptable
                break;
            case (3, 4): // TLS 1.3
                result.RiskScore -= 5; // Good security
                break;
            default:
                result.RiskScore += 15;
                result.SecurityFlags.Add("Unknown TLS version");
                break;
        }
    }

    private static bool HasWeakCiphers(byte[] payload, int offset, int length)
    {
        // This is a simplified check - in practice, you'd check against known weak cipher IDs
        var weakCiphers = new ushort[] { 0x0004, 0x0005, 0x000A, 0x0016, 0x0013, 0x0027 };
        
        for (int i = offset; i < offset + length - 1; i += 2)
        {
            var cipher = (ushort)((payload[i] << 8) | payload[i + 1]);
            if (weakCiphers.Contains(cipher))
                return true;
        }
        return false;
    }

    private static bool IsWeakCipher(ushort cipher)
    {
        // Known weak cipher suites (simplified list)
        var weakCiphers = new ushort[] { 0x0004, 0x0005, 0x000A, 0x0016, 0x0013, 0x0027 };
        return weakCiphers.Contains(cipher);
    }

    private static string GetEllipticCurveName(ushort groupId)
    {
        return groupId switch
        {
            0x0001 => "sect163k1",
            0x0002 => "sect163r1",
            0x0003 => "sect233k1",
            0x0004 => "sect233r1",
            0x0005 => "sect283k1",
            0x0006 => "sect283r1",
            0x0007 => "sect409k1",
            0x0008 => "sect409r1",
            0x0009 => "sect571k1",
            0x000A => "sect571r1",
            0x000B => "secp160r1",
            0x000C => "secp160r2",
            0x000D => "secp192r1",
            0x000E => "secp224r1",
            0x000F => "secp256r1",
            0x0010 => "secp384r1",
            0x0011 => "secp521r1",
            0x0017 => "secp256r1",
            0x0018 => "secp384r1",
            0x0019 => "secp521r1",
            0x001D => "x25519",
            0x001E => "x448",
            _ => $"Unknown (0x{groupId:X4})"
        };
    }

    private static string GetSignatureAlgorithmName(ushort algId)
    {
        // IANA TLS SignatureAlgorithm registry
        return algId switch
        {
            0x0201 => "rsa_pkcs1_sha1",
            0x0301 => "rsa_pss_rsae_sha256",
            0x0302 => "rsa_pss_rsae_sha384",
            0x0303 => "rsa_pss_rsae_sha512",
            0x0401 => "ecdsa_secp256r1_sha256",
            0x0501 => "rsa_pkcs1_sha256",
            0x0601 => "rsa_pkcs1_sha384",
            0x0701 => "rsa_pkcs1_sha512",
            0x0804 => "rsa_pss_rsae_sha256",
            0x0805 => "rsa_pss_rsae_sha384",
            0x0806 => "rsa_pss_rsae_sha512",
            0x0809 => "ecdsa_secp384r1_sha384",
            0x080A => "ecdsa_secp521r1_sha512",
            0x0810 => "rsa_pss_pss_sha256",
            0x0811 => "rsa_pss_pss_sha384",
            0x0812 => "rsa_pss_pss_sha512",
            0x0813 => "ecdsa_brainpoolP256r1_sha256",
            0x0814 => "ecdsa_brainpoolP384r1_sha384",
            0x0815 => "ecdsa_brainpoolP512r1_sha512",
            _ => $"Unknown (0x{algId:X4})"
        };
    }

    private static Dictionary<ushort, CipherSuiteInfo> BuildCipherSuiteDatabase()
    {
        return new Dictionary<ushort, CipherSuiteInfo>
        {
            // TLS 1.3 - Strong ciphers
            { 0x1301, new CipherSuiteInfo("TLS_AES_128_GCM_SHA256", "ECDHE", "AES-128-GCM", "AEAD", "Strong", false) },
            { 0x1302, new CipherSuiteInfo("TLS_AES_256_GCM_SHA384", "ECDHE", "AES-256-GCM", "AEAD", "Strong", false) },
            { 0x1303, new CipherSuiteInfo("TLS_CHACHA20_POLY1305_SHA256", "ECDHE", "ChaCha20-Poly1305", "AEAD", "Strong", false) },

            // TLS 1.2 - Strong ciphers
            { 0x002F, new CipherSuiteInfo("TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", "AES-128-CBC", "HMAC-SHA1", "Medium", false) },
            { 0x0035, new CipherSuiteInfo("TLS_RSA_WITH_AES_256_CBC_SHA", "RSA", "AES-256-CBC", "HMAC-SHA1", "Medium", false) },
            { 0x003C, new CipherSuiteInfo("TLS_RSA_WITH_AES_128_CBC_SHA256", "RSA", "AES-128-CBC", "HMAC-SHA256", "Medium", false) },
            { 0x003D, new CipherSuiteInfo("TLS_RSA_WITH_AES_256_CBC_SHA256", "RSA", "AES-256-CBC", "HMAC-SHA256", "Medium", false) },
            
            // ECDHE with AES-GCM - Strong
            { 0xC02B, new CipherSuiteInfo("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE", "AES-128-GCM", "AEAD", "Strong", false) },
            { 0xC02C, new CipherSuiteInfo("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE", "AES-256-GCM", "AEAD", "Strong", false) },
            { 0xC02F, new CipherSuiteInfo("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", "AES-128-GCM", "AEAD", "Strong", false) },
            { 0xC030, new CipherSuiteInfo("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", "AES-256-GCM", "AEAD", "Strong", false) },

            // ChaCha20-Poly1305 - Strong
            { 0xCCAA, new CipherSuiteInfo("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", "ChaCha20-Poly1305", "AEAD", "Strong", false) },
            { 0xCCAB, new CipherSuiteInfo("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", "ChaCha20-Poly1305", "AEAD", "Strong", false) },

            // Weak ciphers
            { 0x0001, new CipherSuiteInfo("TLS_NULL_WITH_NULL_NULL", "NULL", "NULL", "NULL", "Weak", true) },
            { 0x0004, new CipherSuiteInfo("TLS_RSA_WITH_RC4_128_MD5", "RSA", "RC4-128", "HMAC-MD5", "Weak", true) },
            { 0x0005, new CipherSuiteInfo("TLS_RSA_WITH_RC4_128_SHA", "RSA", "RC4-128", "HMAC-SHA1", "Weak", true) },
            { 0x000A, new CipherSuiteInfo("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", "3DES", "HMAC-SHA1", "Weak", true) },
            { 0x0013, new CipherSuiteInfo("TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", "DHE", "3DES", "HMAC-SHA1", "Weak", true) },
            { 0x0016, new CipherSuiteInfo("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "DHE", "3DES", "HMAC-SHA1", "Weak", true) },
            { 0x0027, new CipherSuiteInfo("TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", "AES-128-CBC", "HMAC-SHA1", "Weak", true) },
            { 0x002F, new CipherSuiteInfo("TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", "AES-128-CBC", "HMAC-SHA1", "Medium", false) },
        };
    }

    private static HashSet<string> BuildTrustedCADatabase()
    {
        return new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "DigiCert", "Let's Encrypt", "Sectigo", "GoDaddy", "GlobalSign",
            "Comodo", "Thawte", "VeriSign", "StartCom", "Google Trust Services"
        };
    }
}

/// <summary>
/// Represents information about a TLS cipher suite
/// </summary>
public class CipherSuiteInfo
{
    public string Name { get; set; }
    public string KeyExchange { get; set; }
    public string Encryption { get; set; }
    public string Authentication { get; set; }
    public string Strength { get; set; }
    public bool IsWeak { get; set; }

    public CipherSuiteInfo(string name, string keyExchange, string encryption, string authentication, string strength, bool isWeak)
    {
        Name = name;
        KeyExchange = keyExchange;
        Encryption = encryption;
        Authentication = authentication;
        Strength = strength;
        IsWeak = isWeak;
    }
}