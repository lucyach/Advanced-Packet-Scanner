using PacketDotNet;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NetworkMonitor.Backend.ProtocolAnalyzers;

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
                result.RiskScore += 5; // Unknown encryption is slightly risky
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
        if (payload.Length < 43) return; // Minimum ClientHello size

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
                    
                    // Check for weak cipher suites
                    if (HasWeakCiphers(payload, offset + 2, cipherSuitesLength))
                    {
                        result.RiskScore += 25;
                        result.SecurityFlags.Add("Weak cipher suites detected");
                    }
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
                    
                    if (IsWeakCipher(selectedCipher))
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
            // Certificate message format is complex, we'll do basic analysis
            result.Details += " (Certificate chain)";
            
            if (payload.Length > 12)
            {
                var certChainLength = (payload[9] << 16) | (payload[10] << 8) | payload[11];
                result.Metadata["CertificateChainLength"] = certChainLength;
                
                // Try to extract and validate the first certificate
                if (payload.Length > 15)
                {
                    var firstCertLength = (payload[12] << 16) | (payload[13] << 8) | payload[14];
                    if (payload.Length >= 15 + firstCertLength)
                    {
                        var certData = payload.Skip(15).Take(firstCertLength).ToArray();
                        AnalyzeCertificateData(certData, result);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            result.SecurityFlags.Add($"Certificate analysis error: {ex.Message}");
        }
    }

    private static void AnalyzeCertificateData(byte[] certData, ProtocolAnalysisResult result)
    {
        try
        {
            var cert = new X509Certificate2(certData);
            
            result.Metadata["Subject"] = cert.Subject;
            result.Metadata["Issuer"] = cert.Issuer;
            result.Metadata["NotBefore"] = cert.NotBefore;
            result.Metadata["NotAfter"] = cert.NotAfter;
            result.Metadata["SerialNumber"] = cert.SerialNumber ?? "Unknown";
            result.Metadata["Thumbprint"] = cert.Thumbprint ?? "Unknown";
            result.Metadata["KeyAlgorithm"] = cert.PublicKey?.Oid?.FriendlyName ?? "Unknown";
            result.Metadata["KeySize"] = cert.PublicKey?.Key?.KeySize ?? 0;
            
            // Security checks - expiration
            if (cert.NotAfter < DateTime.Now)
            {
                result.RiskScore += 40;
                result.SecurityFlags.Add("Expired certificate");
            }
            else if (cert.NotAfter < DateTime.Now.AddDays(30))
            {
                result.RiskScore += 15;
                result.SecurityFlags.Add("Certificate expires soon");
            }

            // Check if certificate is not yet valid
            if (cert.NotBefore > DateTime.Now)
            {
                result.RiskScore += 35;
                result.SecurityFlags.Add("Certificate not yet valid");
            }

            // Check for weak signature algorithms
            var signatureAlg = cert.SignatureAlgorithm?.FriendlyName?.ToLower() ?? "unknown";
            if (signatureAlg.Contains("sha1") || signatureAlg.Contains("md5"))
            {
                result.RiskScore += 30;
                result.SecurityFlags.Add($"Weak signature algorithm: {signatureAlg}");
            }

            // Check key size
            var keySize = cert.PublicKey?.Key?.KeySize ?? 0;
            if (keySize > 0 && keySize < 2048)
            {
                result.RiskScore += 25;
                result.SecurityFlags.Add($"Weak key size: {keySize} bits");
            }

            // Self-signed certificate check
            if (cert.Subject == cert.Issuer)
            {
                result.RiskScore += 20;
                result.SecurityFlags.Add("Self-signed certificate");
            }

            result.Details += $" | Subject: {cert.GetNameInfo(X509NameType.SimpleName, false)}";
        }
        catch (Exception ex)
        {
            result.RiskScore += 15;
            result.SecurityFlags.Add($"Certificate analysis error: {ex.Message}");
        }
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
}