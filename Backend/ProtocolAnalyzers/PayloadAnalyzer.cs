using System.Text;
using System.Text.RegularExpressions;

namespace NetworkMonitor.Backend.ProtocolAnalyzers;

public static class PayloadAnalyzer
{
    private static readonly Regex UrlRegex = new(@"https?://[^\s<>""]+", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex EmailRegex = new(@"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", RegexOptions.Compiled);
    private static readonly Regex IpRegex = new(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.Compiled);
    private static readonly Regex CreditCardRegex = new(@"\b(?:\d{4}[-\s]?){3}\d{4}\b", RegexOptions.Compiled);
    private static readonly Regex Base64Regex = new(@"^[A-Za-z0-9+/]*={0,2}$", RegexOptions.Compiled);

    public static ProtocolAnalysisResult AnalyzeGenericPayload(byte[] payload, ProtocolAnalysisResult result)
    {
        if (payload == null || payload.Length == 0)
            return result;

        try
        {
            // Try to determine if payload contains text
            var isText = IsLikelyText(payload);
            result.Metadata["IsText"] = isText;
            result.Metadata["PayloadSize"] = payload.Length;

            if (isText)
            {
                AnalyzeTextPayload(payload, result);
            }
            else
            {
                AnalyzeBinaryPayload(payload, result);
            }

            // General payload analysis
            AnalyzePayloadStructure(payload, result);
        }
        catch (Exception ex)
        {
            result.SecurityFlags.Add($"Payload analysis error: {ex.Message}");
        }

        return result;
    }

    private static void AnalyzeTextPayload(byte[] payload, ProtocolAnalysisResult result)
    {
        try
        {
            var text = Encoding.UTF8.GetString(payload);
            result.Metadata["PayloadPreview"] = TruncateString(text, 200);

            // Look for URLs
            var urls = UrlRegex.Matches(text).Cast<Match>().Select(m => m.Value).Distinct().Take(10).ToList();
            if (urls.Any())
            {
                result.Metadata["URLs"] = urls;
                result.SecurityFlags.Add($"Contains {urls.Count} URL(s)");
                
                // Check for suspicious URLs
                if (urls.Any(IsSuspiciousUrl))
                {
                    result.RiskScore += 25;
                    result.SecurityFlags.Add("Contains suspicious URLs");
                }
            }

            // Look for email addresses
            var emails = EmailRegex.Matches(text).Cast<Match>().Select(m => m.Value).Distinct().Take(10).ToList();
            if (emails.Any())
            {
                result.Metadata["EmailAddresses"] = emails;
                result.SecurityFlags.Add($"Contains {emails.Count} email address(es)");
            }

            // Look for IP addresses
            var ips = IpRegex.Matches(text).Cast<Match>().Select(m => m.Value).Distinct().Take(10).ToList();
            if (ips.Any())
            {
                result.Metadata["IPAddresses"] = ips;
                result.SecurityFlags.Add($"Contains {ips.Count} IP address(es)");
            }

            // Look for potential credit card numbers
            var creditCards = CreditCardRegex.Matches(text).Cast<Match>().Where(m => IsValidCreditCard(m.Value)).Take(5).ToList();
            if (creditCards.Any())
            {
                result.RiskScore += 40;
                result.SecurityFlags.Add("Potential credit card numbers detected");
                result.Metadata["CreditCardCount"] = creditCards.Count;
            }

            // Check for SQL injection patterns
            if (ContainsSqlInjection(text))
            {
                result.RiskScore += 35;
                result.SecurityFlags.Add("Potential SQL injection");
            }

            // Check for XSS patterns
            if (ContainsXss(text))
            {
                result.RiskScore += 30;
                result.SecurityFlags.Add("Potential XSS payload");
            }

            // Check for command injection
            if (ContainsCommandInjection(text))
            {
                result.RiskScore += 35;
                result.SecurityFlags.Add("Potential command injection");
            }

            // Check for suspicious keywords
            var suspiciousCount = CountSuspiciousKeywords(text);
            if (suspiciousCount > 0)
            {
                result.RiskScore += suspiciousCount * 5;
                result.SecurityFlags.Add($"Contains {suspiciousCount} suspicious keyword(s)");
            }

            // Check for potential encoded data
            if (ContainsEncodedData(text))
            {
                result.RiskScore += 15;
                result.SecurityFlags.Add("Contains potentially encoded data");
            }

            // Analyze text characteristics
            AnalyzeTextCharacteristics(text, result);
        }
        catch (Exception ex)
        {
            result.SecurityFlags.Add($"Text analysis error: {ex.Message}");
        }
    }

    private static void AnalyzeBinaryPayload(byte[] payload, ProtocolAnalysisResult result)
    {
        result.Metadata["DataType"] = "Binary";

        // Check for common file signatures
        var fileType = DetectFileType(payload);
        if (!string.IsNullOrEmpty(fileType))
        {
            result.Metadata["DetectedFileType"] = fileType;
            result.Details += $" | {fileType} data";

            if (IsSuspiciousFileType(fileType))
            {
                result.RiskScore += 25;
                result.SecurityFlags.Add($"Suspicious file type: {fileType}");
            }
        }

        // Calculate entropy to detect encryption/compression
        var entropy = CalculateEntropy(payload);
        result.Metadata["Entropy"] = entropy;

        if (entropy > 7.5)
        {
            result.RiskScore += 10;
            result.SecurityFlags.Add("High entropy data (encrypted/compressed)");
        }
        else if (entropy < 3.0)
        {
            result.SecurityFlags.Add("Low entropy data (structured/repetitive)");
        }

        // Look for embedded strings in binary data
        var strings = ExtractStrings(payload, 4);
        if (strings.Any())
        {
            result.Metadata["EmbeddedStrings"] = strings.Take(10).ToList();
        }
    }

    private static void AnalyzePayloadStructure(byte[] payload, ProtocolAnalysisResult result)
    {
        // Check for null bytes
        var nullCount = payload.Count(b => b == 0);
        var nullPercentage = (double)nullCount / payload.Length * 100;
        result.Metadata["NullBytePercentage"] = nullPercentage;

        if (nullPercentage > 50)
        {
            result.SecurityFlags.Add("High null byte content");
        }

        // Check for repeating patterns
        if (HasRepeatingPatterns(payload))
        {
            result.SecurityFlags.Add("Contains repeating patterns");
        }

        // Check size
        if (payload.Length > 10000)
        {
            result.SecurityFlags.Add("Large payload size");
        }
    }

    private static bool IsLikelyText(byte[] payload)
    {
        if (payload.Length == 0) return false;
        
        // Limit analysis to first 1KB for performance
        var sampleSize = Math.Min(payload.Length, 1024);
        var sample = payload.Take(sampleSize);

        // Check for high percentage of printable ASCII characters
        var printableCount = sample.Count(b => (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13);
        var printablePercentage = (double)printableCount / sampleSize;
        
        // Also check for null bytes (strong indicator of binary data)
        var nullCount = sample.Count(b => b == 0);
        if (nullCount > sampleSize * 0.1) return false; // More than 10% nulls = binary
        
        return printablePercentage > 0.7;
    }

    private static bool IsSuspiciousUrl(string url)
    {
        var lowerUrl = url.ToLower();
        var suspiciousDomains = new[] { "bit.ly", "tinyurl", "t.co", "short.link" };
        var suspiciousWords = new[] { "phishing", "malware", "virus", "hack", "crack" };
        
        return suspiciousDomains.Any(domain => lowerUrl.Contains(domain)) ||
               suspiciousWords.Any(word => lowerUrl.Contains(word)) ||
               url.Length > 200 ||
               url.Count(c => c == '/') > 10;
    }

    private static bool IsValidCreditCard(string number)
    {
        // Simple Luhn algorithm check
        var digits = number.Where(char.IsDigit).Select(c => c - '0').ToArray();
        if (digits.Length < 13 || digits.Length > 19) return false;

        for (int i = digits.Length - 2; i >= 0; i -= 2)
        {
            digits[i] *= 2;
            if (digits[i] > 9) digits[i] -= 9;
        }

        return digits.Sum() % 10 == 0;
    }

    private static bool ContainsSqlInjection(string text)
    {
        var sqlPatterns = new[]
        {
            @"(\bUNION\b.*\bSELECT\b)|(\bSELECT\b.*\bFROM\b)",
            @"(\bDROP\b.*\bTABLE\b)|(\bDELETE\b.*\bFROM\b)",
            @"(\bINSERT\b.*\bINTO\b)|(\bUPDATE\b.*\bSET\b)",
            @"('.*OR.*'.*=.*')|(\bOR\b.*\d.*=.*\d)",
            @"(--)|(/\*.*\*/)"
        };

        return sqlPatterns.Any(pattern => 
            Regex.IsMatch(text, pattern, RegexOptions.IgnoreCase | RegexOptions.Multiline));
    }

    private static bool ContainsXss(string text)
    {
        var xssPatterns = new[]
        {
            @"<script[^>]*>.*</script>",
            @"javascript:",
            @"on\w+\s*=",
            @"<iframe[^>]*>",
            @"<object[^>]*>",
            @"<embed[^>]*>",
            @"eval\s*\(",
            @"document\.cookie",
            @"document\.write"
        };

        return xssPatterns.Any(pattern => 
            Regex.IsMatch(text, pattern, RegexOptions.IgnoreCase | RegexOptions.Multiline));
    }

    private static bool ContainsCommandInjection(string text)
    {
        var commandPatterns = new[]
        {
            @"[;&|`]\s*(ls|cat|pwd|whoami|id|uname)",
            @"[;&|`]\s*(dir|type|echo|net|ipconfig)",
            @"\$\(.*\)",
            @"`.*`",
            @"&&|\|\|",
            @">\s*/dev/null",
            @"2>&1"
        };

        return commandPatterns.Any(pattern => 
            Regex.IsMatch(text, pattern, RegexOptions.IgnoreCase));
    }

    private static int CountSuspiciousKeywords(string text)
    {
        var suspiciousKeywords = new[]
        {
            "password", "passwd", "secret", "token", "api_key", "private_key",
            "admin", "root", "system", "config", "database", "db_password",
            "exploit", "payload", "shellcode", "backdoor", "trojan",
            "bitcoin", "wallet", "cryptocurrency", "ransomware"
        };

        var lowerText = text.ToLower();
        return suspiciousKeywords.Count(keyword => lowerText.Contains(keyword));
    }

    private static bool ContainsEncodedData(string text)
    {
        // Check for base64-like patterns
        var base64Matches = Regex.Matches(text, @"[A-Za-z0-9+/]{20,}={0,2}");
        if (base64Matches.Count > 0)
        {
            foreach (Match match in base64Matches)
            {
                if (Base64Regex.IsMatch(match.Value) && match.Value.Length % 4 == 0)
                    return true;
            }
        }

        // Check for hex-encoded data
        var hexMatches = Regex.Matches(text, @"[0-9a-fA-F]{32,}");
        return hexMatches.Count > 0;
    }

    private static void AnalyzeTextCharacteristics(string text, ProtocolAnalysisResult result)
    {
        var lines = text.Split('\n').Length;
        var words = text.Split(new[] { ' ', '\t', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries).Length;
        
        result.Metadata["LineCount"] = lines;
        result.Metadata["WordCount"] = words;
        
        // Character distribution
        var alphaCount = text.Count(char.IsLetter);
        var digitCount = text.Count(char.IsDigit);
        var spaceCount = text.Count(char.IsWhiteSpace);
        var specialCount = text.Length - alphaCount - digitCount - spaceCount;
        
        result.Metadata["AlphaPercentage"] = (double)alphaCount / text.Length * 100;
        result.Metadata["DigitPercentage"] = (double)digitCount / text.Length * 100;
        result.Metadata["SpecialPercentage"] = (double)specialCount / text.Length * 100;

        if ((double)specialCount / text.Length > 0.3)
        {
            result.SecurityFlags.Add("High special character content");
        }
    }

    private static string DetectFileType(byte[] payload)
    {
        if (payload.Length < 4) return "Unknown";

        // Common file signatures
        var signatures = new Dictionary<string, byte[][]>
        {
            ["PDF"] = new[] { new byte[] { 0x25, 0x50, 0x44, 0x46 } }, // %PDF
            ["ZIP"] = new[] { new byte[] { 0x50, 0x4B, 0x03, 0x04 } }, // PK..
            ["JPEG"] = new[] { new byte[] { 0xFF, 0xD8, 0xFF } },
            ["PNG"] = new[] { new byte[] { 0x89, 0x50, 0x4E, 0x47 } },
            ["GIF"] = new[] { new byte[] { 0x47, 0x49, 0x46, 0x38 } }, // GIF8
            ["EXE"] = new[] { new byte[] { 0x4D, 0x5A } }, // MZ
            ["XML"] = new[] { new byte[] { 0x3C, 0x3F, 0x78, 0x6D } }, // <?xm
            ["HTML"] = new[] { new byte[] { 0x3C, 0x68, 0x74, 0x6D } } // <htm
        };

        foreach (var (fileType, sigs) in signatures)
        {
            foreach (var sig in sigs)
            {
                if (payload.Take(sig.Length).SequenceEqual(sig))
                    return fileType;
            }
        }

        return "Unknown";
    }

    private static bool IsSuspiciousFileType(string fileType)
    {
        var suspiciousTypes = new[] { "EXE", "DLL", "BAT", "CMD", "SCR", "VBS", "PS1" };
        return suspiciousTypes.Contains(fileType.ToUpper());
    }

    private static double CalculateEntropy(byte[] data)
    {
        if (data.Length == 0) return 0;

        var frequencies = new int[256];
        foreach (var b in data)
        {
            frequencies[b]++;
        }

        double entropy = 0;
        foreach (var freq in frequencies)
        {
            if (freq == 0) continue;
            var probability = (double)freq / data.Length;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }

    private static List<string> ExtractStrings(byte[] data, int minLength)
    {
        var strings = new List<string>();
        var currentString = new StringBuilder();

        foreach (var b in data)
        {
            if (b >= 32 && b <= 126) // Printable ASCII
            {
                currentString.Append((char)b);
            }
            else
            {
                if (currentString.Length >= minLength)
                {
                    strings.Add(currentString.ToString());
                    if (strings.Count >= 50) break; // Limit extracted strings
                }
                currentString.Clear();
            }
        }

        if (currentString.Length >= minLength)
        {
            strings.Add(currentString.ToString());
        }

        return strings;
    }

    private static bool HasRepeatingPatterns(byte[] payload)
    {
        if (payload.Length < 8) return false;

        // Look for patterns of 2-4 bytes that repeat
        for (int patternLength = 2; patternLength <= 4; patternLength++)
        {
            for (int i = 0; i <= payload.Length - patternLength * 3; i++)
            {
                var pattern = payload.Skip(i).Take(patternLength).ToArray();
                var matches = 0;
                
                for (int j = i + patternLength; j <= payload.Length - patternLength; j += patternLength)
                {
                    if (payload.Skip(j).Take(patternLength).SequenceEqual(pattern))
                    {
                        matches++;
                        if (matches >= 3) return true;
                    }
                    else
                    {
                        break;
                    }
                }
            }
        }

        return false;
    }

    private static string TruncateString(string input, int maxLength)
    {
        if (string.IsNullOrEmpty(input) || input.Length <= maxLength)
            return input;
            
        return input.Substring(0, maxLength) + "...";
    }
}