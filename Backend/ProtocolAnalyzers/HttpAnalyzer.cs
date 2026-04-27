using PacketDotNet;
using System.Text;
using System.Text.RegularExpressions;

namespace NetworkMonitor.Backend.ProtocolAnalyzers;

public static class HttpAnalyzer
{
    private static readonly Regex HttpRequestRegex = new(@"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s+(.+?)\s+HTTP/(\d\.\d)", RegexOptions.Compiled);
    private static readonly Regex HttpResponseRegex = new(@"^HTTP/(\d\.\d)\s+(\d{3})\s+(.+)", RegexOptions.Compiled);
    private static readonly Regex HeaderRegex = new(@"^([^:]+):\s*(.+)$", RegexOptions.Compiled);

    public static ProtocolAnalysisResult AnalyzeHttp(TcpPacket tcp, ProtocolAnalysisResult result)
    {
        result.Protocol = "HTTP";

        if (tcp.PayloadData == null || tcp.PayloadData.Length == 0)
        {
            result.Details = "HTTP (no payload)";
            return result;
        }

        try
        {
            // Try UTF-8 first, fallback to ASCII for malformed data
            string payload;
            try
            {
                payload = Encoding.UTF8.GetString(tcp.PayloadData);
            }
            catch
            {
                payload = Encoding.ASCII.GetString(tcp.PayloadData);
                result.SecurityFlags.Add("Non-UTF8 encoding detected");
                result.RiskScore += 5;
            }
            
            var lines = payload.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);

            if (lines.Length == 0) return result;

            var firstLine = lines[0];
            var headers = ParseHeaders(lines.Skip(1));
            result.Metadata["Headers"] = headers;
            result.Metadata["HeaderCount"] = headers.Count;

            // Check if it's a request or response
            var requestMatch = HttpRequestRegex.Match(firstLine);
            var responseMatch = HttpResponseRegex.Match(firstLine);

            if (requestMatch.Success)
            {
                AnalyzeHttpRequest(requestMatch, headers, result);
                AnalyzeHttpSecurity(headers, result, isResponse: false);
            }
            else if (responseMatch.Success)
            {
                AnalyzeHttpResponse(responseMatch, headers, result);
                AnalyzeHttpSecurity(headers, result, isResponse: true);
            }
            else
            {
                result.Details = "HTTP (malformed)";
                result.RiskScore += 20;
                result.SecurityFlags.Add("Malformed HTTP");
            }
        }
        catch (Exception ex)
        {
            result.Details = $"HTTP parsing error: {ex.Message}";
            result.RiskScore += 15;
        }

        return result;
    }

    private static void AnalyzeHttpRequest(Match match, Dictionary<string, string> headers, ProtocolAnalysisResult result)
    {
        var method = match.Groups[1].Value;
        var uri = match.Groups[2].Value;
        var version = match.Groups[3].Value;

        result.Details = $"HTTP {method} {uri}";
        result.Metadata["Method"] = method;
        result.Metadata["URI"] = uri;
        result.Metadata["Version"] = version;

        if (headers.ContainsKey("Host"))
        {
            result.Metadata["Host"] = headers["Host"];
            result.Details += $" | Host: {headers["Host"]}";
        }

        if (headers.ContainsKey("User-Agent"))
        {
            var userAgent = headers["User-Agent"];
            result.Metadata["UserAgent"] = userAgent;
            result.Metadata["UserAgentAnalysis"] = AnalyzeUserAgent(userAgent);
        }

        if (headers.ContainsKey("Cookie"))
        {
            var parsedCookies = ParseCookies(headers["Cookie"]);
            result.Metadata["Cookies"] = parsedCookies;
            result.Metadata["CookieCount"] = parsedCookies.Count;

            if (parsedCookies.Count > 15)
            {
                result.RiskScore += 10;
                result.SecurityFlags.Add("High cookie count in HTTP request");
            }
        }

        if (headers.ContainsKey("Authorization"))
        {
            result.Metadata["Authorization"] = "Present";
            result.SecurityFlags.Add("Contains Authorization Header");
        }

        // Risk assessment
        if (method == "POST" && !headers.ContainsKey("Content-Type"))
        {
            result.RiskScore += 10;
            result.SecurityFlags.Add("POST without Content-Type");
        }

        if (uri.Contains(".."))
        {
            result.RiskScore += 30;
            result.SecurityFlags.Add("Potential Directory Traversal");
        }
    }

    private static void AnalyzeHttpResponse(Match match, Dictionary<string, string> headers, ProtocolAnalysisResult result)
    {
        var version = match.Groups[1].Value;
        var statusCode = match.Groups[2].Value;
        var statusText = match.Groups[3].Value;

        result.Details = $"HTTP {statusCode} {statusText}";
        result.Metadata["Version"] = version;
        result.Metadata["StatusCode"] = statusCode;
        result.Metadata["StatusText"] = statusText;

        if (headers.ContainsKey("Server"))
        {
            result.Metadata["Server"] = headers["Server"];
        }

        if (headers.ContainsKey("Set-Cookie"))
        {
            var setCookies = ParseSetCookies(headers["Set-Cookie"]);
            result.Metadata["SetCookies"] = setCookies;
            result.Metadata["SetCookieCount"] = setCookies.Count;

            if (setCookies.Any(c => c.Secure == false || c.HttpOnly == false))
            {
                result.RiskScore += 10;
                result.SecurityFlags.Add("Response sets cookies without Secure/HttpOnly");
            }
        }

        // Risk assessment for responses
        if (statusCode.StartsWith("4") || statusCode.StartsWith("5"))
        {
            result.RiskScore += 5;
        }
    }

    private static Dictionary<string, string> ParseHeaders(IEnumerable<string> lines)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string? currentHeader = null;
        
        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line)) break; // End of headers

            if ((line.StartsWith(' ') || line.StartsWith('\t')) && currentHeader != null)
            {
                headers[currentHeader] = headers[currentHeader] + " " + line.Trim();
                continue;
            }
            
            var match = HeaderRegex.Match(line);
            if (match.Success)
            {
                var name = match.Groups[1].Value.Trim();
                var value = match.Groups[2].Value.Trim();
                if (headers.ContainsKey(name))
                {
                    headers[name] = headers[name] + ", " + value;
                }
                else
                {
                    headers[name] = value;
                }

                currentHeader = name;
            }
        }

        return headers;
    }

    private static Dictionary<string, string> ParseCookies(string cookieHeader)
    {
        var cookies = new Dictionary<string, string>();
        var parts = cookieHeader.Split(';');

        foreach (var part in parts)
        {
            var kvp = part.Split('=', 2);
            if (kvp.Length == 2)
            {
                cookies[kvp[0].Trim()] = kvp[1].Trim();
            }
        }

        return cookies;
    }

    private static List<SetCookieInfo> ParseSetCookies(string setCookieHeader)
    {
        var result = new List<SetCookieInfo>();
        var cookieCandidates = setCookieHeader.Split(',');

        foreach (var candidate in cookieCandidates)
        {
            var segments = candidate.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            if (segments.Length == 0)
                continue;

            var nameValue = segments[0].Split('=', 2);
            if (nameValue.Length != 2)
                continue;

            var cookie = new SetCookieInfo
            {
                Name = nameValue[0].Trim(),
                Domain = GetCookieAttribute(segments, "Domain"),
                Path = GetCookieAttribute(segments, "Path"),
                SameSite = GetCookieAttribute(segments, "SameSite"),
                Secure = segments.Any(s => s.Equals("Secure", StringComparison.OrdinalIgnoreCase)),
                HttpOnly = segments.Any(s => s.Equals("HttpOnly", StringComparison.OrdinalIgnoreCase))
            };

            result.Add(cookie);
        }

        return result;
    }

    private static string GetCookieAttribute(string[] segments, string name)
    {
        var attribute = segments.FirstOrDefault(s => s.StartsWith(name + "=", StringComparison.OrdinalIgnoreCase));
        if (attribute == null)
            return string.Empty;

        var kv = attribute.Split('=', 2);
        return kv.Length == 2 ? kv[1].Trim() : string.Empty;
    }

    private static Dictionary<string, string> AnalyzeUserAgent(string userAgent)
    {
        var ua = userAgent.ToLowerInvariant();
        var analysis = new Dictionary<string, string>
        {
            ["ClientType"] = ua.Contains("bot") || ua.Contains("crawler") || ua.Contains("spider") ? "Bot" : "Browser"
        };

        analysis["Platform"] = ua switch
        {
            var s when s.Contains("windows") => "Windows",
            var s when s.Contains("android") => "Android",
            var s when s.Contains("iphone") || s.Contains("ipad") => "iOS",
            var s when s.Contains("mac os") || s.Contains("macintosh") => "macOS",
            var s when s.Contains("linux") => "Linux",
            _ => "Unknown"
        };

        analysis["Browser"] = ua switch
        {
            var s when s.Contains("edg/") => "Edge",
            var s when s.Contains("chrome/") && !s.Contains("edg/") => "Chrome",
            var s when s.Contains("firefox/") => "Firefox",
            var s when s.Contains("safari/") && !s.Contains("chrome/") => "Safari",
            _ => "Unknown"
        };

        return analysis;
    }

    private static void AnalyzeHttpSecurity(Dictionary<string, string> headers, ProtocolAnalysisResult result, bool isResponse)
    {
        if (!isResponse)
            return;

        // Check for security headers
        var securityHeaders = new[]
        {
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection"
        };

        var missingHeaders = securityHeaders.Where(h => !headers.ContainsKey(h)).ToList();
        if (missingHeaders.Any())
        {
            result.RiskScore += missingHeaders.Count * 5;
            result.SecurityFlags.Add($"Missing security headers: {string.Join(", ", missingHeaders)}");
        }

        // Check for potentially dangerous content
        if (headers.ContainsKey("Content-Type"))
        {
            var contentType = headers["Content-Type"].ToLower();
            if (contentType.Contains("javascript") || contentType.Contains("script"))
            {
                result.RiskScore += 15;
                result.SecurityFlags.Add("JavaScript content detected");
            }
        }
    }

    private class SetCookieInfo
    {
        public string Name { get; set; } = string.Empty;
        public string Domain { get; set; } = string.Empty;
        public string Path { get; set; } = string.Empty;
        public string SameSite { get; set; } = string.Empty;
        public bool Secure { get; set; }
        public bool HttpOnly { get; set; }
    }
}