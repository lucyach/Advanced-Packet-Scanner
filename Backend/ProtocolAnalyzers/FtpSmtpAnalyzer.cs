using PacketDotNet;
using System.Text;
using System.Text.RegularExpressions;

namespace NetworkMonitor.Backend.ProtocolAnalyzers;

public static class FtpAnalyzer
{
    private static readonly Regex FtpCommandRegex = new(@"^([A-Z]{3,4})\s*(.*?)(\r\n|\r|\n|$)", RegexOptions.Compiled);
    private static readonly Regex FtpResponseRegex = new(@"^(\d{3})([-\s])(.*)(\r\n|\r|\n|$)", RegexOptions.Compiled);

    public static ProtocolAnalysisResult AnalyzeFtp(TcpPacket tcp, ProtocolAnalysisResult result)
    {
        result.Protocol = "FTP";

        if (tcp.PayloadData == null || tcp.PayloadData.Length == 0)
        {
            result.Details = "FTP (no payload)";
            return result;
        }

        try
        {
            var payload = Encoding.ASCII.GetString(tcp.PayloadData);
            var lines = payload.Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.RemoveEmptyEntries);

            if (lines.Length == 0) return result;

            var firstLine = lines[0];
            
            // Check if it's a command or response
            var commandMatch = FtpCommandRegex.Match(firstLine);
            var responseMatch = FtpResponseRegex.Match(firstLine);

            if (commandMatch.Success)
            {
                AnalyzeFtpCommand(commandMatch, result);
            }
            else if (responseMatch.Success)
            {
                AnalyzeFtpResponse(responseMatch, result);
            }
            else
            {
                result.Details = "FTP (unrecognized format)";
                result.RiskScore += 10;
            }

            // Analyze all lines for additional context
            AnalyzeAllFtpLines(lines, result);
        }
        catch (Exception ex)
        {
            result.Details = $"FTP parsing error: {ex.Message}";
            result.RiskScore += 15;
        }

        return result;
    }

    private static void AnalyzeFtpCommand(Match match, ProtocolAnalysisResult result)
    {
        var command = match.Groups[1].Value.ToUpper();
        var arguments = match.Groups[2].Value.Trim();

        result.Metadata["Command"] = command;
        result.Metadata["Arguments"] = arguments;
        result.Details = $"FTP Command: {command}";

        if (!string.IsNullOrEmpty(arguments))
        {
            result.Details += $" {arguments}";
        }

        // Security analysis based on command
        switch (command)
        {
            case "USER":
                result.Metadata["Username"] = arguments;
                if (IsWeakUsername(arguments))
                {
                    result.RiskScore += 20;
                    result.SecurityFlags.Add($"Weak username: {arguments}");
                }
                break;

            case "PASS":
                result.Metadata["HasPassword"] = true;
                result.SecurityFlags.Add("Password transmitted in plaintext");
                result.RiskScore += 25; // Plaintext password is risky
                
                if (IsWeakPassword(arguments))
                {
                    result.RiskScore += 30;
                    result.SecurityFlags.Add("Weak password detected");
                }
                result.Details = "FTP Command: PASS [REDACTED]"; // Don't show password
                break;

            case "STOR":
                result.Metadata["UploadFile"] = arguments;
                result.Details = $"FTP Upload: {arguments}";
                if (IsSuspiciousFileName(arguments))
                {
                    result.RiskScore += 25;
                    result.SecurityFlags.Add($"Suspicious file upload: {arguments}");
                }
                break;

            case "RETR":
                result.Metadata["DownloadFile"] = arguments;
                result.Details = $"FTP Download: {arguments}";
                if (IsSuspiciousFileName(arguments))
                {
                    result.RiskScore += 20;
                    result.SecurityFlags.Add($"Suspicious file download: {arguments}");
                }
                break;

            case "CWD":
                result.Metadata["Directory"] = arguments;
                if (IsDirectoryTraversal(arguments))
                {
                    result.RiskScore += 35;
                    result.SecurityFlags.Add("Directory traversal attempt");
                }
                break;

            case "DELE":
                result.Metadata["DeleteFile"] = arguments;
                result.RiskScore += 15; // File deletion is potentially risky
                result.SecurityFlags.Add("File deletion command");
                break;

            case "MKD":
            case "XMKD":
                result.Metadata["CreateDirectory"] = arguments;
                result.RiskScore += 10;
                break;

            case "RMD":
            case "XRMD":
                result.Metadata["RemoveDirectory"] = arguments;
                result.RiskScore += 15;
                result.SecurityFlags.Add("Directory removal command");
                break;

            case "SITE":
                result.RiskScore += 20;
                result.SecurityFlags.Add("SITE command (potentially dangerous)");
                break;
        }
    }

    private static void AnalyzeFtpResponse(Match match, ProtocolAnalysisResult result)
    {
        var code = match.Groups[1].Value;
        var separator = match.Groups[2].Value;
        var message = match.Groups[3].Value;

        result.Metadata["ResponseCode"] = code;
        result.Metadata["ResponseMessage"] = message;
        result.Details = $"FTP Response: {code} {message}";

        var codeInt = int.Parse(code);
        
        // Analyze response codes
        switch (codeInt)
        {
            case 220: // Service ready
                result.Metadata["ServiceReady"] = true;
                break;
            case 230: // User logged in
                result.Metadata["LoginSuccessful"] = true;
                break;
            case 530: // Not logged in / Login incorrect
                result.RiskScore += 10;
                result.SecurityFlags.Add("Failed login attempt");
                break;
            case 550: // Requested action not taken (file unavailable, etc.)
                result.RiskScore += 5;
                break;
            case >= 500 and <= 599: // Permanent negative response
                result.RiskScore += 8;
                result.SecurityFlags.Add("FTP error response");
                break;
        }

        // Check for banner information leakage
        if (codeInt == 220 && message.Length > 20)
        {
            result.RiskScore += 5;
            result.SecurityFlags.Add("Verbose server banner");
        }
    }

    private static void AnalyzeAllFtpLines(string[] lines, ProtocolAnalysisResult result)
    {
        var commandCount = 0;
        var responseCount = 0;

        foreach (var line in lines)
        {
            if (FtpCommandRegex.IsMatch(line))
                commandCount++;
            else if (FtpResponseRegex.IsMatch(line))
                responseCount++;
        }

        result.Metadata["CommandCount"] = commandCount;
        result.Metadata["ResponseCount"] = responseCount;

        // Check for suspicious patterns
        if (commandCount > 10)
        {
            result.RiskScore += 15;
            result.SecurityFlags.Add("High number of FTP commands");
        }
    }

    private static bool IsWeakUsername(string username)
    {
        var weakUsernames = new[] { "admin", "administrator", "root", "user", "guest", "anonymous", "ftp" };
        return weakUsernames.Contains(username.ToLower());
    }

    private static bool IsWeakPassword(string password)
    {
        if (password.Length < 6) return true;
        
        var weakPasswords = new[] { "password", "123456", "admin", "root", "guest", "anonymous" };
        return weakPasswords.Contains(password.ToLower()) || 
               password.All(char.IsDigit) || 
               password.All(char.IsLetter);
    }

    private static bool IsSuspiciousFileName(string filename)
    {
        var suspiciousExtensions = new[] { ".exe", ".bat", ".cmd", ".scr", ".pif", ".com", ".dll", ".sys" };
        var suspiciousNames = new[] { "passwd", "shadow", "hosts", "config", "backup" };
        
        var lowerFilename = filename.ToLower();
        
        return suspiciousExtensions.Any(ext => lowerFilename.EndsWith(ext)) ||
               suspiciousNames.Any(name => lowerFilename.Contains(name)) ||
               filename.Contains("..") ||
               filename.StartsWith(".") ||
               filename.Contains("$") ||
               filename.Contains("*");
    }

    private static bool IsDirectoryTraversal(string path)
    {
        return path.Contains("..") || 
               path.Contains("../") || 
               path.Contains("..\\") ||
               path.StartsWith("/etc/") ||
               path.StartsWith("/var/") ||
               path.StartsWith("/root/") ||
               path.Contains("system32", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("windows", StringComparison.OrdinalIgnoreCase);
    }
}

public static class SmtpAnalyzer
{
    private static readonly Regex SmtpCommandRegex = new(@"^([A-Z]{4})\s*(.*?)(\r\n|\r|\n|$)", RegexOptions.Compiled);
    private static readonly Regex SmtpResponseRegex = new(@"^(\d{3})([-\s])(.*)(\r\n|\r|\n|$)", RegexOptions.Compiled);
    private static readonly Regex EmailRegex = new(@"<?([^@\s<>]+@[^@\s<>]+\.[^@\s<>]+)>?", RegexOptions.Compiled);

    public static ProtocolAnalysisResult AnalyzeSmtp(TcpPacket tcp, ProtocolAnalysisResult result)
    {
        result.Protocol = "SMTP";

        if (tcp.PayloadData == null || tcp.PayloadData.Length == 0)
        {
            result.Details = "SMTP (no payload)";
            return result;
        }

        try
        {
            var payload = Encoding.ASCII.GetString(tcp.PayloadData);
            var lines = payload.Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.RemoveEmptyEntries);

            if (lines.Length == 0) return result;

            var firstLine = lines[0];
            
            // Check if it's a command or response
            var commandMatch = SmtpCommandRegex.Match(firstLine);
            var responseMatch = SmtpResponseRegex.Match(firstLine);

            if (commandMatch.Success)
            {
                AnalyzeSmtpCommand(commandMatch, result);
            }
            else if (responseMatch.Success)
            {
                AnalyzeSmtpResponse(responseMatch, result);
            }
            else
            {
                // Might be email data
                AnalyzeEmailData(payload, result);
            }

            // Security analysis
            AnalyzeSmtpSecurity(lines, result);
        }
        catch (Exception ex)
        {
            result.Details = $"SMTP parsing error: {ex.Message}";
            result.RiskScore += 15;
        }

        return result;
    }

    private static void AnalyzeSmtpCommand(Match match, ProtocolAnalysisResult result)
    {
        var command = match.Groups[1].Value.ToUpper();
        var arguments = match.Groups[2].Value.Trim();

        result.Metadata["Command"] = command;
        result.Metadata["Arguments"] = arguments;
        result.Details = $"SMTP Command: {command}";

        switch (command)
        {
            case "HELO":
            case "EHLO":
                result.Metadata["ClientHostname"] = arguments;
                result.Details += $" {arguments}";
                if (IsSuspiciousHostname(arguments))
                {
                    result.RiskScore += 15;
                    result.SecurityFlags.Add($"Suspicious hostname: {arguments}");
                }
                break;

            case "MAIL":
                var fromMatch = EmailRegex.Match(arguments);
                if (fromMatch.Success)
                {
                    var fromEmail = fromMatch.Groups[1].Value;
                    result.Metadata["MailFrom"] = fromEmail;
                    result.Details += $" FROM: {fromEmail}";
                    
                    if (IsSuspiciousEmail(fromEmail))
                    {
                        result.RiskScore += 20;
                        result.SecurityFlags.Add($"Suspicious sender: {fromEmail}");
                    }
                }
                break;

            case "RCPT":
                var toMatch = EmailRegex.Match(arguments);
                if (toMatch.Success)
                {
                    var toEmail = toMatch.Groups[1].Value;
                    result.Metadata["RcptTo"] = toEmail;
                    result.Details += $" TO: {toEmail}";
                }
                break;

            case "DATA":
                result.Details = "SMTP Data (Email Content)";
                break;

            case "AUTH":
                result.SecurityFlags.Add("SMTP Authentication");
                result.Details += " (Authentication)";
                if (arguments.Contains("PLAIN"))
                {
                    result.RiskScore += 25;
                    result.SecurityFlags.Add("Plaintext authentication");
                }
                break;

            case "STARTTLS":
                result.SecurityFlags.Add("TLS upgrade requested");
                result.RiskScore -= 5; // Good security practice
                break;

            case "QUIT":
                result.Details = "SMTP Session End";
                break;
        }
    }

    private static void AnalyzeSmtpResponse(Match match, ProtocolAnalysisResult result)
    {
        var code = match.Groups[1].Value;
        var separator = match.Groups[2].Value;
        var message = match.Groups[3].Value;

        result.Metadata["ResponseCode"] = code;
        result.Metadata["ResponseMessage"] = message;
        result.Details = $"SMTP Response: {code} {message}";

        var codeInt = int.Parse(code);
        
        switch (codeInt)
        {
            case 220: // Service ready
                if (message.Length > 30)
                {
                    result.RiskScore += 5;
                    result.SecurityFlags.Add("Verbose SMTP banner");
                }
                break;
            case 250: // Requested mail action okay, completed
                break;
            case 354: // Start mail input
                result.Details = "SMTP Ready for Data";
                break;
            case >= 400 and <= 499: // Temporary failure
                result.RiskScore += 5;
                break;
            case >= 500 and <= 599: // Permanent failure
                result.RiskScore += 10;
                result.SecurityFlags.Add("SMTP error");
                break;
        }
    }

    private static void AnalyzeEmailData(string payload, ProtocolAnalysisResult result)
    {
        result.Details = "SMTP Email Data";
        
        // Look for common email headers
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var lines = payload.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
        
        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line)) break; // End of headers
            
            var colonIndex = line.IndexOf(':');
            if (colonIndex > 0)
            {
                var headerName = line.Substring(0, colonIndex).Trim();
                var headerValue = line.Substring(colonIndex + 1).Trim();
                headers[headerName] = headerValue;
            }
        }

        // Analyze important headers
        if (headers.ContainsKey("Subject"))
        {
            result.Metadata["Subject"] = headers["Subject"];
            if (IsSuspiciousSubject(headers["Subject"]))
            {
                result.RiskScore += 25;
                result.SecurityFlags.Add("Suspicious email subject");
            }
        }

        if (headers.ContainsKey("From"))
        {
            result.Metadata["From"] = headers["From"];
        }

        if (headers.ContainsKey("To"))
        {
            result.Metadata["To"] = headers["To"];
        }

        // Check for suspicious content
        if (payload.Contains("http://", StringComparison.OrdinalIgnoreCase) || 
            payload.Contains("https://", StringComparison.OrdinalIgnoreCase))
        {
            result.RiskScore += 10;
            result.SecurityFlags.Add("Contains URLs");
        }

        if (ContainsSuspiciousWords(payload))
        {
            result.RiskScore += 20;
            result.SecurityFlags.Add("Contains suspicious keywords");
        }
    }

    private static void AnalyzeSmtpSecurity(string[] lines, ProtocolAnalysisResult result)
    {
        var hasAuth = lines.Any(line => line.StartsWith("AUTH", StringComparison.OrdinalIgnoreCase));
        var hasTls = lines.Any(line => line.Contains("STARTTLS", StringComparison.OrdinalIgnoreCase));

        if (!hasTls && hasAuth)
        {
            result.RiskScore += 20;
            result.SecurityFlags.Add("Authentication without TLS");
        }

        var commandCount = lines.Count(line => SmtpCommandRegex.IsMatch(line));
        if (commandCount > 20)
        {
            result.RiskScore += 15;
            result.SecurityFlags.Add("High number of SMTP commands");
        }
    }

    private static bool IsSuspiciousHostname(string hostname)
    {
        return string.IsNullOrWhiteSpace(hostname) ||
               hostname.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
               hostname.Contains("temp", StringComparison.OrdinalIgnoreCase) ||
               hostname.Contains("test", StringComparison.OrdinalIgnoreCase) ||
               !hostname.Contains('.');
    }

    private static bool IsSuspiciousEmail(string email)
    {
        var suspiciousDomains = new[] { "tempmail", "10minutemail", "guerrillamail", "mailinator" };
        var lowerEmail = email.ToLower();
        
        return suspiciousDomains.Any(domain => lowerEmail.Contains(domain)) ||
               lowerEmail.Contains("noreply") ||
               lowerEmail.Contains("donotreply");
    }

    private static bool IsSuspiciousSubject(string subject)
    {
        var suspiciousWords = new[] { "urgent", "winner", "congratulations", "claim", "prize", "bitcoin", "crypto", "investment" };
        var lowerSubject = subject.ToLower();
        
        return suspiciousWords.Any(word => lowerSubject.Contains(word)) ||
               subject.Length > 100 ||
               subject.Count(c => c == '!') > 3;
    }

    private static bool ContainsSuspiciousWords(string content)
    {
        var suspiciousWords = new[] { "password", "login", "account", "suspended", "verify", "click here", "download now" };
        var lowerContent = content.ToLower();
        
        return suspiciousWords.Count(word => lowerContent.Contains(word)) >= 3;
    }
}