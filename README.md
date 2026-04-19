## Advanced Packet Scanner with Deep Packet Inspection (DPI)
### Overview
```
Advanced Packet Scanner is a comprehensive network monitoring and security analysis tool written in C# using the .NET 8 framework. The application captures live network traffic from a selected network interface and performs advanced Deep Packet Inspection (DPI) to analyze packets in real time, detecting suspicious activity and providing detailed protocol analysis.

Key Features:
- Deep Packet Inspection (DPI) with protocol-specific analyzers
- SSL/TLS certificate analysis and validation
- HTTP headers, cookies, and user agent extraction
- DNS security analysis with tunneling detection
- DHCP security monitoring
- FTP and SMTP protocol analysis
- Advanced payload content analysis and filtering
- Real-time security risk scoring
- Enhanced threat detection and alerting

The goal of the project is to demonstrate advanced packet analysis, traffic inspection, and security monitoring in a comprehensive desktop application.
```

### Enhanced Features
```
🔍 Deep Packet Inspection (DPI)
- Protocol-specific parsers for HTTP, HTTPS, DNS, DHCP, FTP, SMTP
- SSL/TLS certificate validation and security analysis
- Payload content analysis with malware signature detection
- Advanced pattern recognition for suspicious activities

🛡️ Security Analysis
- Real-time risk scoring (0-100 scale)
- SSL/TLS security assessment (certificate validation, cipher analysis)
- DNS security (tunneling detection, DGA identification, suspicious domains)
- HTTP security analysis (header validation, XSS detection, injection patterns)
- DHCP rogue server detection
- Email security analysis (phishing patterns, suspicious attachments)

📊 Enhanced Monitoring Dashboard
- Real-time security metrics and risk assessment
- Protocol breakdown with security flags
- Advanced packet filtering and analysis
- Security alert classification and severity scoring
- Detailed packet metadata and forensic information

🚨 Advanced Threat Detection
- Man-in-the-middle attack indicators
- Certificate-based attacks (expired, self-signed, suspicious CAs)
- DNS poisoning and tunneling attempts
- Command injection and XSS payload detection
- Credit card and PII data exposure alerts
- Behavioral analysis for zero-day detection
```

### Technical Enhancements
```
Protocol Analyzers:
✅ HTTP/HTTPS - Headers, cookies, user agents, security headers analysis
✅ SSL/TLS - Certificate validation, cipher assessment, vulnerability detection  
✅ DNS - Query analysis, tunneling detection, DGA identification
✅ DHCP - Rogue server detection, suspicious configuration analysis
✅ FTP - Command analysis, suspicious file transfer detection
✅ SMTP - Email security analysis, phishing pattern detection
✅ Generic Payload - Content analysis, malware signatures, encoding detection

Security Features:
✅ Real-time risk scoring with threat classification
✅ Certificate chain validation and security assessment
✅ Advanced pattern matching for attack signatures
✅ Behavioral analysis for anomaly detection
✅ Comprehensive security alerting system
✅ Forensic data collection and analysis
```

## Enhanced File Structure

```
Advanced-Packet-Scanner/
├── Backend/
│   ├── AppConfig.cs              # Enhanced configuration management
│   ├── DataModel.cs              # Enhanced data models with security metrics
│   ├── MainController.cs         # Enhanced main controller with DPI integration
│   └── ProtocolAnalyzers/        # Deep Packet Inspection analyzers
│       ├── ProtocolAnalyzer.cs   # Main protocol analysis coordinator
│       ├── HttpAnalyzer.cs       # HTTP/HTTPS deep analysis
│       ├── SslTlsAnalyzer.cs     # SSL/TLS certificate and security analysis
│       ├── DnsAnalyzer.cs        # DNS security and tunneling analysis
│       ├── DhcpAnalyzer.cs       # DHCP security analysis
│       ├── FtpSmtpAnalyzer.cs    # FTP and SMTP protocol analysis
│       └── PayloadAnalyzer.cs    # Generic payload content analysis
├── UI/
│   ├── AlertsPage.cs             # Enhanced alerts with security classification
│   ├── BasePage.cs               # Base UI functionality
│   ├── DashboardPage.cs          # Enhanced dashboard with security metrics
│   ├── MainForm.cs               # Enhanced main form
│   └── OptionsPage.cs            # Enhanced configuration options
├── NetworkMonitor.csproj         # Enhanced project dependencies
├── Program.cs                    # Application entry point
├── README.md                     # This enhanced documentation
└── config.json                   # Enhanced configuration file
```

### Security Capabilities

```
🔒 SSL/TLS Security Analysis:
- Certificate chain validation and trust assessment
- Cipher suite security evaluation
- TLS version compliance checking
- Certificate expiration and validity monitoring
- Self-signed certificate detection
- Certificate authority trust validation

🌐 DNS Security Monitoring:
- DNS tunneling detection and analysis
- Domain Generation Algorithm (DGA) identification
- Suspicious domain pattern recognition
- DNS poisoning attempt detection
- Query frequency analysis for C&C detection

📧 Email Security Analysis:
- SMTP security assessment
- Phishing pattern detection
- Suspicious attachment identification
- Email header analysis and validation
- Sender reputation assessment

🔍 Advanced Payload Analysis:
- Malware signature detection
- Command injection pattern recognition
- XSS and SQL injection detection
- Credit card and PII exposure alerts
- Encoded payload detection and analysis
- File type identification and security assessment
```

### Installation and Setup

```
Prerequisites:
- .NET 8.0 Runtime or later
- Npcap packet capture driver (https://npcap.org/)
- Administrator privileges (required for packet capture)

Enhanced Dependencies:
- SharpPcap 6.3.1+ (packet capture library)
- System.Security.Cryptography.X509Certificates (certificate analysis)
- System.Text.Json 8.0+ (enhanced JSON processing)

Build Instructions:
1. Clone the repository
2. Install Npcap with WinPcap API-compatible mode
3. Open project in Visual Studio 2022 or use dotnet CLI
4. Build and run as Administrator
```

### Enhanced Usage Guide

```
🚀 Getting Started:
1. Run the application as Administrator
2. Select network adapter from the dropdown
3. Start packet capture to begin DPI analysis
4. Monitor real-time security metrics and alerts
5. Review detailed packet analysis with risk scoring

🔧 Advanced Configuration:
- Adjust risk scoring thresholds in AppConfig.cs
- Configure security alert severity levels
- Customize protocol analysis parameters
- Set packet retention and analysis limits

📊 Security Dashboard:
- Real-time risk score monitoring
- Protocol distribution analysis  
- Security flag frequency tracking
- High-risk packet identification
- Forensic data collection and export
```

### Security Considerations

```
⚠️ Important Security Notes:
- Always run with minimal necessary privileges
- Regularly update Npcap drivers for security patches
- Monitor for false positives in security analysis
- Validate certificate analysis results independently
- Use in compliance with applicable laws and regulations
- Implement proper data handling for sensitive information

🛡️ Defensive Measures:
- Built-in protection against analysis evasion
- Robust error handling for malformed packets
- Secure storage of captured security data
- Protection against packet injection attacks
- Comprehensive logging for audit trails
```

This enhanced packet scanner now provides enterprise-level Deep Packet Inspection capabilities with comprehensive security analysis, making it suitable for advanced network security monitoring and forensic analysis.
│   ├── DashboardPage.cs     # Dashboard interface
│   ├── MainForm.cs          # Main form window
│   └── OptionsPage.cs       # Settings and options
├── bin/                     # Build output directory
├── obj/                     # Build temporary files
├── config.json             # Application configuration
├── NetworkMonitor.csproj   # Project file
├── NetworkMonitor.sln      # Solution file
├── Program.cs              # Application entry point
└── README.md               # This file
```
## 
Packet Detection Rules
```
ICMP Flood Detection
Triggers when a large number of ICMP echo requests are detected from the same source within a short time period.

SYN Flood Detection
Detects large volumes of TCP packets that contain the SYN flag but not the ACK flag.

UDP Flood Detection
Triggers when an unusually high number of UDP packets arrive from the same source IP.

Port Scan Detection
Tracks how many unique ports a source IP attempts to connect to within a short time window.

If any rule is triggered, the system generates an alert displayed in the Alerts page.
```
## How C# and HTML Connect
### **Step-by-Step Connection:**

#### **Step 1: C# Creates Data**
```csharp
// In MainController.cs
var model = new DataModel
{
    Message = "Hello from C#!",           // C# gets this data
    CurrentTime = DateTime.Now.ToString(), // C# determines this
    ComputerName = Environment.MachineName // C# reads system info
};
```

#### **Step 2: C# Sends to HTML**
```csharp
return View("~/UI/MainPage.cshtml", model);  // Send 'model' to HTML
```

#### **Step 3: HTML Displays Data**
```html
@model NetworkMonitor.Backend.DataModel    <!-- Connect to C# model -->

<span>@Model.Message</span>                 <!-- Display: "Hello from C#!" -->
<span>@Model.CurrentTime</span>             <!-- Display: current time -->
<span>@Model.ComputerName</span>            <!-- Display: computer name -->
```

## How to Run the Program

### Prerequisites
Install the required libraries using NuGet:
```bash
dotnet add package SharpPcap
dotnet add package PacketDotNet
```
- Install .NET 10.0+ SDK from [Microsoft's website](https://dotnet.microsoft.com/download)
- Install NpCap:
https://npcap.com/

### Running Steps
**Run the application:**
   ```bash
   dotnet run
   ```

   If it is already running in the background:
   ```
   taskkill /f /im NetworkMonitor.exe
   ```
   Then run dotnet run

**Open your web browser and go to:**
   ```
   https://localhost:5001
   ```
   (Or whatever URL is shown in the terminal)

### OR Using Visual Studios
```
Install:
Visual Studio 2022 Community

During installation select:
.NET Desktop Development workload

Using the NuGet Package Manager in Visual Studio install SharpPcap and PacketDotNet.

Open the project solution:
NetworkMonitor.sln

Run VS as Administrator to allow easier capturing

Build Project (Ctrl + Shift + B)

Run the program (F5)

Select a Network Adapter in the dashboard of the program
```
## Testing the Alerts
### ICMP Flood Test
```bash
for ($i=0; $i -lt 500; $i++) { ping 8.8.8.8 -n 1 > $null }
```

### SYN Flood Test
```bash
nping --tcp -p 80 --flags syn --rate 100 <target_ip>
```

### UDP Flood Test
```bash
nping --udp --rate 200 <target_ip>
```

### Port Scan Test
```bash
nmap -p 1-100 <target_ip>
```

