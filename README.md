## Easy Packet Grabber / Network Monitor
### Overview
```
Easy Packet Grabber is a network monitoring and security analysis tool written in C# using the .NET framework. The application captures live network traffic from a selected network interface and analyzes packets in real time to detect suspicious activity such as:

-ICMP flooding

-TCP SYN flooding

-UDP flooding

-Port scanning behavior

The goal of the project is to demonstrate how packet sniffing, traffic analysis, and security monitoring can be implemented in a lightweight desktop application.
```
### Features
```
Network Packet Capture
Captures real-time network traffic using a packet capture driver.

Traffic Monitoring Dashboard
Displays captured packets including:

Source IP
Destination IP
Protocol
Packet size
Timestamp
Intrusion Detection

Detects abnormal traffic patterns such as:
SYN floods
UDP floods
ICMP floods
Port scanning
Alerts System
Flags suspicious traffic and logs alerts inside the Alerts page.
```

## Simplified File Structure

```
Easy-Packet-Grabber/
├── Backend/
│   ├── AppConfig.cs         # Application configuration
│   ├── DataModel.cs         # Data structures and models
│   └── MainController.cs    # Main controller logic
├── UI/
│   ├── AlertsPage.cs        # Alerts interface
│   ├── BasePage.cs          # Base UI class
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

