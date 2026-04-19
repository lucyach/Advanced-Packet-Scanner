using NetworkMonitor.Backend;

namespace NetworkMonitor.UI;

// Alerts page content
public class AlertsPage : BasePage
{
    private DataGridView? _alertedPacketsGrid;
    private Label? _statsLabel;
    private Label? _statusLabel;
    private Button? _clearButton;
    private ComboBox? _filterCombo;
    private GroupBox? _suspiciousPacketsGroupBox;
    
    private List<string> _allAlertedPackets = new();
    private string _currentFilter = "All";
    
    public AlertsPage(MainController controller, Panel contentPanel) : base(controller, contentPanel)
    {
    }

    public override void LoadContent()
    {
        // Stats label
        _statsLabel = new Label
        {
            Text = "No flagged packets detected",
            Location = new Point(30, 90),
            AutoSize = true,
            Font = new Font("Segoe UI", 10, FontStyle.Regular),
            ForeColor = Color.FromArgb(148, 163, 184),
            BackColor = Color.Transparent
        };
        _contentPanel?.Controls.Add(_statsLabel);

        // Filter dropdown
        var filterLabel = new Label
        {
            Text = "Filter:",
            Location = new Point(30, 130),
            AutoSize = true,
            Font = new Font("Segoe UI", 10, FontStyle.Regular),
            ForeColor = Color.FromArgb(148, 163, 184),
            BackColor = Color.Transparent
        };
        _contentPanel?.Controls.Add(filterLabel);

        _filterCombo = new ComboBox
        {
            Location = new Point(120, 130),
            Size = new Size(150, 25),
            BackColor = Color.FromArgb(55, 65, 81),
            ForeColor = Color.FromArgb(240, 240, 240),
            Font = new Font("Segoe UI", 9),
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _filterCombo.Items.AddRange(new[] { "All", "High Risk", "Medium Risk", "ICMP", "Large Packets", "Small Packets" });
        _filterCombo.SelectedIndex = 0;
        _filterCombo.SelectedIndexChanged += FilterCombo_SelectedIndexChanged;
        _contentPanel?.Controls.Add(_filterCombo);

        // Clear button
        _clearButton = new Button
        {
            Text = "Clear All",
            Location = new Point((_contentPanel?.Width ?? 800) - 150, 130),
            Size = new Size(100, 40),
            BackColor = Color.FromArgb(239, 68, 68),
            ForeColor = Color.White,
            Font = new Font("Segoe UI", 9, FontStyle.Bold),
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand
        };
        _clearButton.FlatAppearance.BorderSize = 0;
        _clearButton.Click += ClearButton_Click;
        _contentPanel?.Controls.Add(_clearButton);

        // Status label
        _statusLabel = new Label
        {
            Text = "",
            Location = new Point(30, (_contentPanel?.Height ?? 600) - 30),
            AutoSize = true,
            Font = new Font("Segoe UI", 9, FontStyle.Regular),
            ForeColor = Color.FromArgb(34, 197, 94),
            BackColor = Color.Transparent,
            Anchor = AnchorStyles.Bottom | AnchorStyles.Left
        };
        _contentPanel?.Controls.Add(_statusLabel);

        // Suspicious Packets GroupBox (Full Section)
        _suspiciousPacketsGroupBox = new GroupBox
        {
            Text = "⚠️ Flagged Network Packets",
            Font = new Font("Segoe UI", 11, FontStyle.Bold),
            Location = new Point(30, 180),
            Size = new Size((_contentPanel?.Width ?? 800) - 60, (_contentPanel?.Height ?? 600) - 200),
            MinimumSize = new Size(400, 300),
            AutoSize = false,
            ForeColor = Color.FromArgb(148, 163, 184),
            BackColor = Color.FromArgb(30, 41, 59),
            Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right
        };

        // Create DataGridView for flagged packets
        _alertedPacketsGrid = new DataGridView
        {
            Location = new Point(15, 50),
            Size = new Size(_suspiciousPacketsGroupBox.Width - 30, _suspiciousPacketsGroupBox.Height - 45),
            Font = new Font("Segoe UI", 9, FontStyle.Regular),
            BackgroundColor = Color.FromArgb(15, 23, 42),
            ForeColor = Color.FromArgb(209, 213, 219),
            GridColor = Color.FromArgb(55, 65, 81),
            BorderStyle = BorderStyle.None,
            AllowUserToAddRows = false,
            AllowUserToDeleteRows = false,
            AllowUserToResizeRows = false,
            ReadOnly = true,
            RowHeadersVisible = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            MultiSelect = false,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
            ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize,
            Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right
        };

        // Configure DataGridView appearance
        _alertedPacketsGrid.DefaultCellStyle.BackColor = Color.FromArgb(15, 23, 42);
        _alertedPacketsGrid.DefaultCellStyle.ForeColor = Color.FromArgb(209, 213, 219);
        _alertedPacketsGrid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(55, 65, 81);
        _alertedPacketsGrid.DefaultCellStyle.SelectionForeColor = Color.FromArgb(240, 240, 240);
        _alertedPacketsGrid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(30, 41, 59);
        _alertedPacketsGrid.ColumnHeadersDefaultCellStyle.ForeColor = Color.FromArgb(148, 163, 184);
        _alertedPacketsGrid.ColumnHeadersDefaultCellStyle.Font = new Font("Segoe UI", 9, FontStyle.Bold);
        _alertedPacketsGrid.EnableHeadersVisualStyles = false;
        _alertedPacketsGrid.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(20, 28, 47);

        // Add columns
        _alertedPacketsGrid.Columns.Add("Timestamp", "Time");
        _alertedPacketsGrid.Columns.Add("Protocol", "Protocol");
        _alertedPacketsGrid.Columns.Add("Source", "Source");
        _alertedPacketsGrid.Columns.Add("Destination", "Destination");
        _alertedPacketsGrid.Columns.Add("Length", "Length");
        _alertedPacketsGrid.Columns.Add("Alert", "⚠");
        _alertedPacketsGrid.Columns.Add("Reason", "Risk Factor");

        // Configure column properties
        _alertedPacketsGrid.Columns["Timestamp"].FillWeight = 15f;
        _alertedPacketsGrid.Columns["Protocol"].FillWeight = 10f;
        _alertedPacketsGrid.Columns["Source"].FillWeight = 20f;
        _alertedPacketsGrid.Columns["Destination"].FillWeight = 20f;
        _alertedPacketsGrid.Columns["Length"].FillWeight = 10f;
        _alertedPacketsGrid.Columns["Alert"].FillWeight = 8f;
        _alertedPacketsGrid.Columns["Reason"].FillWeight = 17f;

        // Configure alert column appearance
        _alertedPacketsGrid.Columns["Alert"].DefaultCellStyle.Alignment = DataGridViewContentAlignment.MiddleCenter;
        _alertedPacketsGrid.Columns["Alert"].DefaultCellStyle.Font = new Font("Segoe UI", 10, FontStyle.Bold);

        _suspiciousPacketsGroupBox.Controls.Add(_alertedPacketsGrid);
        _contentPanel.Controls.Add(_suspiciousPacketsGroupBox);

        // Initial population
        UpdateContent();
    }

    private void FilterCombo_SelectedIndexChanged(object? sender, EventArgs e)
    {
        _currentFilter = _filterCombo?.SelectedItem?.ToString() ?? "All";
        UpdateFlaggedPacketsDisplay();
    }

    private void ClearButton_Click(object? sender, EventArgs e)
    {
        // Clear our local display
        _allAlertedPackets.Clear();
        _alertedPacketsGrid?.Rows.Clear();
        
        _statusLabel!.Text = "All flagged packets cleared";
        _statusLabel.ForeColor = Color.FromArgb(34, 197, 94);

        // Clear status message after 2 seconds
        var timer = new System.Windows.Forms.Timer();
        timer.Interval = 2000;
        timer.Tick += (s, args) =>
        {
            _statusLabel.Text = "";
            timer.Stop();
            timer.Dispose();
        };
        timer.Start();
        
        UpdateStats();
    }

    private void UpdateStats()
    {
        if (_statsLabel == null) return;
        
        int totalFlaggedPackets = _allAlertedPackets.Count;
        int highRiskCount = _allAlertedPackets.Count(p => ParsePacketString(p).AlertStatus.Contains("🚨"));
        int mediumRiskCount = _allAlertedPackets.Count(p => ParsePacketString(p).AlertStatus.Contains("⚠"));

        if (totalFlaggedPackets == 0)
        {
            _statsLabel.Text = "No suspicious packets detected";
            _statsLabel.ForeColor = Color.FromArgb(34, 197, 94);
        }
        else
        {
            string statsText = $"Flagged Packets: {totalFlaggedPackets} | High Risk: {highRiskCount} | Medium Risk: {mediumRiskCount}";
            _statsLabel.Text = statsText;
            _statsLabel.ForeColor = totalFlaggedPackets > 0 ? Color.FromArgb(239, 68, 68) : Color.FromArgb(34, 197, 94);
        }
    }

    public override void UpdateContent()
    {
        if (_alertedPacketsGrid == null) return;

        // Get the latest data from backend
        var dashboardData = _controller.GetDashboardData();

        // Update flagged packets
        foreach (var packet in dashboardData.Packets)
        {
            if (!_allAlertedPackets.Contains(packet))
            {
                var parsedPacket = ParsePacketString(packet);
                if (!string.IsNullOrEmpty(parsedPacket.AlertStatus) && parsedPacket.AlertStatus != "-")
                {
                    _allAlertedPackets.Add(packet);
                }
            }
        }

        // Update display
        UpdateFlaggedPacketsDisplay();
        UpdateStats();
    }

    private void UpdateFlaggedPacketsDisplay()
    {
        if (_alertedPacketsGrid == null) return;

        // Store current scroll position
        bool wasAtBottom = false;
        if (_alertedPacketsGrid.Rows.Count > 0)
        {
            var lastVisibleRow = _alertedPacketsGrid.FirstDisplayedScrollingRowIndex + _alertedPacketsGrid.DisplayedRowCount(false) - 1;
            wasAtBottom = lastVisibleRow >= _alertedPacketsGrid.Rows.Count - 1;
        }

        // Clear and rebuild the flagged packets table
        _alertedPacketsGrid.Rows.Clear();
        
        // Apply filter to packets
        var filteredPackets = _allAlertedPackets.AsEnumerable();
        
        if (_currentFilter != "All")
        {
            filteredPackets = _currentFilter switch
            {
                "High Risk" => filteredPackets.Where(p => ParsePacketString(p).AlertStatus.Contains("🚨")),
                "Medium Risk" => filteredPackets.Where(p => ParsePacketString(p).AlertStatus.Contains("⚠")),
                "ICMP" => filteredPackets.Where(p => ParsePacketString(p).Protocol.ToLower().Contains("icmp")),
                "Large Packets" => filteredPackets.Where(p => int.TryParse(ParsePacketString(p).Length, out int size) && size > 1400),
                "Small Packets" => filteredPackets.Where(p => int.TryParse(ParsePacketString(p).Length, out int size) && size < 20),
                _ => filteredPackets
            };
        }
        
        // Only show the most recent flagged packets (last 50 for performance)
        var recentFlaggedPackets = filteredPackets.TakeLast(50).ToList();
        
        foreach (var packet in recentFlaggedPackets)
        {
            var parsedPacket = ParsePacketString(packet);
            var reason = DetermineAlertReason(parsedPacket);
            
            _alertedPacketsGrid.Rows.Add(parsedPacket.Timestamp, parsedPacket.Protocol, 
                                       parsedPacket.Source, parsedPacket.Destination, 
                                       parsedPacket.Length, parsedPacket.AlertStatus, reason);
            
            // Color code the row
            var lastRowIndex = _alertedPacketsGrid.Rows.Count - 1;
            var protocolCell = _alertedPacketsGrid.Rows[lastRowIndex].Cells["Protocol"];
            var alertCell = _alertedPacketsGrid.Rows[lastRowIndex].Cells["Alert"];
            
            protocolCell.Style.ForeColor = GetProtocolColor(parsedPacket.Protocol);
            protocolCell.Style.Font = new Font("Segoe UI", 9, FontStyle.Bold);
            
            alertCell.Style.ForeColor = parsedPacket.AlertStatus.Contains("🚨") ? 
                Color.FromArgb(239, 68, 68) : Color.FromArgb(245, 158, 11);
        }

        // Auto-scroll to bottom if user was already at bottom
        if (wasAtBottom && _alertedPacketsGrid.Rows.Count > 0)
        {
            _alertedPacketsGrid.FirstDisplayedScrollingRowIndex = Math.Max(0, _alertedPacketsGrid.Rows.Count - _alertedPacketsGrid.DisplayedRowCount(false));
        }
    }

    private (string Timestamp, string Protocol, string Source, string Destination, string Length, string AlertStatus) ParsePacketString(string packetString)
    {
        try
        {
            // Expected format: "HH:mm:ss | PROTOCOL | source → destination | additional_info | length bytes"
            var parts = packetString.Split(" | ");
            
            if (parts.Length >= 4)
            {
                var timestamp = parts[0].Trim();
                var protocol = parts[1].Trim();
                
                // Parse source → destination
                var sourceDest = parts[2].Trim();
                var arrow = sourceDest.IndexOf(" → ");
                var source = arrow > 0 ? sourceDest.Substring(0, arrow).Trim() : sourceDest;
                var destination = arrow > 0 ? sourceDest.Substring(arrow + 3).Trim() : "";
                
                // Get length (usually the last part contains "X bytes")
                var lengthPart = parts[parts.Length - 1].Trim();
                var length = lengthPart.Replace(" bytes", "").Trim();
                
                // Determine alert status based on packet characteristics
                var alertStatus = DetermineAlertStatus(protocol, source, destination, parts);
                
                return (timestamp, protocol, source, destination, length, alertStatus);
            }
            
            // Fallback for unexpected format
            return (DateTime.Now.ToString("HH:mm:ss"), "Unknown", packetString, "", "N/A", "-");
        }
        catch
        {
            // Error parsing, return raw string in source column
            return (DateTime.Now.ToString("HH:mm:ss"), "Error", packetString, "", "N/A", "⚠");
        }
    }

    private string DetermineAlertStatus(string protocol, string source, string destination, string[] packetParts)
    {
        // Check for suspicious patterns that would trigger alerts
        
        // High-risk protocols or unusual traffic
        if (protocol.ToLower().Contains("icmp"))
            return "⚠"; // ICMP can indicate ping floods or network scanning
            
        // Check for private to public traffic (potential data exfiltration)  
        if (IsPrivateIP(source) && !IsPrivateIP(destination))
            return "⚠";
            
        // Check for unusual ports in additional info
        var additionalInfo = packetParts.Length > 4 ? string.Join(" ", packetParts, 3, packetParts.Length - 4) : "";
        if (ContainsSuspiciousPortOrPattern(additionalInfo))
            return "🚨";
            
        // Check for suspicious packet sizes (very large or very small)
        if (packetParts.Length > 0)
        {
            var lastPart = packetParts[packetParts.Length - 1];
            if (int.TryParse(lastPart.Replace(" bytes", "").Trim(), out int size))
            {
                if (size > 1400 || size < 20) // Unusually large or small packets
                    return "⚠";
            }
        }
        
        return "-"; // No alert
    }

    private string DetermineAlertReason((string Timestamp, string Protocol, string Source, string Destination, string Length, string AlertStatus) parsedPacket)
    {
        if (parsedPacket.AlertStatus == "-")
            return "";
            
        var reasons = new List<string>();
        
        if (parsedPacket.Protocol.ToLower().Contains("icmp"))
            reasons.Add("ICMP Traffic");
            
        if (IsPrivateIP(parsedPacket.Source) && !IsPrivateIP(parsedPacket.Destination))
            reasons.Add("Outbound to Public");
            
        if (int.TryParse(parsedPacket.Length, out int size))
        {
            if (size > 1400)
                reasons.Add("Large Packet");
            else if (size < 20)
                reasons.Add("Small Packet");
        }
        
        return reasons.Any() ? string.Join(", ", reasons) : "Suspicious Pattern";
    }

    private bool IsPrivateIP(string ip)
    {
        if (string.IsNullOrEmpty(ip)) return false;
        
        // Remove port if present
        var ipOnly = ip.Split(':')[0];
        
        // Check for private IP ranges
        return ipOnly.StartsWith("192.168.") || 
               ipOnly.StartsWith("10.") || 
               (ipOnly.StartsWith("172.") && ipOnly.Split('.').Length > 1 && 
                int.TryParse(ipOnly.Split('.')[1], out int second) && second >= 16 && second <= 31) ||
               ipOnly.StartsWith("127.") ||
               ipOnly == "localhost";
    }

    private bool ContainsSuspiciousPortOrPattern(string info)
    {
        if (string.IsNullOrEmpty(info)) return false;
        
        var suspiciousPatterns = new[]
        {
            "22", "23", "135", "139", "445", "1433", "3389", // Common attack target ports
            "POST", "DELETE", "PUT", // Potentially suspicious HTTP methods
            "password", "login", "admin", "root" // Suspicious keywords
        };
        
        var lowerInfo = info.ToLower();
        return suspiciousPatterns.Any(pattern => lowerInfo.Contains(pattern.ToLower()));
    }

    private Color GetProtocolColor(string protocol)
    {
        return protocol.ToLower() switch
        {
            "tcp" => Color.FromArgb(34, 197, 94),      // Green
            "udp" => Color.FromArgb(59, 130, 246),      // Blue  
            "icmp" => Color.FromArgb(245, 158, 11),     // Orange
            "http" => Color.FromArgb(139, 92, 246),     // Purple
            "https" => Color.FromArgb(168, 85, 247),    // Purple variant
            "dns" => Color.FromArgb(16, 185, 129),      // Teal
            "arp" => Color.FromArgb(245, 101, 101),     // Light red
            _ => Color.FromArgb(156, 163, 175)          // Gray for others
        };
    }
}