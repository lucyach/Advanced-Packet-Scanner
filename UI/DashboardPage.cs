using NetworkMonitor.Backend;

namespace NetworkMonitor.UI;

// Dashboard page content
public class DashboardPage : BasePage
{
    private GroupBox? _systemInfoGroupBox;
    private Label? _messageLabel;
    private ComboBox? _adapterComboBox;
    private Label? _timeLabel;
    private Label? _timeValueLabel;
    private Label? _computerLabel;
    private Label? _computerValueLabel;
    private GroupBox? _packetsGroupBox;
    private DataGridView? _packetsDataGrid;
    private Label? _statusLabel;
    private Label? _packetCountLabel;
    private Label? _packetRateLabel;
    private int _lastPacketCount = 0;
    private DateTime _lastUpdateTime = DateTime.Now;
    
    // Static field to persist adapter selection across page navigations
    private static int _selectedAdapterIndex = 0;

    public DashboardPage(MainController controller, Panel contentPanel) : base(controller, contentPanel)
    {
    }

    private Label CreateInfoIcon(string tooltipText, Point location)
    {
        var infoIcon = new Label
        {
            Text = "ℹ",
            Location = location,
            Size = new Size(20, 25),
            Font = new Font("Segoe UI", 9, FontStyle.Bold),
            ForeColor = Color.FromArgb(59, 130, 246),
            BackColor = Color.Transparent,
            TextAlign = ContentAlignment.MiddleCenter,
            Cursor = Cursors.Help,
            Anchor = AnchorStyles.Top | AnchorStyles.Left
        };

        var toolTip = new ToolTip
        {
            InitialDelay = 500,
            ReshowDelay = 100,
            ShowAlways = true,
            UseFading = true,
            UseAnimation = true
        };
        toolTip.SetToolTip(infoIcon, tooltipText);

        // Add hover effects
        infoIcon.MouseEnter += (s, e) => infoIcon.ForeColor = Color.FromArgb(37, 99, 235);
        infoIcon.MouseLeave += (s, e) => infoIcon.ForeColor = Color.FromArgb(59, 130, 246);

        return infoIcon;
    }

    public override void LoadContent()
    {
        try
        {
            var data = _controller.GetDashboardData();
            
            // System Information GroupBox
            _systemInfoGroupBox = new GroupBox
            {
                Text = "System Information",
                Font = new Font("Segoe UI", 11, FontStyle.Bold),
                Location = new Point(30, 68),
                Size = new Size(_contentPanel.Width - 60, 200),
                MinimumSize = new Size(400, 200),
                AutoSize = false,
                ForeColor = Color.FromArgb(148, 163, 184),
                BackColor = Color.FromArgb(30, 41, 59),
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            
            // Add all the system info labels (reusing existing code structure)
            _messageLabel = new Label
            {
                Text = "Network Adapter:",
                Location = new Point(20, 38),
                AutoSize = true,
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                ForeColor = Color.FromArgb(148, 163, 184),
                TextAlign = ContentAlignment.MiddleLeft,
                Anchor = AnchorStyles.Top | AnchorStyles.Left
            };
            
            _adapterComboBox = new ComboBox
            {
                Location = new Point(180, 35),
                Size = new Size(500, 30),
                DropDownStyle = ComboBoxStyle.DropDownList,
                BackColor = Color.FromArgb(45, 55, 72),
                ForeColor = Color.FromArgb(240, 240, 240),
                Font = new Font("Segoe UI", 10, FontStyle.Regular),
                FlatStyle = FlatStyle.Flat,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };

            // Populate adapters
            foreach (var dev in MainController.AvailableDevices)
            {
                _adapterComboBox.Items.Add(dev.Description);
            }
            
            // Restore previous selection or set to first adapter if none was selected
            if (_adapterComboBox.Items.Count > 0)
            {
                // Ensure the selected index is valid
                if (_selectedAdapterIndex >= 0 && _selectedAdapterIndex < _adapterComboBox.Items.Count)
                {
                    _adapterComboBox.SelectedIndex = _selectedAdapterIndex;
                }
                else
                {
                    _adapterComboBox.SelectedIndex = 0;
                    _selectedAdapterIndex = 0;
                }
                
                // Only start capture if not already active on this device
                var targetDevice = MainController.AvailableDevices[_selectedAdapterIndex];
                if (MainController.CurrentDevice != targetDevice)
                {
                    MainController.StartCapture(targetDevice);
                }
            }

            _adapterComboBox.SelectedIndexChanged += (s, e) =>
            {
                int index = _adapterComboBox.SelectedIndex;
                if (index >= 0 && index < MainController.AvailableDevices.Count)
                {
                    // Save the selection and switch to selected device only if different
                    _selectedAdapterIndex = index;
                    var targetDevice = MainController.AvailableDevices[index];
                    if (MainController.CurrentDevice != targetDevice)
                    {
                        MainController.StartCapture(targetDevice);
                    }
                }
            };
            
            _timeLabel = new Label
            {
                Text = "Time:",
                Location = new Point(20, 90),
                AutoSize = true,
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                ForeColor = Color.FromArgb(148, 163, 184),
                TextAlign = ContentAlignment.MiddleLeft,
                Anchor = AnchorStyles.Top | AnchorStyles.Left
            };
            
            _timeValueLabel = new Label
            {
                Text = data.CurrentTime,
                Location = new Point(80, 85),
                AutoSize = true,
                MinimumSize = new Size(180, 40),
                MaximumSize = new Size(220, 40),
                AutoEllipsis = true,
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                ForeColor = Color.FromArgb(239, 68, 68),
                BackColor = Color.FromArgb(45, 55, 72),
                TextAlign = ContentAlignment.MiddleCenter,
                BorderStyle = BorderStyle.FixedSingle,
                Anchor = AnchorStyles.Top | AnchorStyles.Left
            };
            
            _computerLabel = new Label
            {
                Text = "Computer:",
                Location = new Point(350, 90),
                AutoSize = true,
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                ForeColor = Color.FromArgb(148, 163, 184),
                TextAlign = ContentAlignment.MiddleLeft,
                Anchor = AnchorStyles.Top | AnchorStyles.Left
            };
            
            _computerValueLabel = new Label
            {
                Text = data.ComputerName,
                Location = new Point(460, 85),
                AutoSize = true,
                MinimumSize = new Size(200, 40),
                MaximumSize = new Size(400, 40),
                AutoEllipsis = true,
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                ForeColor = Color.FromArgb(59, 130, 246),
                BackColor = Color.FromArgb(45, 55, 72),
                TextAlign = ContentAlignment.MiddleCenter,
                BorderStyle = BorderStyle.FixedSingle,
                Anchor = AnchorStyles.Top | AnchorStyles.Left
            };
            
            // Packet Count Label and Value
            var packetCountLabel = new Label
            {
                Text = "Packets Captured:",
                Location = new Point(20, 145),
                AutoSize = true,
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                ForeColor = Color.FromArgb(148, 163, 184),
                TextAlign = ContentAlignment.MiddleLeft,
                Anchor = AnchorStyles.Top | AnchorStyles.Left
            };
            
            _packetCountLabel = new Label
            {
                Text = "0",
                Location = new Point(190, 140),
                AutoSize = true,
                MinimumSize = new Size(120, 40),
                MaximumSize = new Size(180, 40),
                AutoEllipsis = true,
                Font = new Font("Segoe UI", 12, FontStyle.Bold),
                ForeColor = Color.FromArgb(34, 197, 94),
                BackColor = Color.FromArgb(45, 55, 72),
                TextAlign = ContentAlignment.MiddleCenter,
                BorderStyle = BorderStyle.FixedSingle,
                Anchor = AnchorStyles.Top | AnchorStyles.Left
            };
            
            // Packet Rate Label and Value
            var packetRateTextLabel = new Label
            {
                Text = "Rate (pkt/sec):",
                Location = new Point(380, 145),
                AutoSize = true,
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                ForeColor = Color.FromArgb(148, 163, 184),
                TextAlign = ContentAlignment.MiddleLeft,
                Anchor = AnchorStyles.Top | AnchorStyles.Left
            };
            
            _packetRateLabel = new Label
            {
                Text = "0.0",
                Location = new Point(520, 140),
                AutoSize = true,
                MinimumSize = new Size(100, 40),
                MaximumSize = new Size(150, 40),
                AutoEllipsis = true,
                Font = new Font("Segoe UI", 12, FontStyle.Bold),
                ForeColor = Color.FromArgb(239, 68, 68),
                BackColor = Color.FromArgb(45, 55, 72),
                TextAlign = ContentAlignment.MiddleCenter,
                BorderStyle = BorderStyle.FixedSingle,
                Anchor = AnchorStyles.Top | AnchorStyles.Left
            };

            // Security Metrics GroupBox
            var securityMetricsGroupBox = new GroupBox
            {
                Text = "🛡️ Security Metrics",
                Font = new Font("Segoe UI", 11, FontStyle.Bold),
                Location = new Point(30, 282),
                Size = new Size(_contentPanel.Width - 60, 180),
                ForeColor = Color.FromArgb(239, 68, 68),
                BackColor = Color.FromArgb(30, 41, 59),
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };

            // Risk Score Display
            var riskScoreLabel = new Label
            {
                Text = "Average Risk Score:",
                Location = new Point(25, 40),
                AutoSize = true,
                Font = new Font("Segoe UI", 11, FontStyle.Bold),
                ForeColor = Color.FromArgb(148, 163, 184)
            };

            var riskScoreValue = new Label
            {
                Name = "riskScoreValue",
                Text = "0.0",
                Location = new Point(220, 35),
                Size = new Size(90, 40),
                Font = new Font("Segoe UI", 14, FontStyle.Bold),
                ForeColor = Color.FromArgb(34, 197, 94),
                BackColor = Color.FromArgb(45, 55, 72),
                TextAlign = ContentAlignment.MiddleCenter,
                BorderStyle = BorderStyle.FixedSingle
            };

            // High Risk Packets
            var highRiskLabel = new Label
            {
                Text = "High Risk Packets:",
                Location = new Point(360, 40),
                AutoSize = true,
                Font = new Font("Segoe UI", 11, FontStyle.Bold),
                ForeColor = Color.FromArgb(148, 163, 184)
            };

            var highRiskValue = new Label
            {
                Name = "highRiskValue",
                Text = "0",
                Location = new Point(545, 35),
                Size = new Size(80, 40),
                Font = new Font("Segoe UI", 14, FontStyle.Bold),
                ForeColor = Color.FromArgb(239, 68, 68),
                BackColor = Color.FromArgb(45, 55, 72),
                TextAlign = ContentAlignment.MiddleCenter,
                BorderStyle = BorderStyle.FixedSingle
            };

            // Protocol Breakdown - second row
            var protocolBreakdownLabel = new Label
            {
                Text = "Top Protocols:",
                Location = new Point(25, 100),
                AutoSize = true,
                Font = new Font("Segoe UI", 11, FontStyle.Bold),
                ForeColor = Color.FromArgb(148, 163, 184)
            };

            var protocolBreakdownValue = new Label
            {
                Name = "protocolBreakdownValue",
                Text = "No data",
                Location = new Point(170, 100),
                Size = new Size(700, 30),
                Font = new Font("Segoe UI", 10, FontStyle.Regular),
                ForeColor = Color.FromArgb(209, 213, 219),
                AutoEllipsis = true
            };

            securityMetricsGroupBox.Controls.Add(riskScoreLabel);
            securityMetricsGroupBox.Controls.Add(riskScoreValue);
            securityMetricsGroupBox.Controls.Add(highRiskLabel);
            securityMetricsGroupBox.Controls.Add(highRiskValue);
            securityMetricsGroupBox.Controls.Add(protocolBreakdownLabel);
            securityMetricsGroupBox.Controls.Add(protocolBreakdownValue);

            // Add labels to system info group box
            _systemInfoGroupBox.Controls.Add(_messageLabel);
            _systemInfoGroupBox.Controls.Add(_adapterComboBox);
            _systemInfoGroupBox.Controls.Add(_timeLabel);
            _systemInfoGroupBox.Controls.Add(_timeValueLabel);
            _systemInfoGroupBox.Controls.Add(_computerLabel);
            _systemInfoGroupBox.Controls.Add(_computerValueLabel);
            _systemInfoGroupBox.Controls.Add(packetCountLabel);
            _systemInfoGroupBox.Controls.Add(_packetCountLabel);
            _systemInfoGroupBox.Controls.Add(packetRateTextLabel);
            _systemInfoGroupBox.Controls.Add(_packetRateLabel);
            
            // Packets GroupBox - moved down to accommodate security metrics
            _packetsGroupBox = new GroupBox
            {
                Text = "Enhanced Packet Analysis",
                Font = new Font("Segoe UI", 11, FontStyle.Bold),
                Location = new Point(30, 476),
                Size = new Size(_contentPanel.Width - 60, _contentPanel.Height - 510),
                MinimumSize = new Size(400, 200),
                AutoSize = false,
                ForeColor = Color.FromArgb(148, 163, 184),
                BackColor = Color.FromArgb(30, 41, 59),
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom
            };
            
            _packetsDataGrid = new DataGridView
            {
                Location = new Point(15, 48),
                Size = new Size(_packetsGroupBox.Width - 30, _packetsGroupBox.Height - 55),
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
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom
            };

            // Configure DataGridView appearance
            _packetsDataGrid.DefaultCellStyle.BackColor = Color.FromArgb(15, 23, 42);
            _packetsDataGrid.DefaultCellStyle.ForeColor = Color.FromArgb(209, 213, 219);
            _packetsDataGrid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(55, 65, 81);
            _packetsDataGrid.DefaultCellStyle.SelectionForeColor = Color.FromArgb(240, 240, 240);
            _packetsDataGrid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(30, 41, 59);
            _packetsDataGrid.ColumnHeadersDefaultCellStyle.ForeColor = Color.FromArgb(148, 163, 184);
            _packetsDataGrid.ColumnHeadersDefaultCellStyle.Font = new Font("Segoe UI", 9, FontStyle.Bold);
            _packetsDataGrid.EnableHeadersVisualStyles = false;
            
            // Add columns for enhanced packet information
            _packetsDataGrid.Columns.Add("Timestamp", "Time");
            _packetsDataGrid.Columns.Add("Risk", "Risk");
            _packetsDataGrid.Columns.Add("Protocol", "Protocol");
            _packetsDataGrid.Columns.Add("Source", "Source");
            _packetsDataGrid.Columns.Add("Destination", "Destination");
            _packetsDataGrid.Columns.Add("Details", "Details");
            _packetsDataGrid.Columns.Add("Size", "Size");
            _packetsDataGrid.Columns.Add("Flags", "Security Flags");
            
            // Configure column properties for enhanced display
            _packetsDataGrid.Columns["Timestamp"].FillWeight = 10f;
            _packetsDataGrid.Columns["Risk"].FillWeight = 5f;
            _packetsDataGrid.Columns["Protocol"].FillWeight = 10f;
            _packetsDataGrid.Columns["Source"].FillWeight = 17f;
            _packetsDataGrid.Columns["Destination"].FillWeight = 17f;
            _packetsDataGrid.Columns["Details"].FillWeight = 20f;
            _packetsDataGrid.Columns["Size"].FillWeight = 6f;
            _packetsDataGrid.Columns["Flags"].FillWeight = 15f;
            
            // Configure risk column appearance
            _packetsDataGrid.Columns["Risk"].DefaultCellStyle.Alignment = DataGridViewContentAlignment.MiddleCenter;
            _packetsDataGrid.Columns["Risk"].DefaultCellStyle.Font = new Font("Segoe UI", 10, FontStyle.Bold);
            
            // Configure flags column appearance
            _packetsDataGrid.Columns["Flags"].DefaultCellStyle.Font = new Font("Segoe UI", 8, FontStyle.Regular);
            _packetsDataGrid.Columns["Flags"].DefaultCellStyle.WrapMode = DataGridViewTriState.True;
            
            // Set alternating row colors for better readability
            _packetsDataGrid.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(20, 28, 47);

            // Create header panel with info icons positioned above DataGridView columns
            var headerPanel = new Panel
            {
                Location = new Point(15, 25),
                Size = new Size(_packetsGroupBox.Width - 30, 20),
                BackColor = Color.Transparent,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };

            // Calculate column positions based on DataGridView column widths  
            int timeWidth = (int)(headerPanel.Width * 0.101f);
            int riskWidth = (int)(headerPanel.Width * 0.067f);
            int protocolWidth = (int)(headerPanel.Width * 0.084f);
            int sourceWidth = (int)(headerPanel.Width * 0.151f);
            int destWidth = (int)(headerPanel.Width * 0.151f);
            int detailsWidth = (int)(headerPanel.Width * 0.210f);
            int sizeWidth = (int)(headerPanel.Width * 0.067f);

            // Add info icons positioned above each column
            var protocolInfoIcon = CreateInfoIcon(
                "Protocol Types:\n\n" +
                "• TCP: Transmission Control Protocol - reliable, connection-based protocol that ensures packets arrive in order without loss. Used for web browsing and file transfers.\n\n" +
                "• UDP: User Datagram Protocol - fast, connectionless protocol without delivery confirmation. Used for streaming and gaming where speed is more important than reliability.\n\n" +
                "• ICMP: Internet Control Message Protocol - used for network diagnostics and error messages.\n\n" +
                "• HTTP: Hypertext Transfer Protocol - used for communication between browsers and servers for loading web pages.",
                new Point(timeWidth + riskWidth + protocolWidth/2 - 10, 0)
            );

            var sourceInfoIcon = CreateInfoIcon(
                "Source: The source refers to the IP address of the original device that sent out the packet. Used to identify where the data originated from within the network.",
                new Point(timeWidth + riskWidth + protocolWidth + sourceWidth/2 - 10, 0)
            );

            var destInfoIcon = CreateInfoIcon(
                "Destination: The destination refers to the IP address of the device to which the packet was sent. Used to identify who the intended recipient of the data was.",
                new Point(timeWidth + riskWidth + protocolWidth + sourceWidth + destWidth/2 - 10, 0)
            );

            var sizeInfoIcon = CreateInfoIcon(
                "Size: The size of the packet refers to the number of bytes of information the packet contains. A standard range is anywhere between 20 and 1500 bytes.",
                new Point(timeWidth + riskWidth + protocolWidth + sourceWidth + destWidth + detailsWidth + sizeWidth/2 - 10, 0)
            );

            headerPanel.Controls.Add(protocolInfoIcon);
            headerPanel.Controls.Add(sourceInfoIcon);
            headerPanel.Controls.Add(destInfoIcon);
            headerPanel.Controls.Add(sizeInfoIcon);

            // Adjust DataGridView position to make room for header panel
            _packetsDataGrid.Location = new Point(15, 48);
            _packetsDataGrid.Size = new Size(_packetsGroupBox.Width - 30, _packetsGroupBox.Height - 55);

            // Add Clear button for packets
            var clearButton = new Button
            {
                Text = "Clear Packets",
                Location = new Point(_packetsGroupBox.Width - 240, -1),
                Size = new Size(105, 26),
                BackColor = Color.FromArgb(239, 68, 68),
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 9, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                Anchor = AnchorStyles.Top | AnchorStyles.Right
            };
            clearButton.FlatAppearance.BorderSize = 0;
            clearButton.Click += (s, e) =>
            {
                MainController.ClearPackets();
                _packetsDataGrid.Rows.Clear();
            };
            
            // Add Save Packets button
            var savePacketsButton = new Button
            {
                Text = "Save Packets",
                Location = new Point(_packetsGroupBox.Width - 125, -1),
                Size = new Size(110, 26),
                BackColor = Color.FromArgb(59, 130, 246),
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 9, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                Anchor = AnchorStyles.Top | AnchorStyles.Right
            };
            savePacketsButton.FlatAppearance.BorderSize = 0;
            savePacketsButton.Click += (s, e) =>
            {
                try
                {
                    int packetCount = AppConfig.Instance.PacketSaveCount;
                    bool success = MainController.SaveLastPacketsToFile(packetCount, null, false);
                    
                    if (success)
                    {
                        MessageBox.Show($"Successfully saved {packetCount} packets to Downloads folder!", 
                                      "Save Successful", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    else
                    {
                        MessageBox.Show("Failed to save packets. Please check console for errors.", 
                                      "Save Failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error saving packets: {ex.Message}", 
                                  "Save Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            };
            
            _packetsGroupBox.Controls.Add(headerPanel);
            _packetsGroupBox.Controls.Add(_packetsDataGrid);
            _packetsGroupBox.Controls.Add(clearButton);
            _packetsGroupBox.Controls.Add(savePacketsButton);
            
            // Add status label
            _statusLabel = new Label
            {
                Text = $"Last updated: {DateTime.Now:HH:mm:ss}",
                Location = new Point(30, _contentPanel.Height - 30),
                AutoSize = true,
                MaximumSize = new Size(_contentPanel.Width - 60, 30),
                AutoEllipsis = true,
                Font = new Font("Segoe UI", 9, FontStyle.Italic),
                ForeColor = Color.FromArgb(148, 163, 184),
                TextAlign = ContentAlignment.MiddleCenter,
                Anchor = AnchorStyles.Bottom | AnchorStyles.Left
            };
            
            // Add controls to content panel
            _contentPanel?.Controls.Add(_systemInfoGroupBox);
            _contentPanel?.Controls.Add(securityMetricsGroupBox);
            _contentPanel?.Controls.Add(_packetsGroupBox);
            _contentPanel?.Controls.Add(_statusLabel);
        }
        catch (Exception ex)
        {
            var errorLabel = new Label
            {
                Text = $"Error loading dashboard data: {ex.Message}",
                Location = new Point(30, 90),
                AutoSize = true,
                Font = new Font("Segoe UI", 10, FontStyle.Regular),
                ForeColor = Color.FromArgb(239, 68, 68),
                BackColor = Color.Transparent
            };
            _contentPanel?.Controls.Add(errorLabel);
        }
    }

    public override void UpdateContent()
    {
        // Only update if controls exist
        if (_timeValueLabel == null || 
            _packetsDataGrid == null)
            return;

        try
        {
            var data = _controller.GetDashboardData();
            
            // Efficiently update system info without recreating controls
            _timeValueLabel.Text = data.CurrentTime;
            
            // Update packet statistics
            var currentPacketCount = data.TotalPacketsCaptured;
            if (_packetCountLabel != null)
            {
                _packetCountLabel.Text = currentPacketCount.ToString();
            }
            
            // Calculate packet rate
            var now = DateTime.Now;
            var timeDiff = (now - _lastUpdateTime).TotalSeconds;
            if (timeDiff >= 1.0) // Update rate every second
            {
                var packetDiff = currentPacketCount - _lastPacketCount;
                var rate = packetDiff / timeDiff;
                if (_packetRateLabel != null)
                {
                    _packetRateLabel.Text = rate.ToString("F1");
                }
                _lastPacketCount = currentPacketCount;
                _lastUpdateTime = now;
            }
            
            // Smart packet table updates - prioritize enhanced packets if available
            if (data.EnhancedPackets.Any())
            {
                UpdateEnhancedPacketDisplay(data);
            }
            else if (data.Packets.Any() && (_packetsDataGrid.Rows.Count == 0 || HasNewPackets(data.Packets)))
            {
                UpdateLegacyPacketDisplay(data);
            }

            // Update security metrics
            UpdateSecurityMetrics(data);
            
            // Update status with more detailed information
            if (_statusLabel != null)
            {
                var selectedAdapter = _adapterComboBox?.SelectedIndex >= 0 ? 
                    MainController.AvailableDevices[_adapterComboBox.SelectedIndex].Description : "No adapter selected";
                var statusColor = data.Message.Contains("Monitoring") ? Color.FromArgb(34, 197, 94) : Color.FromArgb(239, 68, 68);
                _statusLabel.ForeColor = statusColor;
                _statusLabel.Text = $"🔄 Enhanced DPI Active • Last: {DateTime.Now:HH:mm:ss.fff} • Packets: {_packetsDataGrid.Rows.Count} • {data.Message}";
            }
        }
        catch (Exception ex)
        {
            if (_statusLabel != null)
            {
                _statusLabel.ForeColor = Color.FromArgb(239, 68, 68);
                _statusLabel.Text = $"❌ Error: {ex.Message}";
            }
        }
    }

    private void UpdateEnhancedPacketDisplay(DataModel data)
    {
        if (_packetsDataGrid == null) return;

        // Store current scroll position
        bool wasAtBottom = false;
        if (_packetsDataGrid.Rows.Count > 0)
        {
            var lastVisibleRow = _packetsDataGrid.FirstDisplayedScrollingRowIndex + _packetsDataGrid.DisplayedRowCount(false) - 1;
            wasAtBottom = lastVisibleRow >= _packetsDataGrid.Rows.Count - 1;
        }

        // Clear and update with enhanced packet information
        _packetsDataGrid.Rows.Clear();
        foreach (var packet in data.EnhancedPackets.TakeLast(100))
        {
            var riskIcon = GetRiskIcon(packet.RiskScore);
            var flagsDisplay = string.Join(", ", packet.SecurityFlags.Take(2));
            if (packet.SecurityFlags.Count > 2)
                flagsDisplay += $" (+{packet.SecurityFlags.Count - 2} more)";

            _packetsDataGrid.Rows.Add(
                packet.Timestamp.ToString("HH:mm:ss.fff"),
                riskIcon,
                packet.Protocol,
                packet.SourceIP,
                packet.DestinationIP,
                TruncateString(packet.Details, 50),
                packet.Size.ToString(),
                flagsDisplay
            );

            // Apply enhanced styling
            var lastRowIndex = _packetsDataGrid.Rows.Count - 1;
            var row = _packetsDataGrid.Rows[lastRowIndex];

            // Color code risk level
            var riskCell = row.Cells["Risk"];
            riskCell.Style.ForeColor = GetRiskColor(packet.RiskScore);
            riskCell.Style.Font = new Font("Segoe UI", 10, FontStyle.Bold);

            // Color code protocol
            var protocolCell = row.Cells["Protocol"];
            protocolCell.Style.ForeColor = GetProtocolColor(packet.Protocol);
            protocolCell.Style.Font = new Font("Segoe UI", 9, FontStyle.Bold);

            // Color code security flags
            var flagsCell = row.Cells["Flags"];
            if (packet.SecurityFlags.Any())
            {
                flagsCell.Style.ForeColor = packet.RiskScore >= 50 ? 
                    Color.FromArgb(239, 68, 68) : Color.FromArgb(245, 158, 11);
            }

            // Highlight high-risk rows
            if (packet.RiskScore >= 50)
            {
                row.DefaultCellStyle.BackColor = Color.FromArgb(40, 20, 20);
            }
            else if (packet.RiskScore >= 25)
            {
                row.DefaultCellStyle.BackColor = Color.FromArgb(40, 35, 20);
            }
        }

        // Auto-scroll to bottom if user was already at bottom
        if (wasAtBottom && _packetsDataGrid.Rows.Count > 0)
        {
            _packetsDataGrid.FirstDisplayedScrollingRowIndex = Math.Max(0, _packetsDataGrid.Rows.Count - _packetsDataGrid.DisplayedRowCount(false));
        }
    }

    private void UpdateLegacyPacketDisplay(DataModel data)
    {
        // Fallback to legacy packet display for compatibility
        _packetsDataGrid.Rows.Clear();
        foreach (var packet in data.Packets)
        {
            var parsedPacket = ParsePacketString(packet);
            _packetsDataGrid.Rows.Add(
                parsedPacket.Timestamp, 
                "🟢", // Default low risk for legacy packets
                parsedPacket.Protocol, 
                parsedPacket.Source, 
                parsedPacket.Destination, 
                parsedPacket.Protocol, // Use protocol as details for legacy
                parsedPacket.Size, 
                parsedPacket.AlertStatus == "-" ? "" : parsedPacket.AlertStatus
            );
        }
    }

    private void UpdateSecurityMetrics(DataModel data)
    {
        if (data.Statistics == null) return;

        var stats = data.Statistics;
        
        // Update risk score display
        var riskScoreControl = FindControlByName(_systemInfoGroupBox?.Parent, "riskScoreValue") as Label;
        if (riskScoreControl != null)
        {
            riskScoreControl.Text = stats.AverageRiskScore.ToString("F1");
            riskScoreControl.ForeColor = GetRiskColor((int)stats.AverageRiskScore);
        }

        // Update high risk count
        var highRiskControl = FindControlByName(_systemInfoGroupBox?.Parent, "highRiskValue") as Label;
        if (highRiskControl != null)
        {
            highRiskControl.Text = stats.HighRiskPackets.ToString();
        }

        // Update protocol breakdown
        var protocolControl = FindControlByName(_systemInfoGroupBox?.Parent, "protocolBreakdownValue") as Label;
        if (protocolControl != null && stats.ProtocolCounts.Any())
        {
            var topProtocols = stats.ProtocolCounts
                .OrderByDescending(kvp => kvp.Value)
                .Take(4)
                .Select(kvp => $"{kvp.Key}({kvp.Value})")
                .ToArray();
            protocolControl.Text = string.Join(", ", topProtocols);
        }
    }

    private Control? FindControlByName(Control? parent, string name)
    {
        if (parent == null) return null;
        
        foreach (Control control in parent.Controls)
        {
            if (control.Name == name) return control;
            var found = FindControlByName(control, name);
            if (found != null) return found;
        }
        return null;
    }

    private string GetRiskIcon(int riskScore)
    {
        return riskScore switch
        {
            >= 75 => "🔴",
            >= 50 => "🟠",
            >= 25 => "🟡",
            >= 10 => "🔵",
            _ => "🟢"
        };
    }

    private Color GetRiskColor(int riskScore)
    {
        return riskScore switch
        {
            >= 75 => Color.FromArgb(220, 38, 38),
            >= 50 => Color.FromArgb(234, 88, 12),
            >= 25 => Color.FromArgb(245, 158, 11),
            >= 10 => Color.FromArgb(59, 130, 246),
            _ => Color.FromArgb(34, 197, 94)
        };
    }

    private string TruncateString(string input, int maxLength)
    {
        if (string.IsNullOrEmpty(input) || input.Length <= maxLength)
            return input ?? "";
        return input.Substring(0, maxLength) + "...";
    }
    
    private bool HasNewPackets(List<string> newPackets)
    {
        if (_packetsDataGrid == null || _packetsDataGrid.Rows.Count == 0)
            return true;
            
        if (newPackets.Count != _packetsDataGrid.Rows.Count)
            return true;
            
        // Check if the last packet is different (simple optimization)
        var lastRowIndex = _packetsDataGrid.Rows.Count - 1;
        var lastDisplayedPacket = $"{_packetsDataGrid.Rows[lastRowIndex].Cells["Timestamp"].Value} | " +
                                 $"{_packetsDataGrid.Rows[lastRowIndex].Cells["Protocol"].Value} | " +
                                 $"{_packetsDataGrid.Rows[lastRowIndex].Cells["Source"].Value} → " +
                                 $"{_packetsDataGrid.Rows[lastRowIndex].Cells["Destination"].Value}";
        return !newPackets.Last().Contains(lastDisplayedPacket);
    }
    
    private (string Timestamp, string Protocol, string Source, string Destination, string Size, string AlertStatus) ParsePacketString(string packetString)
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
                
                // Get size (usually the last part contains "X bytes")
                var sizePart = parts[parts.Length - 1].Trim();
                var size = sizePart.Replace(" bytes", "").Trim();
                
                // Determine alert status based on packet characteristics
                var alertStatus = DetermineAlertStatus(protocol, source, destination, parts);
                
                return (timestamp, protocol, source, destination, size, alertStatus);
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