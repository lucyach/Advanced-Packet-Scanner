using NetworkMonitor.Backend;

namespace NetworkMonitor.UI;

// Options page content
public class OptionsPage : BasePage
{
    private NumericUpDown packetsLimitControl = new();
    private NumericUpDown alertsLimitControl = new();
    private NumericUpDown packetSaveCountControl = new();
    private Button saveButton = new();
    private Label statusLabel = new();
    
    public OptionsPage(MainController controller, Panel contentPanel) : base(controller, contentPanel)
    {
    }

    public override void LoadContent()
    {
        // Title
        var titleLabel = new Label
        {
            Text = "Options",
            Location = new Point(30, 30),
            AutoSize = true,
            Font = new Font("Segoe UI", 18, FontStyle.Bold),
            ForeColor = Color.FromArgb(240, 240, 240),
            BackColor = Color.Transparent
        };
        _contentPanel?.Controls.Add(titleLabel);

        // Packet limit section
        var packetsLabel = new Label
        {
            Text = "Maximum Packets to Store:",
            Location = new Point(30, 90),
            AutoSize = true,
            Font = new Font("Segoe UI", 11, FontStyle.Regular),
            ForeColor = Color.FromArgb(148, 163, 184),
            BackColor = Color.Transparent
        };
        _contentPanel?.Controls.Add(packetsLabel);

        var packetsHelpLabel = new Label
        {
            Text = "When this limit is reached, older packets will be automatically deleted",
            Location = new Point(30, 125),
            AutoSize = true,
            Font = new Font("Segoe UI", 9, FontStyle.Regular),
            ForeColor = Color.FromArgb(100, 115, 134),
            BackColor = Color.Transparent
        };
        _contentPanel?.Controls.Add(packetsHelpLabel);

        packetsLimitControl = new NumericUpDown
        {
            Location = new Point(40, 160),
            Size = new Size(150, 35),
            Minimum = 100,
            Maximum = 50000,
            Value = AppConfig.Instance.MaxPackets,
            BackColor = Color.FromArgb(55, 65, 81),
            ForeColor = Color.FromArgb(240, 240, 240),
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Segoe UI", 10)
        };
        _contentPanel?.Controls.Add(packetsLimitControl);

        // Alert limit section
        var alertsLabel = new Label
        {
            Text = "Maximum Alerts to Store:",
            Location = new Point(30, 210),
            AutoSize = true,
            Font = new Font("Segoe UI", 11, FontStyle.Regular),
            ForeColor = Color.FromArgb(148, 163, 184),
            BackColor = Color.Transparent
        };
        _contentPanel?.Controls.Add(alertsLabel);

        var alertsHelpLabel = new Label
        {
            Text = "When this limit is reached, older alerts will be automatically deleted",
            Location = new Point(30, 245),
            AutoSize = true,
            Font = new Font("Segoe UI", 9, FontStyle.Regular),
            ForeColor = Color.FromArgb(100, 115, 134),
            BackColor = Color.Transparent
        };
        _contentPanel?.Controls.Add(alertsHelpLabel);

        alertsLimitControl = new NumericUpDown
        {
            Location = new Point(35, 280),
            Size = new Size(150, 35),
            Minimum = 50,
            Maximum = 5000,
            Value = AppConfig.Instance.MaxAlerts,
            BackColor = Color.FromArgb(55, 65, 81),
            ForeColor = Color.FromArgb(240, 240, 240),
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Segoe UI", 10)
        };
        _contentPanel?.Controls.Add(alertsLimitControl);

        // Packet save count section
        var packetSaveLabel = new Label
        {
            Text = "Default Packets to Save:",
            Location = new Point(30, 330),
            AutoSize = true,
            Font = new Font("Segoe UI", 11, FontStyle.Regular),
            ForeColor = Color.FromArgb(148, 163, 184),
            BackColor = Color.Transparent
        };
        _contentPanel?.Controls.Add(packetSaveLabel);

        var packetSaveHelpLabel = new Label
        {
            Text = "Number of most recent packets to save when using Save Packets button",
            Location = new Point(30, 365),
            AutoSize = true,
            Font = new Font("Segoe UI", 9, FontStyle.Regular),
            ForeColor = Color.FromArgb(100, 115, 134),
            BackColor = Color.Transparent
        };
        _contentPanel?.Controls.Add(packetSaveHelpLabel);

        packetSaveCountControl = new NumericUpDown
        {
            Location = new Point(35, 400),
            Size = new Size(150, 35),
            Minimum = 1,
            Maximum = 10000,
            Value = AppConfig.Instance.PacketSaveCount,
            BackColor = Color.FromArgb(55, 65, 81),
            ForeColor = Color.FromArgb(240, 240, 240),
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Segoe UI", 10)
        };
        _contentPanel?.Controls.Add(packetSaveCountControl);

        // Save button
        saveButton = new Button
        {
            Text = "Save Settings",
            Location = new Point(35, 460),
            Size = new Size(120, 55),
            BackColor = Color.FromArgb(34, 197, 94),
            ForeColor = Color.White,
            Font = new Font("Segoe UI", 10, FontStyle.Bold),
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand
        };
        saveButton.FlatAppearance.BorderSize = 0;
        saveButton.Click += SaveButton_Click;
        _contentPanel?.Controls.Add(saveButton);

        // Status label
        statusLabel = new Label
        {
            Text = "",
            Location = new Point(35, 520),
            AutoSize = true,
            Font = new Font("Segoe UI", 9, FontStyle.Regular),
            ForeColor = Color.FromArgb(148, 163, 184),
            BackColor = Color.Transparent
        };
        _contentPanel?.Controls.Add(statusLabel);

        // Current values display
        var currentValuesLabel = new Label
        {
            Text = $"Current: {AppConfig.Instance.MaxPackets} packets, {AppConfig.Instance.MaxAlerts} alerts, save {AppConfig.Instance.PacketSaveCount} packets",
            Location = new Point(200, 405),
            AutoSize = true,
            Font = new Font("Segoe UI", 9, FontStyle.Italic),
            ForeColor = Color.FromArgb(100, 115, 134),
            BackColor = Color.Transparent
        };
        _contentPanel?.Controls.Add(currentValuesLabel);
    }

    private void SaveButton_Click(object? sender, EventArgs e)
    {
        try
        {
            int maxPackets = (int)packetsLimitControl.Value;
            int maxAlerts = (int)alertsLimitControl.Value;
            int packetSaveCount = (int)packetSaveCountControl.Value;
            
            AppConfig.Instance.UpdateLimits(maxPackets, maxAlerts);
            AppConfig.Instance.UpdatePacketSaveCount(packetSaveCount);
            
            statusLabel.Text = "Settings saved successfully!";
            statusLabel.ForeColor = Color.FromArgb(34, 197, 94);

            // Clear status message after 3 seconds
            var timer = new System.Windows.Forms.Timer();
            timer.Interval = 3000;
            timer.Tick += (s, args) =>
            {
                statusLabel.Text = "";
                timer.Stop();
                timer.Dispose();
            };
            timer.Start();
        }
        catch (Exception ex)
        {
            statusLabel.Text = $"Error saving settings: {ex.Message}";
            statusLabel.ForeColor = Color.FromArgb(239, 68, 68);
        }
    }
}