using NetworkMonitor.Backend;

namespace NetworkMonitor.UI;

// This is the main popup window form - replicating the HTML functionality
public partial class MainForm : Form
{
    private readonly MainController _controller;
    private System.Windows.Forms.Timer? _refreshTimer;
    private string _currentPage = "Dashboard"; // Track current page
    private BasePage? _currentPageInstance;

    // UI Controls
    private Panel? _sidebarPanel;
    private Button? _dashboardButton;
    private Button? _alertsButton;
    private Button? _optionsButton;
    private Panel? _contentPanel;
    private Label? _titleLabel;
    private Button? _refreshButton;

    // Page instances
    private DashboardPage? _dashboardPage;
    private AlertsPage? _alertsPage;
    private OptionsPage? _optionsPage;

    public MainForm()
    {
        _controller = new MainController();
        InitializeComponent();
        InitializePages();
        NavigateToPage("Dashboard"); // Load dashboard by default
        SetupRefreshTimer();
    }

    private void InitializeComponent()
    {
        // Form properties - Dark mode with sidebar layout
        this.Text = "Network Monitor Dashboard";
        this.WindowState = FormWindowState.Normal;
        this.StartPosition = FormStartPosition.CenterScreen;
        this.FormBorderStyle = FormBorderStyle.Sizable;
        this.MaximizeBox = true;
        this.MinimizeBox = true;
        this.TopMost = false;
        this.BackColor = Color.FromArgb(15, 23, 42); // Dark blue background
        this.Font = new Font("Segoe UI", 9F, FontStyle.Regular);
        this.AutoScaleMode = AutoScaleMode.Font;
        this.AutoSize = false;

        // Set a very large size
        this.Size = new Size(1400, 1000);
        this.MinimumSize = new Size(1200, 800);

        // Create Sidebar Panel
        _sidebarPanel = new Panel
        {
            Location = new Point(0, 0),
            Size = new Size(250, this.ClientSize.Height),
            BackColor = Color.FromArgb(8, 14, 30), // Darker blue for sidebar
            Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left
        };

        // Dashboard Button
        _dashboardButton = new Button
        {
            Text = "Dashboard",
            Location = new Point(15, 50),
            Size = new Size(220, 60),
            Font = new Font("Segoe UI", 11, FontStyle.Regular),
            BackColor = Color.FromArgb(59, 130, 246), // Active blue
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            TextAlign = ContentAlignment.MiddleLeft,
            Padding = new Padding(10, 0, 0, 0)
        };
        _dashboardButton.FlatAppearance.BorderSize = 0;
        _dashboardButton.Click += (s, e) => NavigateToPage("Dashboard");

        // Alerts Button
        _alertsButton = new Button
        {
            Text = "Alerts",
            Location = new Point(15, 120),
            Size = new Size(220, 60),
            Font = new Font("Segoe UI", 11, FontStyle.Regular),
            BackColor = Color.FromArgb(30, 41, 59), // Inactive dark blue
            ForeColor = Color.FromArgb(148, 163, 184), // Gray text
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            TextAlign = ContentAlignment.MiddleLeft,
            Padding = new Padding(10, 0, 0, 0)
        };
        _alertsButton.FlatAppearance.BorderSize = 0;
        _alertsButton.Click += (s, e) => NavigateToPage("Alerts");

        // Options Button
        _optionsButton = new Button
        {
            Text = "Options",
            Location = new Point(15, 190),
            Size = new Size(220, 60),
            Font = new Font("Segoe UI", 11, FontStyle.Regular),
            BackColor = Color.FromArgb(30, 41, 59),
            ForeColor = Color.FromArgb(148, 163, 184),
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            TextAlign = ContentAlignment.MiddleLeft,
            Padding = new Padding(10, 0, 0, 0)
        };
        _optionsButton.FlatAppearance.BorderSize = 0;
        _optionsButton.Click += (s, e) => NavigateToPage("Options");

        // Main Content Panel
        _contentPanel = new Panel
        {
            Location = new Point(250, 0),
            Size = new Size(this.ClientSize.Width - 250, this.ClientSize.Height),
            BackColor = Color.FromArgb(15, 23, 42),
            Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right
        };

        // Refresh Button
        _refreshButton = new Button
        {
            Text = "🔄 Refresh",
            Location = new Point(15, _sidebarPanel.Height - 60),
            Size = new Size(220, 60),
            Font = new Font("Segoe UI", 11, FontStyle.Bold),
            BackColor = Color.FromArgb(34, 197, 94), // Green
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            TextAlign = ContentAlignment.MiddleLeft,
            Padding = new Padding(10, 0, 0, 0),
            Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right
        };
        _refreshButton.FlatAppearance.BorderSize = 0;
        _refreshButton.Click += RefreshButton_Click;

        // Add controls to sidebar
        _sidebarPanel.Controls.Add(_dashboardButton);
        _sidebarPanel.Controls.Add(_alertsButton);
        _sidebarPanel.Controls.Add(_optionsButton);
        _sidebarPanel.Controls.Add(_refreshButton);

        // Add main panels to form
        this.Controls.Add(_sidebarPanel);
        this.Controls.Add(_contentPanel);
    }

    private void InitializePages()
    {
        _dashboardPage = new DashboardPage(_controller, _contentPanel!);
        _alertsPage = new AlertsPage(_controller, _contentPanel!);
        _optionsPage = new OptionsPage(_controller, _contentPanel!);
    }

    private void NavigateToPage(string pageName)
    {
        _currentPage = pageName;
        UpdateButtonStates();
        LoadPageContent();
    }

    private void UpdateButtonStates()
    {
        var buttons = new[] { _dashboardButton, _alertsButton, _optionsButton };
        foreach (var button in buttons.Where(b => b != null))
        {
            button!.BackColor = Color.FromArgb(30, 41, 59);
            button.ForeColor = Color.FromArgb(148, 163, 184);
        }

        Button? activeButton = _currentPage switch
        {
            "Dashboard" => _dashboardButton,
            "Alerts" => _alertsButton,
            "Options" => _optionsButton,
            _ => _dashboardButton
        };

        if (activeButton != null)
        {
            activeButton.BackColor = Color.FromArgb(59, 130, 246);
            activeButton.ForeColor = Color.White;
        }
    }

    private void LoadPageContent()
    {
        _contentPanel?.Controls.Clear();
        _currentPageInstance?.OnDeactivated();

        _titleLabel = new Label
        {
            Text = $"{_currentPage}",
            Font = new Font("Segoe UI", 18, FontStyle.Bold),
            Location = new Point(30, 20),
            AutoSize = true,
            MaximumSize = new Size(_contentPanel!.Width - 60, 0),
            ForeColor = Color.White,
            TextAlign = ContentAlignment.MiddleLeft,
            BackColor = Color.Transparent,
            Anchor = AnchorStyles.Top | AnchorStyles.Left
        };
        _contentPanel?.Controls.Add(_titleLabel);

        _currentPageInstance = _currentPage switch
        {
            "Dashboard" => _dashboardPage,
            "Alerts" => _alertsPage,
            "Options" => _optionsPage,
            _ => _dashboardPage
        };

        _currentPageInstance?.LoadContent();
        _currentPageInstance?.OnActivated();
    }

    private void SetupRefreshTimer()
    {
        _refreshTimer = new System.Windows.Forms.Timer { Interval = 250 };
        _refreshTimer.Tick += (sender, e) =>
        {
            _currentPageInstance?.UpdateContent();
        };
        _refreshTimer.Start();
    }

    private void RefreshButton_Click(object? sender, EventArgs e)
    {
        _currentPageInstance?.UpdateContent();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _refreshTimer?.Stop();
            _refreshTimer?.Dispose();
        }
        base.Dispose(disposing);
    }
}