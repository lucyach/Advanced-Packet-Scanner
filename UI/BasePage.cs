using NetworkMonitor.Backend;

namespace NetworkMonitor.UI;

// Base class for all page content
public abstract class BasePage
{
    protected readonly MainController _controller;
    protected readonly Panel _contentPanel;

    protected BasePage(MainController controller, Panel contentPanel)
    {
        _controller = controller;
        _contentPanel = contentPanel;
    }

    public abstract void LoadContent();
    public virtual void UpdateContent() { }
    public virtual void OnActivated() { }
    public virtual void OnDeactivated() { }
}