using Microsoft.AspNetCore.Mvc;
using NetworkMonitor.Backend;

namespace NetworkMonitor.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AlertsController(MainController controller) : ControllerBase
{
    [HttpGet]
    public ActionResult<object> Get()
    {
        var dashboard = controller.GetDashboardData();
        var stats = MainController.GetAlertStats();

        return Ok(new
        {
            dashboard.Alerts,
            dashboard.SecurityAlerts,
            stats
        });
    }

    [HttpDelete]
    public ActionResult Clear()
    {
        MainController.ClearAlerts();
        return Ok(new { message = "Alerts cleared." });
    }
}
