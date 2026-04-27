using Microsoft.AspNetCore.Mvc;
using NetworkMonitor.Backend;

namespace NetworkMonitor.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class DashboardController(MainController controller) : ControllerBase
{
    [HttpGet]
    public ActionResult<DataModel> Get()
    {
        return Ok(controller.GetDashboardData());
    }
}
