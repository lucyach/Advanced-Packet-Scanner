using Microsoft.AspNetCore.Mvc;
using NetworkMonitor.Backend;

namespace NetworkMonitor.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class DashboardController(MainController controller) : ControllerBase
{
    [HttpGet]
    public ActionResult<DataModel> Get([FromQuery] string? protocol, [FromQuery] int? minRisk, [FromQuery] int? maxRisk, [FromQuery] string? payloadContains)
    {
        return Ok(controller.GetDashboardDataFiltered(protocol, minRisk, maxRisk, payloadContains));
    }
}
