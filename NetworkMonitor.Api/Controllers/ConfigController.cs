using Microsoft.AspNetCore.Mvc;
using NetworkMonitor.Backend;

namespace NetworkMonitor.Api.Controllers;

public record ConfigResponse(int MaxPackets, int MaxAlerts, int PacketSaveCount);
public record UpdateConfigRequest(int MaxPackets, int MaxAlerts, int PacketSaveCount);

[ApiController]
[Route("api/[controller]")]
public class ConfigController : ControllerBase
{
    [HttpGet]
    public ActionResult<ConfigResponse> Get()
    {
        var config = AppConfig.Instance;
        return Ok(new ConfigResponse(config.MaxPackets, config.MaxAlerts, config.PacketSaveCount));
    }

    [HttpPut]
    public ActionResult<ConfigResponse> Update([FromBody] UpdateConfigRequest request)
    {
        AppConfig.Instance.UpdateLimits(request.MaxPackets, request.MaxAlerts);
        AppConfig.Instance.UpdatePacketSaveCount(request.PacketSaveCount);

        var updated = AppConfig.Instance;
        return Ok(new ConfigResponse(updated.MaxPackets, updated.MaxAlerts, updated.PacketSaveCount));
    }
}
