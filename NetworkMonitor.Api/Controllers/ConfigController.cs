using Microsoft.AspNetCore.Mvc;
using NetworkMonitor.Backend;

namespace NetworkMonitor.Api.Controllers;

public record ConfigResponse(
    int MaxPackets,
    int MaxAlerts,
    int PacketSaveCount,
    bool PayloadFilteringEnabled,
    int PayloadPreviewLength,
    List<string> BlockedPayloadKeywords,
    List<string> BlockedPayloadPatterns);

public record UpdateConfigRequest(
    int MaxPackets,
    int MaxAlerts,
    int PacketSaveCount,
    bool? PayloadFilteringEnabled,
    int? PayloadPreviewLength,
    List<string>? BlockedPayloadKeywords,
    List<string>? BlockedPayloadPatterns);

[ApiController]
[Route("api/[controller]")]
public class ConfigController : ControllerBase
{
    [HttpGet]
    public ActionResult<ConfigResponse> Get()
    {
        var config = AppConfig.Instance;
        return Ok(new ConfigResponse(
            config.MaxPackets,
            config.MaxAlerts,
            config.PacketSaveCount,
            config.PayloadFilteringEnabled,
            config.PayloadPreviewLength,
            config.BlockedPayloadKeywords,
            config.BlockedPayloadPatterns));
    }

    [HttpPut]
    public ActionResult<ConfigResponse> Update([FromBody] UpdateConfigRequest request)
    {
        AppConfig.Instance.UpdateLimits(request.MaxPackets, request.MaxAlerts);
        AppConfig.Instance.UpdatePacketSaveCount(request.PacketSaveCount);
        AppConfig.Instance.UpdatePayloadFiltering(
            request.PayloadFilteringEnabled ?? AppConfig.Instance.PayloadFilteringEnabled,
            request.PayloadPreviewLength ?? AppConfig.Instance.PayloadPreviewLength,
            request.BlockedPayloadKeywords,
            request.BlockedPayloadPatterns);

        var updated = AppConfig.Instance;
        return Ok(new ConfigResponse(
            updated.MaxPackets,
            updated.MaxAlerts,
            updated.PacketSaveCount,
            updated.PayloadFilteringEnabled,
            updated.PayloadPreviewLength,
            updated.BlockedPayloadKeywords,
            updated.BlockedPayloadPatterns));
    }
}
