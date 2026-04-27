using Microsoft.AspNetCore.Mvc;
using NetworkMonitor.Backend;

namespace NetworkMonitor.Api.Controllers;

public record DeviceDto(int Index, string Name, bool IsSelected);

[ApiController]
[Route("api/[controller]")]
public class DevicesController : ControllerBase
{
    [HttpGet]
    public ActionResult<IEnumerable<DeviceDto>> Get()
    {
        MainController.ListDevices();

        var selected = MainController.CurrentDevice;
        var result = MainController.AvailableDevices
            .Select((device, index) => new DeviceDto(index, device.Description, ReferenceEquals(device, selected)))
            .ToList();

        return Ok(result);
    }
}
