using Microsoft.AspNetCore.Mvc;
using NetworkMonitor.Backend;

namespace NetworkMonitor.Api.Controllers;

public record StartCaptureRequest(int DeviceIndex);

[ApiController]
[Route("api/[controller]")]
public class CaptureController : ControllerBase
{
    [HttpPost("start")]
    public ActionResult Start([FromBody] StartCaptureRequest request)
    {
        MainController.ListDevices();

        if (request.DeviceIndex < 0 || request.DeviceIndex >= MainController.AvailableDevices.Count)
        {
            return BadRequest(new { message = "Invalid device index." });
        }

        var device = MainController.AvailableDevices[request.DeviceIndex];
        var started = MainController.StartCapture(device);

        if (!started)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new { message = "Capture failed to start." });
        }

        return Ok(new { message = "Capture started.", device = device.Description });
    }

    [HttpPost("pause")]
    public ActionResult Pause()
    {
        MainController.PauseCapture();
        return Ok(new { message = "Capture paused." });
    }

    [HttpPost("resume")]
    public ActionResult Resume()
    {
        MainController.PlayCapture();
        return Ok(new { message = "Capture resumed." });
    }
}
