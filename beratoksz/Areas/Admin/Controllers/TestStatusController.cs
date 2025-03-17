using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using beratoksz.Hubs;
using System.Threading.Tasks;

namespace beratoksz.Areas.Admin.Controllers
{
    [Area("Admin")]
    [Route("admin/[controller]")]
    public class TestStatusController : Controller
    {
        private readonly IHubContext<StatusHub> _hubContext;

        public TestStatusController(IHubContext<StatusHub> hubContext)
        {
            _hubContext = hubContext;
        }

        [HttpGet("send")]
        public async Task<IActionResult> SendTestStatus()
        {
            await _hubContext.Clients.All.SendAsync("ReceiveStatusUpdate", "Tüm sistemler yeşil, uzay gemisi tam gaz ilerliyor!");
            return Content("Durum mesajı gönderildi.");
        }
    }
}
