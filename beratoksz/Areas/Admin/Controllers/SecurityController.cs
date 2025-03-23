using beratoksz.Models;
using beratoksz.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace beratoksz.Areas.Admin.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SecurityController : ControllerBase
    {
        private readonly UserSecurityService _userSecurityService;
        private readonly UserManager<AppUser> _userManager;

        public SecurityController(UserSecurityService userSecurityService, UserManager<AppUser> userManager)
        {
            _userSecurityService = userSecurityService;
            _userManager = userManager;
        }

        [HttpGet("activities")]
        public async Task<IActionResult> GetRecentActivities()
        {
            var userId = _userManager.GetUserId(User);
            var activities = await _userSecurityService.GetRecentActivities(userId);
            return Ok(activities);
        }
    }
}
