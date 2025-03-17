using beratoksz.Data;
using beratoksz.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System.Linq;

namespace beratoksz.Areas.Admin.Controllers
{
    [ApiController]
    [Route("api/activitylog")]
    public class ActivityLogController : ControllerBase
    {
        private readonly IServiceScopeFactory _scopeFactory;

        public ActivityLogController(IServiceScopeFactory scopeFactory)
        {
            _scopeFactory = scopeFactory;
        }

        [HttpGet]
        public IActionResult GetActivityLogs([FromQuery] int page = 1, [FromQuery] int pageSize = 10)
        {
            using (var scope = _scopeFactory.CreateScope())
            {
                var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

                var logs = dbContext.ActivityLogs
                    .AsNoTracking() // ✅ Performance boost!
                    .OrderByDescending(l => l.Timestamp)
                    .Skip((page - 1) * pageSize)
                    .Take(pageSize)
                    .ToList();

                return Ok(logs);
            }
        }
    }
}
