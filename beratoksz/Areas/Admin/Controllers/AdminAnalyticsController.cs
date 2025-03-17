using beratoksz.Data;
using beratoksz.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using System;
using System.Collections.Generic;
using System.Linq;

namespace beratoksz.Areas.Admin.Controllers
{
    [ApiController]
    [Route("api/adminanalytics")]
    public class AdminAnalyticsController : ControllerBase
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly IMemoryCache _memoryCache;

        public AdminAnalyticsController(ApplicationDbContext dbContext, IMemoryCache memoryCache)
        {
            _dbContext = dbContext;
            _memoryCache = memoryCache;
        }

        [HttpGet("top-pages")]
        public IActionResult GetTopPages()
        {
            if (!_memoryCache.TryGetValue("topPages", out List<TopPageDto> topPages))
            {
                topPages = _dbContext.ActivityLogs
                    .GroupBy(l => l.Page)
                    .Select(g => new TopPageDto { Page = g.Key, Count = g.Count() })
                    .OrderByDescending(g => g.Count)
                    .Take(5)
                    .ToList();

                var cacheEntryOptions = new MemoryCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5) // 5 dakika boyunca cache'te kalacak
                };

                _memoryCache.Set("topPages", topPages, cacheEntryOptions);
            }

            return Ok(topPages);
        }

        [HttpGet("browsers")]
        public IActionResult GetBrowserStats()
        {
            var browsers = _dbContext.ActivityLogs
                .GroupBy(l => l.UserAgent)
                .Select(g => new { Browser = g.Key, Count = g.Count() })
                .OrderByDescending(g => g.Count)
                .Take(5)
                .ToList();

            return Ok(browsers);
        }

    }
}
