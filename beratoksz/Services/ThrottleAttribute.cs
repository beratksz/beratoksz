using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using System;

namespace beratoksz.Services
{
    public class ThrottleAttribute : ActionFilterAttribute
    {
        private readonly int _seconds;
        private readonly string _cacheKeyPrefix;
        private readonly int _maxAttempts;

        public ThrottleAttribute(int seconds, int maxAttempts = 3, string cacheKeyPrefix = "Throttle")
        {
            _seconds = seconds;
            _maxAttempts = maxAttempts;
            _cacheKeyPrefix = cacheKeyPrefix;
        }

        public override void OnActionExecuting(ActionExecutingContext context)
        {
            var cache = (IMemoryCache)context.HttpContext.RequestServices.GetService(typeof(IMemoryCache));
            var ipAddress = context.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            // Kullanıcıya veya endpoint'e özgü bir key oluşturuyoruz
            var key = $"{_cacheKeyPrefix}_{context.ActionDescriptor.DisplayName}_{ipAddress}";

            if (cache.TryGetValue(key, out int attempts))
            {
                if (attempts >= _maxAttempts)
                {
                    context.Result = new JsonResult(new
                    {
                        Message = $"Çok fazla deneme yapıldı, lütfen daha sonra tekrar deneyin."
                    })
                    {
                        StatusCode = 429
                    };
                }
                else
                {
                    cache.Set(key, attempts + 1, TimeSpan.FromSeconds(_seconds));
                }
            }
            else
            {
                cache.Set(key, 1, TimeSpan.FromSeconds(_seconds));
            }

            base.OnActionExecuting(context);
        }
    }
}
