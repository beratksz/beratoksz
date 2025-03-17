using Microsoft.AspNetCore.Http;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace beratoksz.PerformanceMetrics
{
    public class PerformanceMetricsMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<PerformanceMetricsMiddleware> _logger;

        public PerformanceMetricsMiddleware(RequestDelegate next, ILogger<PerformanceMetricsMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task Invoke(HttpContext context)
        {
            var stopwatch = Stopwatch.StartNew();
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                _logger.LogError($"❌ Hata: {ex.Message}");
                throw;
            }
            finally
            {
                stopwatch.Stop();
                var duration = stopwatch.ElapsedMilliseconds;
                var statusCode = context.Response.StatusCode;
                var requestPath = context.Request.Path;

                PerformanceMetricsCollector.AddRequestDuration(duration);

                _logger.LogInformation($"🌍 İstek: {requestPath} - {statusCode} | ⏱ Süre: {duration} ms");
            }
        }
    }
}
