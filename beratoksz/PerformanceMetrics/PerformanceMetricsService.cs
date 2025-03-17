using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using beratoksz.Hubs;

namespace beratoksz.PerformanceMetrics
{
    public class PerformanceMetricsService : BackgroundService
    {
        private readonly IHubContext<StatusHub> _hubContext;
        private readonly ILogger<PerformanceMetricsService> _logger;
        private readonly Process _process;
        private TimeSpan _prevCpuTime;
        private DateTime _prevTime;

        public PerformanceMetricsService(IHubContext<StatusHub> hubContext, ILogger<PerformanceMetricsService> logger)
        {
            _hubContext = hubContext;
            _logger = logger;
            _process = Process.GetCurrentProcess();
            _prevCpuTime = _process.TotalProcessorTime;
            _prevTime = DateTime.UtcNow;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("🚀 PerformanceMetricsService BAŞLADI!");

            while (!stoppingToken.IsCancellationRequested)
            {
                var reqMetrics = PerformanceMetricsCollector.GetMetrics();

                _process.Refresh();
                DateTime currentTime = DateTime.UtcNow;
                TimeSpan currentCpuTime = _process.TotalProcessorTime;

                // **CPU Kullanımını Gerçek Yüzde Olarak Hesapla!**
                double elapsedMs = (currentTime - _prevTime).TotalMilliseconds;
                double cpuUsedMs = (currentCpuTime - _prevCpuTime).TotalMilliseconds;
                double cpuUsage = (cpuUsedMs / elapsedMs) * 100 / Environment.ProcessorCount;

                _prevCpuTime = currentCpuTime;
                _prevTime = currentTime;

                double memoryUsageMB = _process.WorkingSet64 / (1024.0 * 1024.0);
                TimeSpan uptime = DateTime.UtcNow - _process.StartTime.ToUniversalTime();

                var payload = new
                {
                    requestMetrics = new
                    {
                        AvgResponseTime = $"{reqMetrics.average:F2} ms",
                        MinResponseTime = $"{reqMetrics.min} ms",
                        MaxResponseTime = $"{reqMetrics.max} ms",
                        RequestCount = reqMetrics.count
                    },
                    systemMetrics = new
                    {
                        CpuUsage = cpuUsage.ToString("F1") + "%",
                        MemoryUsage = memoryUsageMB.ToString("F1") + " MB",
                        Uptime = uptime.ToString(@"dd\.hh\:mm\:ss")
                    }
                };

                _logger.LogInformation($"📡 Veri gönderiliyor: CPU={cpuUsage:F1}%, Bellek={memoryUsageMB:F1}MB, Uptime={uptime}");

                await _hubContext.Clients.All.SendAsync("UpdatePerformanceMetrics", payload, stoppingToken);
                await Task.Delay(5000, stoppingToken);
            }
        }
    }
}
