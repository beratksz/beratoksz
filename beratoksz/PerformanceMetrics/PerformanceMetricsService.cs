﻿using beratoksz.Data;
using beratoksz.Hubs;
using beratoksz.PerformanceMetrics;
using Microsoft.AspNetCore.SignalR;
using System.Diagnostics;

public class PerformanceMetricsService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IHubContext<StatusHub> _hubContext;
    private readonly ILogger<PerformanceMetricsService> _logger;
    private readonly Process _process;
    private TimeSpan _prevCpuTime;
    private DateTime _prevTime;
    private double _lastCpuUsage = -1;
    private double _lastMemoryUsage = -1;

    public PerformanceMetricsService(IServiceScopeFactory scopeFactory, IHubContext<StatusHub> hubContext, ILogger<PerformanceMetricsService> logger)
    {
        _scopeFactory = scopeFactory;
        _hubContext = hubContext;
        _logger = logger;
        _process = Process.GetCurrentProcess();
        _prevCpuTime = _process.TotalProcessorTime;
        _prevTime = DateTime.UtcNow;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("🚀 PerformanceMetricsService BAŞLADI!");

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                using (var scope = _scopeFactory.CreateScope())
                {
                    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

                    var reqMetrics = PerformanceMetricsCollector.GetMetrics();
                    _process.Refresh();
                    DateTime currentTime = DateTime.UtcNow;
                    TimeSpan currentCpuTime = _process.TotalProcessorTime;

                    double elapsedMs = (currentTime - _prevTime).TotalMilliseconds;
                    double cpuUsedMs = (currentCpuTime - _prevCpuTime).TotalMilliseconds;
                    double cpuUsage = (cpuUsedMs / elapsedMs) * 100;

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

                    // Eğer CPU veya RAM kullanımı değişmediyse veri göndermeyi atla (gereksiz trafik önleme)
                    if (Math.Abs(cpuUsage - _lastCpuUsage) > 0.5 || Math.Abs(memoryUsageMB - _lastMemoryUsage) > 5)
                    {
                        _logger.LogInformation($"📡 Veri gönderiliyor: CPU={cpuUsage:F1}%, Bellek={memoryUsageMB:F1}MB, Uptime={uptime}");
                        await _hubContext.Clients.All.SendAsync("UpdatePerformanceMetrics", payload, stoppingToken);
                        _lastCpuUsage = cpuUsage;
                        _lastMemoryUsage = memoryUsageMB;
                    }
                }

                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }
        catch (TaskCanceledException)
        {
            _logger.LogWarning("⚠ PerformanceMetricsService durduruldu.");
        }
        catch (Exception ex)
        {
            _logger.LogError($"🚨 Kritik Hata: {ex.Message}");
        }
        finally
        {
            _logger.LogInformation("🛑 PerformanceMetricsService KAPANDI.");
        }
    }
}
