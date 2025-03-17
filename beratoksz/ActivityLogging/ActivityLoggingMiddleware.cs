using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Threading.Tasks;
using beratoksz.Data;
using beratoksz.Models;
using UAParser;

public class ActivityLoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ActivityLoggingMiddleware> _logger;
    private readonly IServiceScopeFactory _scopeFactory;

    public ActivityLoggingMiddleware(RequestDelegate next, ILogger<ActivityLoggingMiddleware> logger, IServiceScopeFactory scopeFactory)
    {
        _next = next;
        _logger = logger;
        _scopeFactory = scopeFactory;
    }

    public async Task Invoke(HttpContext context)
    {
        var startTime = DateTime.UtcNow;

        await _next(context); // Sayfanın yüklenmesini bekle

        using (var scope = _scopeFactory.CreateScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            var userName = context.User.Identity.IsAuthenticated ? context.User.Identity.Name : "Anonim";
            var pagePath = context.Request.Path.ToString();
            var ipAddress = context.Connection.RemoteIpAddress?.ToString();
            var userAgent = context.Request.Headers["User-Agent"].ToString();
            var duration = (DateTime.UtcNow - startTime).TotalSeconds; // Sayfada kalma süresi

            // İşletim sistemini ve tarayıcıyı belirle
            var uaParser = Parser.GetDefault();
            var clientInfo = uaParser.Parse(userAgent);
            var os = clientInfo.OS.ToString();

            var log = new ActivityLog
            {
                UserName = userName,
                Page = pagePath,
                Timestamp = DateTime.UtcNow,
                IPAddress = ipAddress,
                UserAgent = userAgent,
                OS = os,
                Duration = duration
            };

            _logger.LogInformation($"📌 Kullanıcı: {userName}, Sayfa: {pagePath}, IP: {ipAddress}, OS: {os}, Tarayıcı: {clientInfo.UA}");

            dbContext.ActivityLogs.Add(log);
            await dbContext.SaveChangesAsync();
        }
    }
}
