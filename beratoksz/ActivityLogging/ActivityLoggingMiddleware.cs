using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;
using beratoksz.Data;
using beratoksz.Models;
using UAParser;
using beratoksz;

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

        await _next(context); // Sonraki middleware'i bekle

        using (var scope = _scopeFactory.CreateScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var geoIPService = scope.ServiceProvider.GetRequiredService<GeoIPService>();

            var userName = context.User.Identity.IsAuthenticated ? context.User.Identity.Name : "Anonim";
            var pagePath = context.Request.Path.ToString();
            var ipAddress = context.Connection.RemoteIpAddress?.ToString();
            var userAgent = context.Request.Headers["User-Agent"].ToString();
            var duration = (DateTime.UtcNow - startTime).TotalSeconds;

            // İşletim sistemi ve tarayıcıyı belirle
            var uaParser = Parser.GetDefault();
            var clientInfo = uaParser.Parse(userAgent);
            var os = clientInfo.OS.ToString();

            string country, city, region;

            // Localhost kontrolü
            if (ipAddress == "::1" || ipAddress == "127.0.0.1" || ipAddress == "localhost")
            {
                country = city = region = "Localhost";
            }
            else
            {
                try
                {
                    var location = geoIPService.GetLocation(ipAddress);
                    country = location?.Country?.Name ?? "Bilinmiyor";
                    city = location?.City?.Name ?? "Bilinmiyor";
                    region = location?.MostSpecificSubdivision?.Name ?? "Bilinmiyor";
                }
                catch (Exception ex)
                {
                    _logger.LogError($"🌍 GeoIP hatası: {ex.Message}");
                    country = city = region = "Bilinmiyor";
                }
            }

            var log = new ActivityLog
            {
                UserName = userName,
                Page = pagePath,
                Timestamp = DateTime.UtcNow,
                IPAddress = ipAddress,
                UserAgent = userAgent,
                OS = os,
                Duration = duration,
                Country = country,
                City = city,
                Region = region,
            };

            _logger.LogInformation($"📌 Kullanıcı: {userName}, Sayfa: {pagePath}, IP: {ipAddress}, OS: {os}, Tarayıcı: {clientInfo.UA}, Ülke: {country}, Şehir: {city}, Bölge: {region}");

            dbContext.ActivityLogs.Add(log);
            await dbContext.SaveChangesAsync();
        }
    }
}
