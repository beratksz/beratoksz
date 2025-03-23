using beratoksz.Data;
using beratoksz.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using static PageDiscoveryService;

public class AutoDiscoverMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<AutoDiscoverMiddleware> _logger;

    public AutoDiscoverMiddleware(RequestDelegate next, ILogger<AutoDiscoverMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task Invoke(HttpContext context)
    {
        var path = context.Request.Path.ToString().ToLowerInvariant();
        path = UrlNormalizer.Normalize(path);

        if (string.IsNullOrWhiteSpace(path) || path.StartsWith("/static") || path == "/")
        {
            await _next(context);
            return;
        }


        if (Regex.IsMatch(path, @"^/(error|accessdenied|swagger|favicon)", RegexOptions.IgnoreCase))
        {
            await _next(context);
            return;
        }
    

        using var scope = context.RequestServices.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        bool exists = dbContext.RolePermissions.Any(rp => rp.PagePath == path);
        if (!exists)
        {
            var isStatic = Regex.IsMatch(path, @"\.(html|css|js|png|ico|jpg|jpeg|json|map|woff2?)$", RegexOptions.IgnoreCase);
            var fileExists = File.Exists(Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", path.TrimStart('/')));
            var label = isStatic ? "📦 Statik dosya" : "🚀 Yeni API/sayfa";

            _logger.LogWarning($"{label} keşfedildi ve eklendi: {path}");

            dbContext.RolePermissions.Add(new RolePermission
            {
                PagePath = path,
                RoleName = "Admin",
                CanAccess = true
            });

            await dbContext.SaveChangesAsync();
        }


        await _next(context);
    }


}
