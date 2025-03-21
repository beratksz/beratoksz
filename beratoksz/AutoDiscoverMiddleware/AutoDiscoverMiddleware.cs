using beratoksz.Data;
using beratoksz.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
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
        var path = context.Request.Path.ToString().ToLower();
        path = UrlNormalizer.Normalize(path);  // URL'yi normalize et

        using (var scope = context.RequestServices.CreateScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            bool exists = dbContext.RolePermissions.Any(rp => rp.PagePath == path);
            if (!exists)
            {
                _logger.LogWarning($"🚀 Yeni API keşfedildi ve ekleniyor: {path}");
                dbContext.RolePermissions.Add(new RolePermission { PagePath = path, RoleName = "Admin", CanAccess = true });
                await dbContext.SaveChangesAsync();
            }
        }

        await _next(context);
    }
}
