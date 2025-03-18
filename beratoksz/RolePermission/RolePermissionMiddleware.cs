using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Security.Claims;
using System.Threading.Tasks;

public class RolePermissionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RolePermissionMiddleware> _logger;
    private readonly IServiceScopeFactory _scopeFactory;

    public RolePermissionMiddleware(RequestDelegate next, ILogger<RolePermissionMiddleware> logger, IServiceScopeFactory scopeFactory)
    {
        _next = next;
        _logger = logger;
        _scopeFactory = scopeFactory;
    }

    public async Task Invoke(HttpContext context)
    {
        var user = context.User;
        var path = context.Request.Path.ToString().ToLower();
        var endpoint = context.GetEndpoint();

        if (endpoint != null)
        {
            var routePattern = endpoint.Metadata.GetMetadata<Microsoft.AspNetCore.Routing.RouteEndpoint>()?.RoutePattern.RawText;
            if (!string.IsNullOrEmpty(routePattern))
            {
                path = "/" + routePattern.Replace("{", "").Replace("}", "").Replace("?", "");
            }
        }

        if (path == "/" || path == "/index.html")
        {
            path = "/home/index"; // ✅ Doğru path formatına dönüştür
        }

        if (!user.Identity.IsAuthenticated)
        {
            _logger.LogInformation($"🔒 Yetkisiz kullanıcı giriş yapmaya çalıştı: {path}");
            await _next(context);
            return;
        }

        using (var scope = _scopeFactory.CreateScope()) // Scoped servisleri almak için
        {
            var rolePermissionService = scope.ServiceProvider.GetRequiredService<RolePermissionService>();

            // Kullanıcının ilgili sayfaya erişim izni olup olmadığını kontrol et
            var hasAccess = await rolePermissionService.HasAccess(user, path);

            if (!hasAccess)
            {
                _logger.LogWarning($"🚫 Yetkisiz erişim: Kullanıcı {user.Identity?.Name ?? "Anonim"} {path} sayfasına erişmeye çalıştı.");
                context.Response.Redirect("/Error/Forbidden");
                return;
            }
        }

        await _next(context);
    }
}
