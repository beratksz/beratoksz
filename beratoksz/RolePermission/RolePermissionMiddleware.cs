using beratoksz.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using beratoksz.Extension;
using Microsoft.AspNetCore.Identity;
using beratoksz.Data;

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
        var rawPath = context.Request.Path;
        var path = NormalizePath(rawPath);
        var user = context.User;
        var userName = user.Identity?.Name ?? AppRoleName.Guest;

        using var scope = _scopeFactory.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<AppUser>>();
        var userRoles = await user.GetUserRolesOrGuestAsync(userManager);

        _logger.LogInformation("[RolePermission Middleware] Gelen Path: {Path}", path);
        _logger.LogInformation("[RolePermission Middleware] Kullanıcı: {User} | Roller: {Roles}", userName, string.Join(", ", userRoles));

        // Statik dosyaları es geç
        if (Regex.IsMatch(path, @"\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|map|txt|xml|json|webp)$"))
        {
            await _next(context);
            return;
        }

        // Türkçe karakterleri ASCII'ye çevir
        path = ConvertToAscii(path);

        // Eğer path sonunda /index yoksa ama veritabanında /index’li hali varsa otomatik tamamla
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        if (!path.EndsWith("/index") && db.RolePermissions.Any(x => x.PagePath == path + "/index"))
        {
            path += "/index";
            _logger.LogInformation("[RolePermission Middleware] Path /index ile tamamlandı: {Path}", path);
        }

        var rolePermissionService = scope.ServiceProvider.GetRequiredService<RolePermissionService>();
        var hasAccess = await rolePermissionService.HasAccess(user, path);

        if (!hasAccess)
        {
            var message = Uri.EscapeDataString($"Yetkisiz Erişim: {path}");

            if (path.StartsWith("/accessdenied", StringComparison.OrdinalIgnoreCase))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsync("403 - Yetkisiz Erişim");
                return;
            }

            context.Response.Redirect($"/AccessDenied?message={message}");
            return;
        }

        await _next(context);
    }


    private static string NormalizePath(string path)
    {
        path = path.Trim().ToLowerInvariant();

        while (path.Contains("//"))
            path = path.Replace("//", "/");

        return path;
    }

    public static string ConvertToAscii(string input)
    {
        if (string.IsNullOrEmpty(input))
            return input;

        return input
            .ToLower(new CultureInfo("en-US"))
            .Replace("ı", "i").Replace("İ", "I")
            .Replace("ş", "s").Replace("Ş", "S")
            .Replace("ç", "c").Replace("Ç", "C")
            .Replace("ğ", "g").Replace("Ğ", "G")
            .Replace("ö", "o").Replace("Ö", "O")
            .Replace("ü", "u").Replace("Ü", "U");
    }
}