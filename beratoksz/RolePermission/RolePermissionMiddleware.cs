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
        var path = context.Request.Path.ToString().Trim().ToLower().Replace("//", "/");
        var user = context.User;

        
        
        var userName = user.Identity?.IsAuthenticated == true && !string.IsNullOrEmpty(user.Identity.Name)
             ? user.Identity.Name
             : AppRoleName.Guest;



        var userRoles = user.Claims
            .Where(c => c.Type == ClaimTypes.Role)
            .Select(c => c.Value)
            .ToList();
        

        Console.WriteLine($"🟡 [Middleware] Gelen Path: {path}");
        Console.WriteLine($"🟡 [Middleware] Kullanıcı Roller: {string.Join(", ", userRoles)}");

        while (path.Contains("//"))
        {
            path = path.Replace("//", "/");
        }

        if (path.EndsWith("/"))
        {
            path = path.TrimEnd('/');
        }

        _logger.LogInformation($"✅ Güncellenmiş URL: {path}");

        // 📌 1️⃣ Statik dosyaları filtrele
        if (Regex.IsMatch(path, @"\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|map|txt|xml|json|webp)$"))
        {
            await _next(context);
            return;
        }

        // 📌 3️⃣ Kullanıcı giriş yapmamışsa login sayfasına yönlendir
        /*
        if (!user.Identity.IsAuthenticated)
        {
            _logger.LogWarning($"🔒 Yetkisiz kullanıcı giriş yapmaya çalıştı: {path}");
            context.Response.Redirect("/VAccount/Login");
            return;
        }
        */


        // 📌 4️⃣ Türkçe karakterleri ASCII'ye çevir
        path = ConvertToAscii(path);

        using (var scope = _scopeFactory.CreateScope())
        {
            var rolePermissionService = scope.ServiceProvider.GetRequiredService<RolePermissionService>();

            // 📌 5️⃣ Kullanıcının yetkisini kontrol et
            var hasAccess = await rolePermissionService.HasAccess(user, path);

            if (!hasAccess)
            {

            // _logger.LogWarning($"🚫 Yetkisiz erişim: Kullanıcı {userName} {path} sayfasına erişmeye çalıştı.");

                var safePath = ConvertToAscii(path).Replace("//", "/").TrimEnd('/');

                if (string.IsNullOrWhiteSpace(path))
                {
                    path = "/"; // fallback olarak kök dizin
                }

                var message = Uri.EscapeDataString($"Yetkisiz Erişim: {safePath}");

                // 🚨 Kullanıcı AccessDenied sayfasına erişimi yoksa doğrudan 403 Forbidden dön!
                if (path.Equals("/accessdenied", StringComparison.OrdinalIgnoreCase))
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    await context.Response.WriteAsync("403 - Yetkisiz Erişim");
                    return;
                }

                // 🌟 AccessDenied sayfasına yönlendirme
                context.Response.Redirect($"/AccessDenied?message={message}");
                return;
            }

        }

        await _next(context);
    }

    // 📌 TÜRKÇE KARAKTERLERİ ASCII'YE DÖNÜŞTÜR
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
