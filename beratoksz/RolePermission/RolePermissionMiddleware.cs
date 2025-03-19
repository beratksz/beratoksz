using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;
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
        var path = context.Request.Path.ToString().Trim('/').ToLower();
        var user = context.User;  // 🔥 Burada user'ı tanımla!


        var userRoles = context.User.Claims
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

        // 📌 2️⃣ HATA SAYFASI KONTROLÜ (Yönlendirme döngüsünü önlemek için)
        if (path.StartsWith("/Home/AccessDenied"))
        {
            await _next(context);
            return;
        }

        if (path.StartsWith("/api"))
        {
            await _next(context);
            return;
        }


        // 📌 3️⃣ Route Endpoint kontrolü
        var endpoint = context.GetEndpoint();
        if (endpoint != null)
        {
            var allowAnonymous = endpoint.Metadata.GetMetadata<Microsoft.AspNetCore.Authorization.AllowAnonymousAttribute>();
            if (allowAnonymous != null)
            {
                _logger.LogInformation($"🔓 {path} sayfası [AllowAnonymous] ile işaretlenmiş, erişim serbest!");
                await _next(context);
                return;
            }

            var routePattern = endpoint.Metadata.GetMetadata<Microsoft.AspNetCore.Routing.RouteEndpoint>()?.RoutePattern.RawText;
            if (!string.IsNullOrEmpty(routePattern))
            {
                path = "/" + routePattern.Replace("{", "").Replace("}", "").Replace("?", "");
            }
        }

        // 📌 4️⃣ Ana sayfa yönlendirmesi
        if (path == "/" || path == "/index.html" || path == "/index" || path == "/home")
        {
            path = "/home/index";
        }

        // 📌 5️⃣ Admin area yönlendirme
        if (path.StartsWith("/admin") || path.StartsWith("/user"))
        {
            path = $"/{path}";
        }

        // 📌 6️⃣ TÜRKÇE KARAKTER DÜZELTME

        path = ConvertToAscii(path);
        Console.WriteLine($"🛑 Yetki Kontrolü: Kullanıcı: {context.User.Identity?.Name}, Path: {path}");

        // 📌 7️⃣ Kullanıcı giriş yapmamışsa login sayfasına yönlendir
        if (!user.Identity.IsAuthenticated)
        {
            _logger.LogWarning($"🔒 Yetkisiz kullanıcı giriş yapmaya çalıştı: {path}");
            context.Response.Redirect("/Account/Login");
            return;
        }


        using (var scope = _scopeFactory.CreateScope())
        {
            var rolePermissionService = scope.ServiceProvider.GetRequiredService<RolePermissionService>();

            // 📌 8️⃣ Kullanıcının ilgili sayfaya erişim izni olup olmadığını kontrol et
            var hasAccess = await rolePermissionService.HasAccess(user, path);

            if (!hasAccess)
            {
                _logger.LogWarning($"🚫 Yetkisiz erişim: Kullanıcı {user.Identity?.Name ?? "Anonim"} {path} sayfasına erişmeye çalıştı.");

                // **Türkçe karakterleri kaldır ve ASCII formatına çevir**
                var safePath = ConvertToAscii(path).Replace("//", "/").TrimEnd('/'); // Fazladan slash temizle

                // ✅ **Sadece query parametresini encode et**
                var message = Uri.EscapeDataString($"Yetkisiz Erişim: {safePath}");

                // 🌟 **HATASIZ REDIRECT**
                var redirectUrl = $"/Home/AccessDenied?message={message}";
                context.Response.Redirect(redirectUrl);
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
            .ToLowerInvariant() // 🔥 Türkçe büyük/küçük harf hatasını önler!
            .Replace("ı", "i").Replace("İ", "I")
            .Replace("ş", "s").Replace("Ş", "S")
            .Replace("ç", "c").Replace("Ç", "C")
            .Replace("ğ", "g").Replace("Ğ", "G")
            .Replace("ö", "o").Replace("Ö", "O")
            .Replace("ü", "u").Replace("Ü", "U");
    }

}
