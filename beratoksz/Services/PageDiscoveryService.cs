using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.Mvc.Routing;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;


public class PageDiscoveryService
{
    private readonly IActionDescriptorCollectionProvider _actionProvider;

    public PageDiscoveryService(IActionDescriptorCollectionProvider actionProvider)
    {
        _actionProvider = actionProvider;
    }

    public List<string> GetAllPages()
    {
        var pages = new List<string>();

        var controllers = Assembly.GetExecutingAssembly()
            .GetTypes()
            .Where(type => (typeof(Controller).IsAssignableFrom(type) || typeof(ControllerBase).IsAssignableFrom(type))
                            && !type.IsAbstract);

        foreach (var controller in controllers)
        {
            var controllerName = controller.Name.Replace("Controller", "");
            var areaAttr = controller.GetCustomAttribute<AreaAttribute>(); // ✅ Area bilgisini al
            var routeAttr = controller.GetCustomAttribute<RouteAttribute>();

            foreach (var method in controller.GetMethods())
            {
                if (method.IsPublic && method.DeclaringType == controller)
                {
                    var actionName = method.Name;
                    var methodAttr = method.GetCustomAttribute<HttpMethodAttribute>();

                    string path;

                    if (routeAttr != null)
                    {
                        path = routeAttr.Template
                            .Replace("[controller]", controllerName)
                            .Replace("[action]", actionName);
                    }
                    else
                    {
                        path = $"/{controllerName}/{actionName}";
                    }

                    // ✅ Eğer Area varsa, URL'ye ekle
                    if (areaAttr != null)
                    {
                        path = $"/{areaAttr.RouteValue}".TrimEnd('/') + "/" + path.TrimStart('/');
                    }

                    pages.Add(path.ToLowerInvariant()); // 🔥 Küçük harf dönüşümü hatasız yapıldı
                }
            }
        }

        return pages.Distinct().ToList(); // 🔥 Tekrarları kaldır
    }

    

public static class UrlNormalizer
{
    public static string Normalize(string url)
    {
        if (string.IsNullOrEmpty(url)) return url;

        // ID'leri, GUID'leri ve sayısal değerleri tespit edip yerine * koy
        url = Regex.Replace(url, @"\/[0-9a-fA-F\-]{8,}", "/*");  // GUID'leri yakala
        url = Regex.Replace(url, @"\/\d+", "/*");  // Sayıları yakala

        return url.ToLower().TrimEnd('/');
    }
}

}
