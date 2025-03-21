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
            var areaAttr = controller.GetCustomAttribute<AreaAttribute>();
            var controllerRouteAttr = controller.GetCustomAttribute<RouteAttribute>();
            var baseRoute = controllerRouteAttr?.Template ?? "";

            foreach (var method in controller.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly))
            {
                var httpMethodAttributes = method.GetCustomAttributes<HttpMethodAttribute>(inherit: true);
                var actionName = method.Name;

                if (!httpMethodAttributes.Any())
                {
                    // Eğer HTTP attribute yoksa varsayılan route kabul edilir (e.g. MVC: /controller/action)
                    string defaultPath = $"/{controllerName}/{actionName}";
                    if (areaAttr != null)
                        defaultPath = $"/{areaAttr.RouteValue}/{controllerName}/{actionName}";

                    pages.Add(defaultPath.ToLowerInvariant());
                    continue;
                }

                foreach (var httpAttr in httpMethodAttributes)
                {
                    string template = httpAttr.Template ?? "";

                    string fullPath = baseRoute;

                    if (!string.IsNullOrEmpty(template))
                    {
                        if (!string.IsNullOrEmpty(baseRoute))
                            fullPath += "/" + template;
                        else
                            fullPath = template;
                    }

                    fullPath = fullPath
                        .Replace("[controller]", controllerName)
                        .Replace("[action]", actionName);

                    if (!fullPath.StartsWith("/"))
                        fullPath = "/" + fullPath;

                    if (areaAttr != null)
                        fullPath = $"/{areaAttr.RouteValue}".TrimEnd('/') + fullPath;

                    pages.Add(fullPath.ToLowerInvariant());
                }
            }
        }

        return pages.Distinct().ToList();
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
