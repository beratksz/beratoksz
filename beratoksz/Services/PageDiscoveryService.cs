using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.Mvc.Routing;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

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
            .Where(type => typeof(Controller).IsAssignableFrom(type) && !type.IsAbstract);

        foreach (var controller in controllers)
        {
            var controllerName = controller.Name.Replace("Controller", "");
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
                    if (path == "/") path = "/home/index"; // ✅ Root path'leri düzeltiyoruz

                    pages.Add(path.ToLower()); // Küçük harfe çevirerek ekle
                }
            }
        }

        return pages;
    }
}
