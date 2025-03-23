using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using System.Collections.Generic;
using System.Globalization;
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
        var pages = new HashSet<string>();

        var actionDescriptors = _actionProvider.ActionDescriptors.Items;

        foreach (var action in actionDescriptors)
        {
            if (action is ControllerActionDescriptor descriptor)
            {
                var area = descriptor.RouteValues.ContainsKey("area") ? descriptor.RouteValues["area"] : null;
                var controller = descriptor.ControllerName;
                var actionName = descriptor.ActionName;

                var template = descriptor.AttributeRouteInfo?.Template;
                string path = !string.IsNullOrWhiteSpace(template)
                    ? "/" + template
                    : $"/{controller}/{actionName}";

                if (area != null)
                    path = $"/{area}{path}";

                path = UrlNormalizer.Normalize(path);
                pages.Add(path);
            }
        }

        return pages.ToList();
    }

    public static class UrlNormalizer
    {
        public static string Normalize(string url)
        {
            if (string.IsNullOrWhiteSpace(url)) return "/";

            // Türkçe karakter düzeltmesi – önce yap
            url = url
                .Replace("ı", "i").Replace("İ", "I")
                .Replace("ş", "s").Replace("Ş", "S")
                .Replace("ç", "c").Replace("Ç", "C")
                .Replace("ğ", "g").Replace("Ğ", "G")
                .Replace("ö", "o").Replace("Ö", "O")
                .Replace("ü", "u").Replace("Ü", "U");

            // Lowercase (en-US)
            url = url.ToLower(new CultureInfo("en-US"));

            // Sayısal ID & GUID maskeleri
            url = Regex.Replace(url, @"\/[0-9a-fA-F\-]{8,}", "/*"); // GUID
            url = Regex.Replace(url, @"\/\d+", "/*");              // Sayı

            // // düzelt ve trailing slash temizle
            url = url.Replace("//", "/").TrimEnd('/');

            return url;
        }
    }
}
