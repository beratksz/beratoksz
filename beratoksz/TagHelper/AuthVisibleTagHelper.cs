// 📦 TagHelper: Role-based görünürlük için
using Microsoft.AspNetCore.Razor.TagHelpers;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using beratoksz.Models;
using beratoksz.Extension;
using Microsoft.Extensions.DependencyInjection;

[HtmlTargetElement("auth-visible")]
public class AuthVisibleTagHelper : TagHelper
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IServiceScopeFactory _scopeFactory;

    public AuthVisibleTagHelper(IHttpContextAccessor httpContextAccessor, IServiceScopeFactory scopeFactory)
    {
        _httpContextAccessor = httpContextAccessor;
        _scopeFactory = scopeFactory;
    }

    [ViewContext]
    [HtmlAttributeNotBound]
    public ViewContext ViewContext { get; set; } = default!;

    [HtmlAttributeName("path")] public string? Path { get; set; }
    [HtmlAttributeName("asp-area")] public string? Area { get; set; }
    [HtmlAttributeName("asp-controller")] public string? Controller { get; set; }
    [HtmlAttributeName("asp-action")] public string? Action { get; set; }

    public override async Task ProcessAsync(TagHelperContext context, TagHelperOutput output)
    {
        using var scope = _scopeFactory.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<AppUser>>();
        var rolePermissionService = scope.ServiceProvider.GetRequiredService<RolePermissionService>();

        var httpContext = _httpContextAccessor.HttpContext;
        var user = httpContext?.User;

        if (user == null)
        {
            output.SuppressOutput();
            return;
        }

        string finalPath;

        if (!string.IsNullOrWhiteSpace(Path))
        {
            finalPath = Path.Trim().ToLowerInvariant();
        }
        else if (!string.IsNullOrWhiteSpace(Controller))
        {
            var areaSegment = string.IsNullOrWhiteSpace(Area) ? "" : $"/{Area}";
            var actionSegment = string.IsNullOrWhiteSpace(Action) ? "/Index" : $"/{Action}";
            finalPath = $"{areaSegment}/{Controller}{actionSegment}".ToLowerInvariant();
        }
        else
        {
            output.SuppressOutput();
            return;
        }

        bool hasAccess = await rolePermissionService.HasAccess(user, finalPath);

        if (!hasAccess)
        {
            output.SuppressOutput();
        }
    }
}
