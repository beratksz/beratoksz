using beratoksz.Data;
using beratoksz.Extension;
using beratoksz.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

public class RolePermissionService
{
    private readonly ApplicationDbContext _dbContext;
    private readonly UserManager<AppUser> _userManager;
    private readonly IMemoryCache _cache;
    private readonly ILogger<RolePermissionService> _logger;

    public RolePermissionService(ApplicationDbContext dbContext, UserManager<AppUser> userManager, IMemoryCache cache, ILogger<RolePermissionService> logger)
    {
        _dbContext = dbContext;
        _userManager = userManager;
        _cache = cache;
        _logger = logger;
    }

    public async Task<bool> HasAccess(ClaimsPrincipal user, string pagePath)
    {
        string userId = null;
        AppUser userEntity = null;
        IList<string> roles;

        roles = await user.GetUserRolesOrGuestAsync(_userManager);

        var areaPagePath = pagePath.StartsWith("/admin") || pagePath.StartsWith("/user") ? pagePath : $"/{pagePath}";

        var normalizedPagePath = pagePath.Trim().ToLower().Replace("//", "/").TrimEnd('/');
        if (string.IsNullOrWhiteSpace(normalizedPagePath))
            normalizedPagePath = "/";

        var normalizedAreaPagePath = areaPagePath.Trim().ToLower().Replace("//", "/").TrimEnd('/');

        var cacheKey = $"role_permissions_{string.Join("_", roles)}_{normalizedAreaPagePath}";
        if (_cache.TryGetValue(cacheKey, out bool hasPermission))
            return hasPermission;

        var permission = await _dbContext.RolePermissions
            .Where(rp => roles.Contains(rp.RoleName) &&
                (rp.PagePath.ToLower() == normalizedPagePath || rp.PagePath.ToLower() == normalizedAreaPagePath))
            .Select(rp => rp.CanAccess)
            .FirstOrDefaultAsync();

        hasPermission = permission.GetValueOrDefault(false);
        _cache.Set(cacheKey, hasPermission, TimeSpan.FromMinutes(10));

        _logger.LogInformation($"🔑 Yetki kontrolü: Kullanıcı: {(userEntity?.UserName ?? "Guest")}, Sayfa: {areaPagePath}, Erişim: {(hasPermission ? "✅ İzin Verildi" : "❌ Engellendi")}");

        return hasPermission;
    }


}
