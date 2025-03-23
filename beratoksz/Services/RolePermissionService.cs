using beratoksz.Data;
using beratoksz.Extension; // Eklenen using ifadesi
using beratoksz.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

public class RolePermissionService
{
    private readonly ApplicationDbContext _dbContext;
    private readonly UserManager<AppUser> _userManager;
    private readonly IMemoryCache _cache;
    private readonly ILogger<RolePermissionService> _logger;
    private readonly IServiceScopeFactory _scopeFactory;


    public RolePermissionService(
        ApplicationDbContext dbContext,
        UserManager<AppUser> userManager,
        IMemoryCache cache,
        ILogger<RolePermissionService> logger,
        IServiceScopeFactory scopeFactory)
    {
        _dbContext = dbContext;
        _userManager = userManager;
        _cache = cache;
        _logger = logger;
        _scopeFactory = scopeFactory;

    }

    public async Task<bool> HasAccess(ClaimsPrincipal user, string pagePath)
    {
        var roles = await user.GetUserRolesOrGuestAsync(_userManager);

        var normalizedPagePath = NormalizePath(pagePath);
        var areaPagePath = normalizedPagePath.StartsWith("/admin") || normalizedPagePath.StartsWith("/user")
            ? normalizedPagePath
            : $"/{normalizedPagePath.TrimStart('/')}";

        // Regex ile ID parametresini `{id}` olarak normalize et (opsiyonel)
        var simplifiedPath = System.Text.RegularExpressions.Regex.Replace(areaPagePath, @"\/[a-f0-9\-]{36}$", "/{id}");

        if (!areaPagePath.EndsWith("/index", StringComparison.OrdinalIgnoreCase))
        {
            var dbPaths = _dbContext.RolePermissions.Select(rp => rp.PagePath.ToLower()).ToList();
            var withIndex = $"{areaPagePath}/index";

            if (dbPaths.Contains(withIndex))
            {
                areaPagePath = withIndex;
                simplifiedPath = withIndex;
            }
        }

        var cacheKey = $"role_permissions_{string.Join("_", roles)}_{simplifiedPath}";
        if (_cache.TryGetValue(cacheKey, out bool cachedAccess))
            return cachedAccess;

        var access = await _dbContext.RolePermissions
            .Where(rp => roles.Contains(rp.RoleName) &&
                        (normalizedPagePath.StartsWith(rp.PagePath) || simplifiedPath.StartsWith(rp.PagePath)))
            .Select(rp => rp.CanAccess)
            .FirstOrDefaultAsync();

        var hasAccess = access.GetValueOrDefault(false);
        _cache.Set(cacheKey, hasAccess, TimeSpan.FromMinutes(10));

        _logger.LogInformation("[DEBUG] Gelen path: {RawPath}, Normalize: {Norm}, AreaPath: {Area}, Simple: {Simple}",
            pagePath, normalizedPagePath, areaPagePath, simplifiedPath);

        _logger.LogInformation("[DEBUG] DB'deki yollar: {Paths}",
            string.Join(" | ", _dbContext.RolePermissions.Select(x => x.PagePath)));

        var userName = user.Identity?.Name ?? "Misaifr(Guest)";
        _logger.LogInformation("[RolePermission Service] Yetki kontrolü: Kullanıcı: {User}, Roller: {Roles}, Sayfa: {Path}, Erişim: {Access}",
        userName,
        string.Join(", ", roles),
        areaPagePath,
        hasAccess ? "✅ İzin Verildi" : "❌ Engellendi");

        return hasAccess;
    }

    private string NormalizePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return "/";

        var normalized = path.Trim().ToLower().Replace("//", "/");
        return string.IsNullOrEmpty(normalized) ? "/" : normalized;
    }
}