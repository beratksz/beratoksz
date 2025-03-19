using beratoksz.Data;
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
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IMemoryCache _cache;
    private readonly ILogger<RolePermissionService> _logger;

    public RolePermissionService(ApplicationDbContext dbContext, UserManager<IdentityUser> userManager, IMemoryCache cache, ILogger<RolePermissionService> logger)
    {
        _dbContext = dbContext;
        _userManager = userManager;
        _cache = cache;
        _logger = logger;
    }

    public async Task<bool> HasAccess(ClaimsPrincipal user, string pagePath)
    {
        if (user == null || !user.Identity.IsAuthenticated)
        {
            _logger.LogWarning($"🚫 Yetkisiz erişim denemesi: Giriş yapılmamış! Sayfa: {pagePath}");
            return false;
        }

        var userId = _userManager.GetUserId(user);
        var userEntity = await _userManager.FindByIdAsync(userId);

        if (userEntity == null)
        {
            _logger.LogError($"⚠ Kullanıcı bulunamadı! ID: {userId}");
            return false;
        }

        // Kullanıcının rollerini al
        var roles = await _userManager.GetRolesAsync(userEntity);

        // Area desteği için ek kontrol
        var areaPagePath = pagePath.StartsWith("/admin") || pagePath.StartsWith("/user") ? pagePath : $"/{pagePath}";

        // Cache kontrolü
        var cacheKey = $"role_permissions_{string.Join("_", roles)}_{areaPagePath}";
        if (_cache.TryGetValue(cacheKey, out bool hasPermission))
        {
            return hasPermission;
        }

        // Kullanıcının rollerine göre erişim izni kontrolü (Area desteğiyle)
        var permission = await _dbContext.RolePermissions
            .Where(rp => roles.Contains(rp.RoleName) && (rp.PagePath == pagePath || rp.PagePath == areaPagePath))
            .Select(rp => rp.CanAccess)
            .FirstOrDefaultAsync();

        hasPermission = permission.GetValueOrDefault(false);

        // Cache'e ekle (10 dakika boyunca sakla)
        _cache.Set(cacheKey, hasPermission, TimeSpan.FromMinutes(10));

        _logger.LogInformation($"🔑 Yetki kontrolü: Kullanıcı: {userEntity.UserName}, Sayfa: {areaPagePath}, Erişim: {(hasPermission ? "✅ İzin Verildi" : "❌ Engellendi")}");

        return hasPermission;
    }

}
