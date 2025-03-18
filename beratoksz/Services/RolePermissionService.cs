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

        // Cache kontrolü (Aynı rol için tekrar sorgu atılmasın)
        var cacheKey = $"role_permissions_{string.Join("_", roles)}_{pagePath}";
        if (_cache.TryGetValue(cacheKey, out bool hasPermission))
        {
            return hasPermission;
        }

        // Kullanıcının rollerine göre erişim izni kontrolü
        var permission = await _dbContext.RolePermissions
            .Where(rp => roles.Contains(rp.RoleName) && rp.PagePath == pagePath)
            .Select(rp => rp.CanAccess)
            .FirstOrDefaultAsync();

        hasPermission = permission.GetValueOrDefault(false);

        // Cache'e ekle (10 dakika boyunca sakla)
        _cache.Set(cacheKey, hasPermission, TimeSpan.FromMinutes(10));

        _logger.LogInformation($"🔑 Yetki kontrolü: Kullanıcı: {userEntity.UserName}, Sayfa: {pagePath}, Erişim: {(hasPermission ? "✅ İzin Verildi" : "❌ Engellendi")}");

        return hasPermission;
    }
}
