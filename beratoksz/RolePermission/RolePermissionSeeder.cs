using System.Linq;
using beratoksz.Data;
using beratoksz.Models;
using static PageDiscoveryService;

public class RolePermissionSeeder
{
    private readonly ApplicationDbContext _dbContext;

    public RolePermissionSeeder(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public void SeedPermissions(List<string> allEndpoints)
    {
        var defaultGuestPaths = new List<string>
        {
            UrlNormalizer.Normalize("/Home/Index"),
            UrlNormalizer.Normalize("/Home/About"),
            UrlNormalizer.Normalize("/Home/Contact"),
            UrlNormalizer.Normalize("/Privacy"),
            UrlNormalizer.Normalize("/VAccount/Login"),
            UrlNormalizer.Normalize("/VAccount/Register"),
            UrlNormalizer.Normalize("/VAccount/ForgetPassword"),
            UrlNormalizer.Normalize("/VAccount/2FA"),
            UrlNormalizer.Normalize("/Home/Error"),
            UrlNormalizer.Normalize("/NotFound"),
            UrlNormalizer.Normalize("/Home/AccessDenied"),
            UrlNormalizer.Normalize("/Home/Error/*"),
            UrlNormalizer.Normalize("/NotFound/*"),
            UrlNormalizer.Normalize("/Home/AccessDenied/*"),
            UrlNormalizer.Normalize("/api/account/check-auth"),
            UrlNormalizer.Normalize("/api/account/userinfo"),
            UrlNormalizer.Normalize("/api/account/register"),
            UrlNormalizer.Normalize("/api/account/login"),
            UrlNormalizer.Normalize("/api/security/activities")
        };

        var defaultUserPaths = new List<string>
        {
            UrlNormalizer.Normalize("/Home/Index"),
            UrlNormalizer.Normalize("/Home/About"),
            UrlNormalizer.Normalize("/Home/Contact"),
            UrlNormalizer.Normalize("/Privacy"),
            UrlNormalizer.Normalize("/VAccount/Login"),
            UrlNormalizer.Normalize("/VAccount/Register"),
            UrlNormalizer.Normalize("/VAccount/ForgetPassword"),
            UrlNormalizer.Normalize("/VAccount/2FA"),
            UrlNormalizer.Normalize("/Home/Error"),
            UrlNormalizer.Normalize("/NotFound"),
            UrlNormalizer.Normalize("/Home/AccessDenied"),
            UrlNormalizer.Normalize("/Home/Error/*"),
            UrlNormalizer.Normalize("/NotFound/*"),
            UrlNormalizer.Normalize("/Home/AccessDenied/*"),
            UrlNormalizer.Normalize("/api/account/check-auth"),
            UrlNormalizer.Normalize("/api/account/userinfo"),
            UrlNormalizer.Normalize("/api/account/register"),
            UrlNormalizer.Normalize("/api/account/login"),
            UrlNormalizer.Normalize("/api/account/logout"),
            UrlNormalizer.Normalize("/api/account/refresh-token"),
            UrlNormalizer.Normalize("/api/account/change-password"),
            UrlNormalizer.Normalize("/api/account/update-profile"),
            UrlNormalizer.Normalize("/api/security/activities")
        };

        var defaultAdminPaths = new List<string>
        {
            UrlNormalizer.Normalize("/Home/Error"),
            UrlNormalizer.Normalize("/NotFound"),
            UrlNormalizer.Normalize("/Home/AccessDenied"),
            UrlNormalizer.Normalize("/Home/Error/*"),
            UrlNormalizer.Normalize("/NotFound/*"),
            UrlNormalizer.Normalize("/Home/AccessDenied/*"),
        };

        foreach (var endpoint in allEndpoints.Distinct())
        {
            var normalizedPath = UrlNormalizer.Normalize(endpoint);

            if (string.IsNullOrWhiteSpace(normalizedPath) || normalizedPath == "/")
                continue;

            // Admin için
            if (!_dbContext.RolePermissions.Any(rp => rp.PagePath == normalizedPath && rp.RoleName == "Admin"))
            {
                _dbContext.RolePermissions.Add(new RolePermission
                {
                    RoleName = "Admin",
                    PagePath = normalizedPath,
                    CanAccess = true
                });
                Console.WriteLine($"✅ [Admin] {normalizedPath}");
            }

            if (defaultAdminPaths.Contains(normalizedPath) &&
                !_dbContext.RolePermissions.Any(rp => rp.PagePath == normalizedPath && rp.RoleName == "Admin"))
            {
                _dbContext.RolePermissions.Add(new RolePermission
                {
                    RoleName = "Admin",
                    PagePath = normalizedPath,
                    CanAccess = true
                });
                Console.WriteLine($"👥 [Admin] {normalizedPath}");
            }

            // Guest için
            if (defaultGuestPaths.Contains(normalizedPath) &&
                !_dbContext.RolePermissions.Any(rp => rp.PagePath == normalizedPath && rp.RoleName == "Guest"))
            {
                _dbContext.RolePermissions.Add(new RolePermission
                {
                    RoleName = "Guest",
                    PagePath = normalizedPath,
                    CanAccess = true
                });
                Console.WriteLine($"👥 [Guest] {normalizedPath}");
            }
            // User için
            if (defaultUserPaths.Contains(normalizedPath) &&
                !_dbContext.RolePermissions.Any(rp => rp.PagePath == normalizedPath && rp.RoleName == "User"))
            {
                _dbContext.RolePermissions.Add(new RolePermission
                {
                    RoleName = "User",
                    PagePath = normalizedPath,
                    CanAccess = true
                });
                Console.WriteLine($"👥 [User] {normalizedPath}");
            }
        }

        _dbContext.SaveChanges();
    }
}
