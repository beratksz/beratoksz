using System.Linq;
using beratoksz.Data;
using beratoksz.Hubs;
using beratoksz.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.SqlServer.Server;
using Microsoft.Win32;
using Newtonsoft.Json.Linq;
using Serilog;
using static System.Runtime.InteropServices.JavaScript.JSType;
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
    UrlNormalizer.Normalize("/api/account/register"),
    UrlNormalizer.Normalize("/api/account/confirm-email"),
    UrlNormalizer.Normalize("/api/account/login"),
    UrlNormalizer.Normalize("/api/account/resend-confirmation"),
    UrlNormalizer.Normalize("/api/account/verify-2fa"),
    UrlNormalizer.Normalize("/api/account/resend-2fa-code"),
    UrlNormalizer.Normalize("/api/account/forgot-password"),
    UrlNormalizer.Normalize("/api/account/reset-password"),
    UrlNormalizer.Normalize("/api/account/logout"),
    UrlNormalizer.Normalize("/api/account/userinfo"),
    UrlNormalizer.Normalize("/api/account/check-auth"),
    UrlNormalizer.Normalize("/error/{statuscode}"),
    UrlNormalizer.Normalize("/home/index"),
    UrlNormalizer.Normalize("/home/accessdenied"),
    UrlNormalizer.Normalize("/home/about"),
    UrlNormalizer.Normalize("/home/contact"),
    UrlNormalizer.Normalize("/home/privacy"),
    UrlNormalizer.Normalize("/home/error"),
    UrlNormalizer.Normalize("/vaccount/login"),
    UrlNormalizer.Normalize("/vaccount/logout"),
    UrlNormalizer.Normalize("/vaccount/confirmemailresult"),
    UrlNormalizer.Normalize("/vaccount/emailconfirmationsent"),
    UrlNormalizer.Normalize("/vaccount/emailsent"),
    UrlNormalizer.Normalize("/vaccount/emailsentpassword"),
    UrlNormalizer.Normalize("/vaccount/forgotpassword"),
    UrlNormalizer.Normalize("/vaccount/register"),
    UrlNormalizer.Normalize("/email-confirmation"),
    UrlNormalizer.Normalize("/reset-password"),
    UrlNormalizer.Normalize("/api/token/login"),
    UrlNormalizer.Normalize("/api/token/refresh"),
    UrlNormalizer.Normalize("/api/token/logout"),
    UrlNormalizer.Normalize("/api/activitylog"),
    UrlNormalizer.Normalize("/api/security/activities"),
    UrlNormalizer.Normalize("/statushub")
        };

        var defaultUserPaths = new List<string>
{
    UrlNormalizer.Normalize("/api/account/register"),
    UrlNormalizer.Normalize("/api/account/confirm-email"),
    UrlNormalizer.Normalize("/api/account/login"),
    UrlNormalizer.Normalize("/api/account/resend-confirmation"),
    UrlNormalizer.Normalize("/api/account/verify-2fa"),
    UrlNormalizer.Normalize("/api/account/resend-2fa-code"),
    UrlNormalizer.Normalize("/api/account/forgot-password"),
    UrlNormalizer.Normalize("/api/account/reset-password"),
    UrlNormalizer.Normalize("/api/account/logout"),
    UrlNormalizer.Normalize("/api/account/userinfo"),
    UrlNormalizer.Normalize("/api/account/check-auth"),
    UrlNormalizer.Normalize("/error/{statuscode}"),
    UrlNormalizer.Normalize("/home/index"),
    UrlNormalizer.Normalize("/home/accessdenied"),
    UrlNormalizer.Normalize("/home/about"),
    UrlNormalizer.Normalize("/home/contact"),
    UrlNormalizer.Normalize("/home/privacy"),
    UrlNormalizer.Normalize("/home/error"),
    UrlNormalizer.Normalize("/profile/securitysettings"),
    UrlNormalizer.Normalize("/profile/updatetwofactor"),
    UrlNormalizer.Normalize("/vaccount/login"),
    UrlNormalizer.Normalize("/vaccount/logout"),
    UrlNormalizer.Normalize("/vaccount/confirmemailresult"),
    UrlNormalizer.Normalize("/vaccount/emailconfirmationsent"),
    UrlNormalizer.Normalize("/vaccount/emailsent"),
    UrlNormalizer.Normalize("/vaccount/emailsentpassword"),
    UrlNormalizer.Normalize("/vaccount/forgotpassword"),
    UrlNormalizer.Normalize("/vaccount/register"),
    UrlNormalizer.Normalize("/email-confirmation"),
    UrlNormalizer.Normalize("/reset-password"),
    UrlNormalizer.Normalize("/api/token/login"),
    UrlNormalizer.Normalize("/api/token/refresh"),
    UrlNormalizer.Normalize("/api/token/logout"),
    UrlNormalizer.Normalize("/api/activitylog"),
    UrlNormalizer.Normalize("/api/security/activities"),
    UrlNormalizer.Normalize("/statushub")
};

        var defaultAdminPaths = new List<string>
        {
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
