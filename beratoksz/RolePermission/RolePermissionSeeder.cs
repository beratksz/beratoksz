using System.Linq;
using beratoksz.Data;
using beratoksz.Models;
using Microsoft.EntityFrameworkCore;
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
        foreach (var endpoint in allEndpoints)
        {
            var normalizedPath = UrlNormalizer.Normalize(endpoint);
            bool exists = _dbContext.RolePermissions.Any(rp => rp.PagePath == normalizedPath);

            if (!exists)
            {
                _dbContext.RolePermissions.Add(new RolePermission
                {
                    RoleName = "Admin",
                    PagePath = normalizedPath,
                    CanAccess = true
                });
                Console.WriteLine($"✅ Yeni endpoint eklendi: {normalizedPath}");
            }
        }
        _dbContext.SaveChanges();
    }
}
