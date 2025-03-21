using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using beratoksz.Models;

namespace beratoksz.Data
{
    public class ApplicationDbContext : IdentityDbContext<AppUser, AppRole, string>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.ApplyConfiguration(new AppRoleConfiguration());

            // Diğer configler varsa:
            // modelBuilder.ApplyConfiguration(new AppUserConfiguration());
        }



        // DbSet properties go here
        // public DbSet<YourEntity> YourEntities { get; set; }

        public DbSet<RefreshToken> RefreshTokens { get; set; }
        public DbSet<ActivityLog> ActivityLogs { get; set; }
        public DbSet<UserSecurityActivity> UserSecurityActivities { get; set; }
        public DbSet<RolePermission> RolePermissions { get; set; }

    }
}
