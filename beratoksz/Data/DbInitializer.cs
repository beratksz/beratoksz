using beratoksz.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading.Tasks;

namespace beratoksz.Data
{
    public static class DbInitializer
    {
        public static async Task InitializeAsync(IServiceProvider serviceProvider)
        {
            using (var scope = serviceProvider.CreateScope())
            {
                var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<AppRole>>();
                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<AppUser>>();

                // Roller tanımlanıyor: Admin ve User (sonradan eklenebilir yapı)
                string[] roles = new string[] { "Admin", "Guest" , "User" };
                foreach (var role in roles)
                {
                    if (!await roleManager.RoleExistsAsync(role))
                    {
                        await roleManager.CreateAsync(new AppRole(role));
                    }
                }

                // Admin kullanıcı seeding: Bu bilgiler deploy sonrası sistemin ilk admin kullanıcısını oluşturur
                string adminEmail = "admin@example.com";
                string adminPassword = "Admin123!";
                var adminUser = await userManager.FindByEmailAsync(adminEmail);

                if (adminUser == null)
                {
                    adminUser = new AppUser
                    {
                        UserName = adminEmail,
                        Email = adminEmail,
                        EmailConfirmed = true
                    };
                    var result = await userManager.CreateAsync(adminUser, adminPassword);
                    if (result.Succeeded)
                    {
                        await userManager.AddToRoleAsync(adminUser, "Admin");
                    }
                }
            }
        }
    }
}
