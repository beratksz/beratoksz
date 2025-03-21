using beratoksz.Models;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace beratoksz.Extension
{
    public static class ClaimsPrincipalExtensions
    {
        public static async Task<IList<string>> GetUserRolesOrGuestAsync(this ClaimsPrincipal user, UserManager<AppUser> userManager)
        {
            if (user.Identity?.IsAuthenticated == true)
            {
                var userId = userManager.GetUserId(user);

                if (!string.IsNullOrEmpty(userId))
                {
                    var userEntity = await userManager.FindByIdAsync(userId);

                    if (userEntity != null)
                        return await userManager.GetRolesAsync(userEntity);
                }
            }

            return new List<string> { AppRoleName.Guest };
        }
    }

}
