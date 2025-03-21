using System.Security.Claims;
using System.Threading.Tasks;
using beratoksz.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace beratoksz
{
    public class AdditionalUserClaimsPrincipalFactory : UserClaimsPrincipalFactory<AppUser, AppRole>
    {
        public AdditionalUserClaimsPrincipalFactory(
            UserManager<AppUser> userManager,
            RoleManager<AppRole> roleManager,
            IOptions<IdentityOptions> optionsAccessor)
            : base(userManager, roleManager, optionsAccessor)
        {
        }

        protected override async Task<ClaimsIdentity> GenerateClaimsAsync(AppUser user)
        {
            var identity = await base.GenerateClaimsAsync(user);
            var roles = await UserManager.GetRolesAsync(user);
            foreach (var role in roles)
            {
                identity.AddClaim(new Claim(ClaimTypes.Role, role));
            }
            return identity;
        }
    }
}
