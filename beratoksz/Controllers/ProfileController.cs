using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using beratoksz.Models;
using Microsoft.AspNetCore.Identity;

namespace beratoksz.Controllers
{
    [Authorize]
    public class ProfileController : Controller
    {
        private readonly UserManager<AppUser> _userManager;

        public ProfileController(UserManager<AppUser> userManager)
        {
            _userManager = userManager;
        }

        [HttpGet]
        public async Task<IActionResult> SecuritySettings()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return RedirectToAction("Login", "VAccount"); // Yedeğe alın

            return View(user); // View'e kullanıcı modelini gönderiyoruz ✅
        }
    }

}
