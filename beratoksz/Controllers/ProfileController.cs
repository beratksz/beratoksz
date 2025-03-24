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
                return RedirectToAction("Login", "VAccount");

            return View(user);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> UpdateTwoFactor(bool enable)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return Unauthorized();

            user.TwoFactorEnabled = enable;
            var result = await _userManager.UpdateAsync(user);
            if (result.Succeeded)
            {
                TempData["Message"] = "Güvenlik ayarları güncellendi.";
                return RedirectToAction("SecuritySettings");
            }
            TempData["Error"] = "Güncelleme sırasında bir hata oluştu.";
            return RedirectToAction("SecuritySettings");
        }
    }
}
