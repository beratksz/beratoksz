using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace beratoksz.Controllers
{
    public class VAccountController : Controller
    {
        [HttpGet("reset-password")]
        public IActionResult ResetPassword(string userId, string token)
        {
            // URL'den gelen userId ve token bilgilerini view'e taşıyoruz.
            ViewBag.UserId = userId;
            ViewBag.Token = token;
            return View();
        }

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Logout()
        {
            return RedirectToAction("Login");
        }
    }
}
