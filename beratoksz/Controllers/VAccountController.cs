using Microsoft.AspNetCore.Mvc;

namespace beratoksz.Controllers
{
    public class VAccountController : Controller
    {
        public IActionResult Login()
        {
            return View();
        }

        public IActionResult Logout()
        {
            return RedirectToAction("Login");
        }

        public IActionResult Register()
        {
            return View();
        }

        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpGet("reset-password")]
        public IActionResult ResetPassword(string userId, string token)
        {
            ViewBag.UserId = userId;
            ViewBag.Token = token;
            return View();
        }

        public IActionResult EmailConfirmationSent()
        {
            return View();
        }

        public IActionResult EmailSentPassword()
        {
            return View();
        }

        [HttpGet("email-confirmation")]
        public IActionResult ConfirmEmail(string userId, string token)
        {
            ViewBag.UserId = userId;
            ViewBag.Token = token;
            return View();
        }
    }
}
