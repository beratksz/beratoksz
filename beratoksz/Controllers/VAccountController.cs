using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace beratoksz.Controllers
{
    public class VAccountController : Controller
    {
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
