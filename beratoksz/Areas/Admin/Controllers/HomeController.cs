using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace beratoksz.Areas.Admin.Controllers
{
    [Area("Admin")]
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            var claims = User.Claims.Select(c => new { c.Type, c.Value }).ToList();
            // Bu bilgiyi loglayabilir veya view'e gönderebilirsiniz
            return View(claims);
        }

    }
}
