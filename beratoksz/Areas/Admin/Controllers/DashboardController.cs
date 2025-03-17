using Microsoft.AspNetCore.Mvc;

namespace beratoksz.Areas.Admin.Controllers
{
    [Area("Admin")]
    public class DashboardController : Controller
    {
        // Dashboard üretim verileri ile dolu olacak şekilde, backend tarafında gerçek verileri gönderin.
        public IActionResult Index()
        {
            // Gerekirse başlangıç verilerini ViewBag ya da ViewModel üzerinden aktarabilirsiniz.
            return View();
        }
    }
}
