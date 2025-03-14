using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using beratoksz.Models;
using System.Linq;
using System.Threading.Tasks;
using System;

namespace beratoksz.Areas.Admin.Controllers
{
    [Area("Admin")]
    [Authorize(Roles = "Admin")]
    public class UserManagementController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserManagementController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public IActionResult Index()
        {
            var users = _userManager.Users.ToList();
            var model = users.Select(u => new UserViewModel
            {
                Id = u.Id,
                Email = u.Email,
                // Roller asenkron alıyoruz, örnek amaçlı .Result
                Roles = _userManager.GetRolesAsync(u).Result,
                CreatedAt = DateTime.Now // Örnek, gerçekte veritabanından gelmeli
            });
            return View(model);
        }

        [HttpGet]
        public IActionResult Create()
        {
            var model = new EditUserViewModel
            {
                Roles = _roleManager.Roles.Select(r => r.Name).ToList(),
                SelectedRoles = new List<string>()
            };
            return View(model);
        }

        [HttpPost]
public async Task<IActionResult> Create(EditUserViewModel model, string[] SelectedRoles, string Password)
{
    ModelState.Remove("Id");

    if (model.SelectedRoles == null)
    {
        model.SelectedRoles = new List<string>();
    }

    if (!ModelState.IsValid)
    {
        model.Roles = _roleManager.Roles.Select(r => r.Name).ToList();
        return View(model);
    }
    try
    {
        var user = new IdentityUser
        {
            UserName = model.Email,
            Email = model.Email,
            EmailConfirmed = true
        };
        var result = await _userManager.CreateAsync(user, Password);
        if (result.Succeeded)
        {
            await _userManager.AddToRolesAsync(user, SelectedRoles);
            ViewData["SuccessMessage"] = "Kullanıcı başarıyla oluşturuldu.";
            return RedirectToAction("Index");
        }
        foreach (var error in result.Errors)
        {
            ModelState.AddModelError("", error.Description);
        }
        model.Roles = _roleManager.Roles.Select(r => r.Name).ToList();
        return View(model);
    }
    catch (Exception ex)
    {
        ModelState.AddModelError("", "Beklenmeyen bir hata oluştu: " + ex.Message);
        model.Roles = _roleManager.Roles.Select(r => r.Name).ToList();
        return View(model);
    }
}



        [HttpGet]
        public async Task<IActionResult> Edit(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null) return NotFound();

            var userRoles = await _userManager.GetRolesAsync(user);
            var allRoles = _roleManager.Roles.Select(r => r.Name).ToList();

            var model = new EditUserViewModel
            {
                Id = user.Id,
                Email = user.Email,
                Roles = allRoles,
                SelectedRoles = userRoles
            };
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Edit(EditUserViewModel model, string[] SelectedRoles)
        {
            if (!ModelState.IsValid)
            {
                model.Roles = _roleManager.Roles.Select(r => r.Name).ToList();
                return View(model);
            }
            var user = await _userManager.FindByIdAsync(model.Id);
            if (user == null) return NotFound();

            // Mevcut rolleri kaldır
            var userRoles = await _userManager.GetRolesAsync(user);
            await _userManager.RemoveFromRolesAsync(user, userRoles);

            // Yeni rolleri ekle
            await _userManager.AddToRolesAsync(user, SelectedRoles);

            return RedirectToAction("Index");
        }

        [HttpGet]
        public async Task<IActionResult> Details(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null) return NotFound();

            var roles = await _userManager.GetRolesAsync(user);
            var model = new UserViewModel
            {
                Id = user.Id,
                Email = user.Email,
                Roles = roles,
                CreatedAt = DateTime.Now // Örnek
            };
            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> Delete(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null) return NotFound();

            var roles = await _userManager.GetRolesAsync(user);
            var model = new UserViewModel
            {
                Id = user.Id,
                Email = user.Email,
                Roles = roles,
                CreatedAt = DateTime.Now
            };
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [ActionName("DeleteConfirmed")]
        public async Task<IActionResult> DeleteConfirmed(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null) return NotFound();

            var result = await _userManager.DeleteAsync(user);
            if (!result.Succeeded)
            {
                // Hata durumunda geri bildirim
                TempData["ErrorMessage"] = "Kullanıcı silinirken bir hata oluştu.";
                return RedirectToAction("Index");
            }
            TempData["SuccessMessage"] = "Kullanıcı başarıyla silindi.";
            return RedirectToAction("Index", "UserManagement", new { area = "Admin" });
        }


    }
}
