using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using beratoksz.Models;

namespace beratoksz.Areas.Admin.Controllers
{
    [Area("Admin")]
    public class UserRoleController : Controller
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<AppRole> _roleManager;

        public UserRoleController(UserManager<AppUser> userManager, RoleManager<AppRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public async Task<IActionResult> Index()
        {
            var users = _userManager.Users.ToList();
            var userRoles = new List<UserRoleViewModel>();

            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                userRoles.Add(new UserRoleViewModel
                {
                    UserId = user.Id,
                    UserName = user.UserName,
                    AssignedRoles = roles.ToList()
                });
            }

            return View(userRoles);
        }

        public async Task<IActionResult> Manage(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return NotFound();

            var assignedRoles = await _userManager.GetRolesAsync(user);
            var allRoles = _roleManager.Roles.Select(r => r.Name).ToList();

            var model = new UserRoleViewModel
            {
                UserId = user.Id,
                UserName = user.UserName,
                AssignedRoles = assignedRoles.ToList(),
                AvailableRoles = allRoles.Except(assignedRoles).ToList()
            };

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Manage(UserRoleViewModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null) return NotFound();

            var existingRoles = await _userManager.GetRolesAsync(user);
            var resultRemove = await _userManager.RemoveFromRolesAsync(user, existingRoles);
            if (!resultRemove.Succeeded)
            {
                TempData["ErrorMessage"] = "Mevcut roller kaldırılırken hata oluştu.";
                return RedirectToAction("Index");
            }

            var resultAdd = await _userManager.AddToRolesAsync(user, model.AssignedRoles);
            if (!resultAdd.Succeeded)
            {
                TempData["ErrorMessage"] = "Yeni roller atanırken hata oluştu.";
                return RedirectToAction("Index");
            }

            TempData["SuccessMessage"] = "Roller başarıyla güncellendi.";
            return RedirectToAction("Index");
        }
    }
}
