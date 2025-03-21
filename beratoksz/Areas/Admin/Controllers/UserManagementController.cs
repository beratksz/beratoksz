﻿using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using beratoksz.Models;
using System.Linq;
using System.Threading.Tasks;
using System;

namespace beratoksz.Areas.Admin.Controllers
{
    [Area("Admin")]
    public class UserManagementController : Controller
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<AppRole> _roleManager;

        public UserManagementController(UserManager<AppUser> userManager, RoleManager<AppRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        // Listeleme
        public IActionResult Index()
        {
            var users = _userManager.Users.ToList();
            var model = users.Select(u => new UserViewModel
            {
                Id = u.Id,
                Email = u.Email,
                // Roller asenkron alıyoruz, örnek amaçlı .Result kullanıyoruz (production’da async/await tercih edin)
                Roles = _userManager.GetRolesAsync(u).Result,
                CreatedAt = DateTime.Now // Gerçek oluşturulma tarihi eklenebilir
            });
            return View(model);
        }

        // Kullanıcı ekleme: GET
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

        // Kullanıcı ekleme: POST
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(EditUserViewModel model, string[] SelectedRoles, string Password)
        {
            // ModelState'den "Id" alanı hatasını kaldırıyoruz
            ModelState.Remove(nameof(model.Id));
            ModelState.Remove(nameof(model.NormalizedUserName));
            ModelState.Remove(nameof(model.NormalizedEmail));
            ModelState.Remove(nameof(model.PasswordHash));
            ModelState.Remove(nameof(model.SecurityStamp));
            ModelState.Remove(nameof(model.ConcurrencyStamp));
            ModelState.Remove(nameof(model.PhoneNumber));


            // Eğer SelectedRoles null ise, boş liste atıyoruz
            if (model.SelectedRoles == null)
            {
                model.SelectedRoles = new List<string>();
            }

            // Model binding hatalarını konsola yazdırıyoruz
            foreach (var key in ModelState.Keys)
            {
                foreach (var error in ModelState[key].Errors)
                {
                    Console.WriteLine($"Key: {key} Error: {error.ErrorMessage}");
                }
            }

            if (!ModelState.IsValid)
            {
                model.Roles = _roleManager.Roles.Select(r => r.Name).ToList();
                return View(model);
            }

            try
            {
                Console.WriteLine("User oluşturuluyor: " + model.Email);
                var user = new AppUser
                {
                    UserName = model.UserName,
                    Email = model.Email,
                    EmailConfirmed = true
                };
                Console.WriteLine("User oluşturuldu.");

                var result = await _userManager.CreateAsync(user, Password);

                if (result == null)
                {
                    Console.WriteLine("CreateAsync sonucu null.");
                }
                else if (!result.Succeeded)
                {
                    foreach (var error in result.Errors)
                    {
                        Console.WriteLine("Hata: " + error.Description);
                    }
                }

                if (result != null && result.Succeeded)
                {
                    await _userManager.AddToRolesAsync(user, SelectedRoles);
                    TempData["SuccessMessage"] = "Kullanıcı başarıyla oluşturuldu.";
                    return RedirectToAction("Index");
                }

                // Eğer hata varsa, hata mesajlarını ModelState'e ekliyoruz ve konsola da yazdırıyoruz
                if (result != null)
                {
                    foreach (var error in result.Errors)
                    {
                        Console.WriteLine("ModelState Hata: " + error.Description);
                        ModelState.AddModelError("", error.Description);
                    }
                }
                model.Roles = _roleManager.Roles.Select(r => r.Name).ToList();
                return View(model);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception: " + ex.Message);
                ModelState.AddModelError("", "Beklenmeyen bir hata oluştu: " + ex.Message);
                model.Roles = _roleManager.Roles.Select(r => r.Name).ToList();
                return View(model);
            }
        }



        // Kullanıcı düzenleme: GET
        [HttpGet]
        public async Task<IActionResult> Edit(string id)
        {
            Console.WriteLine("Edit GET action başlatıldı. id: " + id);

            // Kullanıcıyı veritabanından bulma
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                Console.WriteLine("User bulunamadı. id: " + id);
                return NotFound();
            }
            Console.WriteLine("User bulundu: " + user.Email);

            // Kullanıcının rollerini alıyoruz
            var userRoles = await _userManager.GetRolesAsync(user);
            Console.WriteLine("User rolleri alındı: " + string.Join(", ", userRoles));

            // Tüm rollerin listesini alıyoruz
            var allRoles = _roleManager.Roles.Select(r => r.Name).ToList();
            Console.WriteLine("Tüm roller alındı: " + string.Join(", ", allRoles));

            // EditUserViewModel oluşturuluyor
            var model = new EditUserViewModel
            {
                Id = user.Id,
                Email = user.Email,
                UserName = user.UserName,
                NormalizedUserName = user.NormalizedUserName,
                NormalizedEmail = user.NormalizedEmail,
                EmailConfirmed = user.EmailConfirmed,
                PasswordHash = user.PasswordHash,
                SecurityStamp = user.SecurityStamp,
                ConcurrencyStamp = user.ConcurrencyStamp,
                PhoneNumber = user.PhoneNumber,
                PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                TwoFactorEnabled = user.TwoFactorEnabled,
                LockoutEnd = user.LockoutEnd,
                LockoutEnabled = user.LockoutEnabled,
                AccessFailedCount = user.AccessFailedCount,
                Roles = allRoles,
                SelectedRoles = userRoles
            };
            Console.WriteLine("Model oluşturuldu. Email: " + model.Email);

            // Önceki ModelState hatalarını temizliyoruz
            ModelState.Clear();
            Console.WriteLine("ModelState temizlendi.");

            return View(model);
        }





        // Kullanıcı düzenleme: POST
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(EditUserViewModel model, string[] SelectedRoles)
        {
            if (!ModelState.IsValid)
            {
                model.Roles = _roleManager.Roles.Select(r => r.Name).ToList();
                return View(model);
            }

            var user = await _userManager.FindByIdAsync(model.Id);
            if (user == null)
            {
                ModelState.AddModelError("", "Kullanıcı bulunamadı.");
                return View(model);
            }

            // Kullanıcının bilgilerini güncelleme
            user.Email = model.Email;
            user.UserName = model.UserName;
            user.NormalizedUserName = model.NormalizedUserName;
            user.NormalizedEmail = model.NormalizedEmail;
            user.EmailConfirmed = model.EmailConfirmed;
            user.PasswordHash = model.PasswordHash;
            user.SecurityStamp = model.SecurityStamp;
            user.ConcurrencyStamp = model.ConcurrencyStamp;
            user.PhoneNumber = model.PhoneNumber;
            user.PhoneNumberConfirmed = model.PhoneNumberConfirmed;
            user.TwoFactorEnabled = model.TwoFactorEnabled;
            user.LockoutEnd = model.LockoutEnd;
            user.LockoutEnabled = model.LockoutEnabled;
            user.AccessFailedCount = model.AccessFailedCount;

            // Mevcut rolleri kaldırın ve yeni rolleri ekleyin
            var userRoles = await _userManager.GetRolesAsync(user);
            await _userManager.RemoveFromRolesAsync(user, userRoles);
            await _userManager.AddToRolesAsync(user, SelectedRoles);

            // Kullanıcıyı güncelleme
            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                foreach (var error in updateResult.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
                return View(model);
            }

            TempData["SuccessMessage"] = "Kullanıcı başarıyla güncellendi.";
            return RedirectToAction("Index");
        }


        // Kullanıcı detayları: GET
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
                UserName = user.UserName,
                AccessFailedCount = user.AccessFailedCount,
                EmailConfirmed = user.EmailConfirmed,
                PhoneNumber = user.PhoneNumber,
                PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                TwoFactorEnabled = user.TwoFactorEnabled,
                LockoutEnd = user.LockoutEnd,
                LockoutEnabled = user.LockoutEnabled,

                CreatedAt = DateTime.Now // Gerçek tarih eklenebilir
            };
            return View(model);
        }

        // Kullanıcı silme onayı: GET (Opsiyonel, onay sayfası)
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

        // Kullanıcı silme işlemi: POST
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null) return NotFound();

            var result = await _userManager.DeleteAsync(user);
            if (!result.Succeeded)
            {
                TempData["ErrorMessage"] = "Kullanıcı silinirken bir hata oluştu.";
                return RedirectToAction("Index", "UserManagement", new { area = "Admin" });
            }
            TempData["SuccessMessage"] = "Kullanıcı başarıyla silindi.";
            return RedirectToAction("Index", "UserManagement", new { area = "Admin" });
        }


    }
}
