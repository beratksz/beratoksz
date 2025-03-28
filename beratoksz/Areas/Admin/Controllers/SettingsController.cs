using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using beratoksz.Models;
using beratoksz.Services;
using beratoksz.Controllers;

namespace beratoksz.Areas.Admin.Controllers
{
    [Area("Admin")]
    public class SettingsController : Controller
    {
        private readonly SettingsService _settingsService;
        private readonly ILogger<SettingsController> _logger;

        public SettingsController(SettingsService settingsService,
                                    ILogger<SettingsController> logger)
        {
            _settingsService = settingsService;
            _logger = logger;
        }

        // Ana ayar sayfası: Liste ve form
        [HttpGet]
        public async Task<IActionResult> Index(int? id)
        {
            var allSettings = await _settingsService.GetAllSettingsAsync();
            if (allSettings == null || allSettings.Count == 0)
            {
                // Default ayarları oluştur
                var defaultSettings = new SiteSettings
                {
                    EnableEmailVerification = false,
                    EnableTwoFactorAuthentication = false,
                    SmtpHost = "",
                    SmtpPort = 25,
                    SmtpUsername = "",
                    SmtpPassword = "",
                    EmailFromAddress = "",
                    EmailFromName = "",
                    EmailVerificationTemplate = "<p>Lütfen emailinizi doğrulamak için <a href='{LINK}'>buraya tıklayın</a>.</p>",
                    TwoFactorEmailTemplate = "<p>Doğrulama kodunuz: {CODE}</p>",
                    PasswordResetEmailTemplate = "<p>Doğrulama kodunuz: {LINK}</p>",
                    PhoneVerificationTemplate = "<p>WhatsApp doğrulama kodunuz: {CODE}</p>",
                    SmsSenderPhoneNumber = "+905xxxxxxxxx",
                    IsActive = false
                };
                await _settingsService.CreateSettingsAsync(defaultSettings);
                allSettings = await _settingsService.GetAllSettingsAsync();
            }

            var model = new SettingsViewModel
            {
                SettingsList = allSettings
            };

            if (id.HasValue)
            {
                var settings = await _settingsService.GetSettingsByIdAsync(id.Value);
                model.CurrentSettings = settings ?? new SiteSettings();
            }
            else
            {
                // Varsayılan olarak, yeni bir kayıt oluştur
                model.CurrentSettings = new SiteSettings();
            }

            return View(model);
        }



        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Save(SettingsViewModel model)
        {
            if (ModelState.IsValid)
            {
                if (model.CurrentSettings.Id > 0)
                {
                    await _settingsService.UpdateSettingsAsync(model.CurrentSettings);
                }
                else
                {
                    await _settingsService.CreateSettingsAsync(model.CurrentSettings);
                }
                TempData["SuccessMessage"] = "Ayarlar kaydedildi.";
                return RedirectToAction("Index");
            }

            _logger.LogInformation("Admin '{Admin}' updated settings ID {Id}", User.Identity.Name, model.CurrentSettings.Id);
            model.SettingsList = await _settingsService.GetAllSettingsAsync();
            return View("Index", model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Activate(int id)
        {
            var allSettings = await _settingsService.GetAllSettingsAsync();
            foreach (var s in allSettings)
            {
                s.IsActive = false;
                await _settingsService.UpdateSettingsAsync(s);
            }
            var settings = await _settingsService.GetSettingsByIdAsync(id);
            if (settings != null)
            {
                settings.IsActive = true;
                await _settingsService.UpdateSettingsAsync(settings);
                TempData["SuccessMessage"] = "Seçilen ayarlar aktifleştirildi.";
            }
            return RedirectToAction("Index");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(int id)
        {
            var settings = await _settingsService.GetSettingsByIdAsync(id);
            if (settings != null)
            {
                await _settingsService.DeleteSettingsAsync(settings);
                TempData["SuccessMessage"] = "Ayar kaydı silindi.";
            }
            return RedirectToAction("Index");
        }

    }
}
