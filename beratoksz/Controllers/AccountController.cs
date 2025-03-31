using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using beratoksz.Models;
using beratoksz.Data;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity.UI.Services;
using beratoksz.Services;
using System.Net;

namespace beratoksz.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly TwoFactorEmailService _twoFactorEmailService;
        private readonly UserSecurityService _userSecurityService;
        private readonly SettingsService _settingsService;
        private readonly EmailConfirmationService _emailConfirmationService;
        private readonly ILogger<AccountController> _logger;
        private readonly PasswordResetEmailService _passwordResetEmailService;
        private readonly SmsService _smsService;

        public AccountController(UserManager<AppUser> userManager,
                                 SignInManager<AppUser> signInManager,
                                 IConfiguration configuration,
                                 ApplicationDbContext context,
                                 TwoFactorEmailService twoFactorEmailService,
                                 UserSecurityService userSecurityService,
                                 SettingsService settingsService,
                                 EmailConfirmationService emailConfirmationService,
                                 ILogger<AccountController> logger,
                                 PasswordResetEmailService passwordResetEmailService,
                                 SmsService smsService)
        {
            _userManager = userManager;
            _configuration = configuration;
            _signInManager = signInManager;
            _twoFactorEmailService = twoFactorEmailService;
            _userSecurityService = userSecurityService;
            _settingsService = settingsService;
            _emailConfirmationService = emailConfirmationService;
            _logger = logger;
            _passwordResetEmailService = passwordResetEmailService;
            _smsService = smsService;
        }

        [HttpPost("register")]
        [Throttle(300)]
        public async Task<IActionResult> Register([FromBody] RegisterViewModel model)
        {
            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Register attempt failed due to invalid model state.");
                return BadRequest(ModelState);
            }

            var userExists = await _userManager.FindByEmailAsync(model.Email);
            if (userExists != null)
            {
                _logger.LogWarning("Registration failed: Email {Email} is already in use.", model.Email);
                return BadRequest(new { message = "Bu e-posta adresi zaten kayıtlı." });
            }

            

            var user = new AppUser
            {
                UserName = model.UserName,
                Email = model.Email,
                PhoneNumber = model.PhoneNumber
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                _logger.LogError("Registration failed for email {Email}: {Errors}", model.Email, errors);
                return BadRequest(result.Errors);
            }

            await _userManager.AddToRoleAsync(user, "User");
            _logger.LogInformation("User registered: {UserId}, Email: {Email}", user.Id, user.Email);

            // Email doğrulaması için token üret
            var emailToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var safeToken = WebUtility.UrlEncode(emailToken); // using System.Net;
            var confirmationLink = Url.Action("ConfirmEmail", "VAccount", new { userId = user.Id, token = safeToken }, Request.Scheme);
            try
            {
                await _emailConfirmationService.SendConfirmationEmailAsync(user.Email, confirmationLink);
                _logger.LogInformation("Confirmation email sent to {Email}", user.Email);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send confirmation email to {Email}", user.Email);
                // İsteğe bağlı: hata mesajı dönmek veya devam etmek
            }

            return Ok(new { message = "Kayıt başarılı. Lütfen emailinizi kontrol edin.", redirectUrl = "/VAccount/EmailConfirmationSent" });
        }

        [HttpGet("confirm-email")]
        [Throttle(300)]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
                return BadRequest(new { success = false, message = "Doğrulama linki hatalı veya eksik." });

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return BadRequest(new { success = false, message = "Kullanıcı bulunamadı." });

            if (user.EmailConfirmed)
                return BadRequest(new { success = false, message = "Email zaten doğrulanmış." });

            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
                return Ok(new { success = true, message = "Email adresin başarıyla doğrulandı." });

            return BadRequest(new { success = false, message = "Email doğrulama başarısız oldu veya link geçerliliğini yitirmiş." });
        }


        [HttpGet("GetEmailByUserId")]
        public async Task<IActionResult> GetEmailByUserId(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound(new { email = "" });

            return Ok(new { email = user.Email });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userManager.FindByEmailAsync(model.LoginIdentifier) ??
                       await _userManager.FindByNameAsync(model.LoginIdentifier);

            if (user == null || !(await _userManager.CheckPasswordAsync(user, model.Password)))
            {
                if (user != null)
                {
                    await _userSecurityService.LogActivity(user.Id, "FailedLogin", HttpContext.Connection.RemoteIpAddress.ToString(), Request.Headers["User-Agent"].ToString(), false);
                }
                return Unauthorized(new { message = "Geçersiz giriş bilgileri" });
            }

            // Email doğrulaması kontrolü
            if (!user.EmailConfirmed)
            {
                return Unauthorized(new { message = "Email doğrulaması yapılmamış. Lütfen emailinizi kontrol ediniz." });
            }

            // 2FA kontrolü (aktif ayarlar üzerinden kontrol edilebilir)
            var settings = await _settingsService.GetActiveSettingsAsync();
            if (settings != null && settings.EnableTwoFactorAuthentication && await _userManager.GetTwoFactorEnabledAsync(user))
            {
                var code = new Random().Next(100000, 999999).ToString();
                HttpContext.Session.SetString("2FACode", code);
                HttpContext.Session.SetString("2FAUserId", user.Id);
                HttpContext.Session.SetString("2FA_ExpireTime", DateTime.UtcNow.AddMinutes(5).ToString());

                await _twoFactorEmailService.SendCodeAsync(user.Email, code);
                await _userSecurityService.LogActivity(user.Id, "2FARequested", HttpContext.Connection.RemoteIpAddress.ToString(), Request.Headers["User-Agent"].ToString(), true);
                return Ok(new { requires2FA = true, message = "Doğrulama kodu e-posta ile gönderildi." });
            }

            // Kullanıcıyı oturuma al ve kimlik doğrulamayı güncelle
            await _signInManager.SignInAsync(user, isPersistent: model.RememberMe);

            // JWT oluştur
            var token = GenerateJwtToken(user);
            var refreshToken = Guid.NewGuid().ToString();

            // Cookie olarak set et
            SetAuthCookies(token, refreshToken);

            await _userSecurityService.LogActivity(user.Id, "Login", HttpContext.Connection.RemoteIpAddress.ToString(), HttpContext.Request.Headers["User-Agent"].ToString(), true);
            return Ok(new { message = "Giriş başarılı!", redirectUrl = "/" });
        }

        [HttpPost("resend-confirmation")]
        [Throttle(300)]
        public async Task<IActionResult> ResendConfirmation([FromBody] ResendConfirmationDto model)
        {
            if (string.IsNullOrWhiteSpace(model.Email))
                return BadRequest(new { message = "Email gerekli." });

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return NotFound(new { message = "Kullanıcı bulunamadı." });

            if (user.EmailConfirmed)
                return BadRequest(new { message = "Email zaten doğrulanmış." });

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var safeToken = WebUtility.UrlEncode(token); // ✅ SADECE BURADA ENCODE
            var confirmationLink = Url.Action("ConfirmEmail", "VAccount", new { userId = user.Id, token = safeToken }, Request.Scheme);

            try
            {
                await _emailConfirmationService.SendConfirmationEmailAsync(user.Email, confirmationLink);
                _logger.LogInformation("Resend confirmation email sent to {Email}", user.Email);
                return Ok(new { message = "Doğrulama emaili tekrar gönderildi. Lütfen emailinizi kontrol edin." });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to resend confirmation email to {Email}", user.Email);
                return StatusCode(500, new { message = "Email gönderilemedi." });
            }
        }


        [HttpPost("verify-2fa")]
        [Throttle(300)]
        public async Task<IActionResult> Verify2FA([FromBody] Verify2FADto dto)
        {
            var code = HttpContext.Session.GetString("2FACode");
            var userId = HttpContext.Session.GetString("2FAUserId");

            if (DateTime.TryParse(HttpContext.Session.GetString("2FA_ExpireTime"), out var expireTime))
            {
                if (DateTime.UtcNow > expireTime)
                    return Unauthorized(new { message = "Doğrulama kodunun süresi doldu." });
            }

            if (dto.Code != code)
                return Unauthorized(new { message = "Doğrulama kodu yanlış." });

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return Unauthorized(new { message = "Kullanıcı bulunamadı." });

            await _signInManager.SignInAsync(user, isPersistent: false);
            var token = GenerateJwtToken(user);
            var refreshToken = Guid.NewGuid().ToString();
            SetAuthCookies(token, refreshToken);

            // Session'ı temizle
            HttpContext.Session.Remove("2FACode");
            HttpContext.Session.Remove("2FAUserId");
            HttpContext.Session.Remove("2FA_ExpireTime");

            return Ok(new { success = true, message = "2FA doğrulandı!", redirectUrl = "/" });
        }

        [HttpPost("resend-2fa-code")]
        [Throttle(300)]
        public async Task<IActionResult> ResendTwoFactorCode([FromBody] Resend2FADto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.LoginIdentifier)
                       ?? await _userManager.FindByNameAsync(dto.LoginIdentifier);

            if (user == null) return NotFound(new { message = "Kullanıcı bulunamadı." });

            var code = new Random().Next(100000, 999999).ToString();
            HttpContext.Session.SetString("2FACode", code);
            HttpContext.Session.SetString("2FAUserId", user.Id);
            HttpContext.Session.SetString("2FA_ExpireTime", DateTime.UtcNow.AddMinutes(5).ToString());

            await _twoFactorEmailService.SendCodeAsync(user.Email, code);
            return Ok(new { message = "Yeni doğrulama kodu gönderildi." });
        }

        public class Resend2FADto
        {
            public string LoginIdentifier { get; set; }
        }


        [HttpPost("forgot-password")]
        [Throttle(300)]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDto model)
        {
            if (string.IsNullOrWhiteSpace(model.Email))
                return BadRequest(new { message = "Email gerekli." });

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return NotFound(new { message = "Kullanıcı bulunamadı." });

            var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
            var resetLink = Url.Action("ResetPassword", "VAccount", new { userId = user.Id, token = resetToken }, Request.Scheme);

            try
            {
                await _passwordResetEmailService.SendPasswordResetEmailAsync(user.Email, resetLink);
                _logger.LogInformation("Password reset email sent to {Email}", user.Email);
                return Ok(new { message = "Şifre sıfırlama emaili gönderildi. Lütfen emailinizi kontrol edin." });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send password reset email to {Email}", user.Email);
                return StatusCode(500, new { message = "Email gönderilemedi." });
            }
        }

        [HttpPost("reset-password")]
        [Throttle(300)]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto model)
        {


            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null)
                return NotFound(new { message = "Kullanıcı bulunamadı." });

            var result = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);
            if (result.Succeeded)
            {
                _logger.LogInformation("Password reset successful for {Email}", user.Email);
                return Ok(new { message = "Şifre sıfırlama başarılı. Artık yeni şifrenizle giriş yapabilirsiniz." });
            }
            else
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                _logger.LogError("Password reset failed for {Email}: {Errors}", user.Email, errors);
                return BadRequest(new { message = "Şifre sıfırlama başarısız.", errors });
            }

        }

        [Authorize]
        [HttpPost("update-security-settings")]
        [Throttle(300)]

        public async Task<IActionResult> UpdateSecuritySettings([FromBody] AccountSecurityUpdateDto dto)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return Unauthorized(new { message = "Kullanıcı bulunamadı." });

            var messages = new List<string>();
            var isModified = false;

            // Kullanıcı adı güncelleme
            if (!string.IsNullOrWhiteSpace(dto.UserName) && dto.UserName != user.UserName)
            {
                user.UserName = dto.UserName;
                isModified = true;
                messages.Add("Kullanıcı adı güncellendi.");
            }

            // Telefon numarası
            if (!string.IsNullOrWhiteSpace(dto.PhoneNumber) && dto.PhoneNumber != user.PhoneNumber)
            {
                user.PhoneNumber = dto.PhoneNumber;
                user.PhoneNumberConfirmed = false;
                isModified = true;
                messages.Add("Telefon numarası güncellendi. Onay bekleniyor.");
            }

            // 2FA kontrolü
            if (dto.EnableTwoFactor.HasValue && dto.EnableTwoFactor != user.TwoFactorEnabled)
            {
                user.TwoFactorEnabled = dto.EnableTwoFactor.Value;
                isModified = true;
                messages.Add($"2FA {(dto.EnableTwoFactor.Value ? "aktif" : "pasif")} hale getirildi.");
            }

            // Şifre güncelleme
            if (!string.IsNullOrWhiteSpace(dto.NewPassword))
            {
                if (dto.NewPassword != dto.ConfirmPassword)
                    return BadRequest(new { message = "Yeni şifreler uyuşmuyor." });

                if (string.IsNullOrWhiteSpace(dto.CurrentPassword))
                    return BadRequest(new { message = "Mevcut şifre gereklidir." });

                var passwordResult = await _userManager.ChangePasswordAsync(user, dto.CurrentPassword, dto.NewPassword);
                if (!passwordResult.Succeeded)
                {
                    var errors = passwordResult.Errors.Select(e => e.Description);
                    return BadRequest(new { message = "Şifre değiştirilemedi.", errors });
                }

                messages.Add("Şifre başarıyla güncellendi.");
            }

            // Değişiklikleri kaydet
            if (isModified)
            {
                var updateResult = await _userManager.UpdateAsync(user);
                if (!updateResult.Succeeded)
                {
                    var errors = updateResult.Errors.Select(e => e.Description);
                    return BadRequest(new { message = "Kullanıcı bilgileri güncellenemedi.", errors });
                }
            }
            _logger.LogInformation("User {UserId} security settings updated. Changes: {Changes}", user.Id, string.Join(", ", messages));
            return Ok(new { message = "Ayarlar başarıyla güncellendi.", details = messages });
        }

        [Authorize]
        [HttpPost("send-phone-verification")]
        [Throttle(300)]

        public async Task<IActionResult> SendPhoneVerificationCode([FromBody] SendPhoneCodeRequest dto)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return Unauthorized(new { message = "Kullanıcı bulunamadı." });

            var phone = dto.PhoneNumber ?? user.PhoneNumber;
            if (string.IsNullOrWhiteSpace(phone))
                return BadRequest(new { message = "Telefon numarası bulunamadı veya geçersiz." });

            var settings = await _settingsService.GetActiveSettingsAsync();
            if (settings == null)
                return StatusCode(500, new { message = "Sistem ayarları eksik." });

            // Kod üret
            var code = new Random().Next(100000, 999999).ToString();

            // Session'a yaz
            HttpContext.Session.SetString("PhoneCode", code);
            HttpContext.Session.SetString("PhoneCode_Phone", phone);
            HttpContext.Session.SetString("PhoneCode_Expire", DateTime.UtcNow.AddMinutes(5).ToString());

            // WhatsApp'tan mesaj gönder
            await _smsService.SendVerificationCodeAsync(phone, code, settings);

            return Ok(new { message = "Doğrulama kodu gönderildi." });
        }

        [HttpPost("logout")]
        public IActionResult Logout()
        {
            // Oturumdan çıkart
            Response.Cookies.Delete("AuthToken");
            Response.Cookies.Delete("RefreshToken");

            // Kullanıcının oturumunu sonlandır
            if (User.Identity.IsAuthenticated)
            {
                var user = _userManager.GetUserAsync(User).Result;
                if (user != null)
                {
                    _signInManager.SignOutAsync().Wait();
                }
            }

            return Ok(new { message = "Çıkış yapıldı." });
        }

        [Authorize]
        [HttpPost("verify-phone-code")]
        public async Task<IActionResult> VerifyPhoneCode([FromBody] VerifyPhoneCodeRequest dto)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return Unauthorized(new { message = "Kullanıcı bulunamadı." });

            var storedCode = HttpContext.Session.GetString("PhoneCode");
            var expireStr = HttpContext.Session.GetString("PhoneCode_Expire");
            var phoneInSession = HttpContext.Session.GetString("PhoneCode_Phone");

            if (string.IsNullOrEmpty(storedCode) || string.IsNullOrEmpty(expireStr))
                return BadRequest(new { message = "Kod bulunamadı veya süresi dolmuş olabilir." });

            if (!DateTime.TryParse(expireStr, out var expireTime) || DateTime.UtcNow > expireTime)
                return BadRequest(new { message = "Kodun süresi dolmuş." });

            if (dto.Code != storedCode)
                return BadRequest(new { message = "Kod hatalı." });

            // Telefon numarasını doğrula
            if (!string.IsNullOrEmpty(phoneInSession))
            {
                user.PhoneNumber = phoneInSession;
                user.PhoneNumberConfirmed = true;
            }
            else
            {
                user.PhoneNumberConfirmed = true;
            }

            await _userManager.UpdateAsync(user);

            // Session'ı temizle
            HttpContext.Session.Remove("PhoneCode");
            HttpContext.Session.Remove("PhoneCode_Phone");
            HttpContext.Session.Remove("PhoneCode_Expire");

            return Ok(new { message = "Telefon numaranız başarıyla doğrulandı." });
        }

        [HttpGet("userinfo")]
        public async Task<IActionResult> GetUserInfo()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return Ok(new { isAuthenticated = false });
            }

            return Ok(new
            {
                isAuthenticated = true,
                username = user.UserName,
                roles = await _userManager.GetRolesAsync(user)
            });
        }



        [HttpGet("check-auth")]
        public async Task<IActionResult> CheckAuth()
        {
            if (User.Identity.IsAuthenticated)
            {
                var user = await _userManager.GetUserAsync(User);
                var roles = await _userManager.GetRolesAsync(user);
                return Ok(new { isAuthenticated = true, userName = User.Identity.Name, roles });
            }
            return Ok(new { isAuthenticated = false });
        }



        private void SetAuthCookies(string token, string refreshToken)
        {
            Response.Cookies.Append("AuthToken", token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddHours(3)
            });

            Response.Cookies.Append("RefreshToken", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(7)
            });
        }


        private string GenerateJwtToken(AppUser user)
        {
            var jwtConfig = _configuration.GetSection("JWT");
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfig["Secret"]));

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: jwtConfig["ValidIssuer"],
                audience: jwtConfig["ValidAudience"],
                expires: DateTime.UtcNow.AddHours(3),
                claims: claims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
