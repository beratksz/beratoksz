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

        public AccountController(UserManager<AppUser> userManager,
                            SignInManager<AppUser> signInManager,
                            IConfiguration configuration,
                            ApplicationDbContext context,   
                            TwoFactorEmailService twoFactorEmailService) 

        {
            _userManager = userManager;
            _configuration = configuration;
            _signInManager = signInManager;
            _twoFactorEmailService = twoFactorEmailService;

        }

        [HttpGet("whoami")]
        public IActionResult WhoAmI()
        {
            var roles = User.Claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value).ToList();
            return Ok(new
            {
                User.Identity.Name,
                Roles = roles
            });
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var userExists = await _userManager.FindByEmailAsync(model.Email);
            if (userExists != null)
                return BadRequest(new { message = "Bu e-posta adresi zaten kayıtlı." });

            var user = new AppUser
            {
                UserName = model.UserName,
                Email = model.Email,
                PhoneNumber = model.PhoneNumber
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return BadRequest(result.Errors);

            await _userManager.AddToRoleAsync(user, "User");

            var token = GenerateJwtToken(user);
            var refreshToken = Guid.NewGuid().ToString(); // refreshToken oluşturulmalı
            SetAuthCookies(token, refreshToken);


            return Ok(new { message = "Kayıt başarılı, giriş yapıldı!", username = user.UserName });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userManager.FindByEmailAsync(model.LoginIdentifier) ??
                       await _userManager.FindByNameAsync(model.LoginIdentifier);

            if (user == null || !(await _userManager.CheckPasswordAsync(user, model.Password)))
                return Unauthorized(new { message = "Geçersiz giriş bilgileri" });

            // Kullanıcının 2FA aktif mi?
            if (await _userManager.GetTwoFactorEnabledAsync(user))
            {
                var code = new Random().Next(100000, 999999).ToString();

                // Cache veya DB yerine şimdilik memory dictionary kullanabilirsin (test için):
                HttpContext.Session.SetString("2FACode", code);
                HttpContext.Session.SetString("2FAUserId", user.Id);
                HttpContext.Session.SetString("2FA_ExpireTime", DateTime.UtcNow.AddMinutes(5).ToString());

                // E-posta gönder
                await _twoFactorEmailService.SendCodeAsync(user.Email, code);

                return Ok(new { requires2FA = true, message = "Doğrulama kodu e-posta ile gönderildi." });
            }

            // Kullanıcıyı oturuma al ve kimlik doğrulamayı güncelle
            await _signInManager.SignInAsync(user, isPersistent: model.RememberMe);

            // JWT oluştur
            var token = GenerateJwtToken(user);
            var refreshToken = Guid.NewGuid().ToString();

            // Cookie olarak set et
            SetAuthCookies(token, refreshToken);

            return Ok(new { message = "Giriş başarılı!", redirectUrl = "/" });
        }

        [HttpPost("verify-2fa")]
        public async Task<IActionResult> Verify2FA([FromBody] Verify2FADto dto)
        {
            var code = HttpContext.Session.GetString("2FA_Code");
            var userId = HttpContext.Session.GetString("2FA_UserId");

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
            HttpContext.Session.Remove("2FA_Code");
            HttpContext.Session.Remove("2FA_UserId");

            return Ok(new { message = "2FA doğrulandı!", redirectUrl = "/" });
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
        public IActionResult CheckAuth()
        {
            if (User.Identity.IsAuthenticated)
            {
                return Ok(new { isAuthenticated = true, userName = User.Identity.Name });
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
