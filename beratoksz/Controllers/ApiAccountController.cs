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

namespace beratoksz.Controllers
{
    [AllowAnonymous]
    [Route("api/[controller]")]
    [ApiController]
    public class ApiAccountController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly SignInManager<IdentityUser> _signInManager;

        public ApiAccountController(UserManager<IdentityUser> userManager,
                            SignInManager<IdentityUser> signInManager,
                            IConfiguration configuration,
                            ApplicationDbContext context)
        {
            _userManager = userManager;
            _configuration = configuration;
            _signInManager = signInManager; // BU SATIRI EKLE

        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var userExists = await _userManager.FindByEmailAsync(model.Email);
            if (userExists != null)
                return BadRequest(new { message = "Bu e-posta adresi zaten kayıtlı." });

            var user = new IdentityUser
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

            // Kullanıcıyı oturuma al ve kimlik doğrulamayı güncelle
            await _signInManager.SignInAsync(user, isPersistent: model.RememberMe);

            // JWT oluştur
            var token = GenerateJwtToken(user);
            var refreshToken = Guid.NewGuid().ToString();

            // Cookie olarak set et
            SetAuthCookies(token, refreshToken);

            return Ok(new { message = "Giriş başarılı!", redirectUrl = "/" });
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


        private string GenerateJwtToken(IdentityUser user)
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
