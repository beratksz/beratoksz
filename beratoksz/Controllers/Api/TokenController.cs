using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using beratoksz.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using beratoksz.Data;
using Microsoft.AspNetCore.Http;

namespace beratoksz.Controllers.Api
{
    [Route("api/[controller]")]
    [ApiController]
    
    public class TokenController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly ApplicationDbContext _context;

        public TokenController(UserManager<IdentityUser> userManager, IConfiguration configuration, ApplicationDbContext context)
        {
            _userManager = userManager;
            _configuration = configuration;
            _context = context;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            IdentityUser user = await GetUserByIdentifier(model.LoginIdentifier);
            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
                return Unauthorized("Geçersiz giriş bilgileri.");

            // JWT ve Refresh Token üret
            var jwtToken = GenerateJwtToken(user);
            var refreshToken = GenerateRefreshToken();

            // Refresh token'ı veritabanına kaydet
            await SaveRefreshToken(user.Id, refreshToken);

            // JWT'yi ve Refresh Token'ı HttpOnly Cookie olarak ayarla
            SetTokenCookies(jwtToken, refreshToken);

            return Ok(new { message = "Başarıyla giriş yapıldı." });
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh()
        {
            if (!Request.Cookies.TryGetValue("refresh_token", out var refreshTokenValue))
                return Unauthorized("Refresh token bulunamadı.");

            var storedToken = await _context.RefreshTokens.FirstOrDefaultAsync(t => t.Token == refreshTokenValue);
            if (storedToken == null || storedToken.Expiration < DateTime.UtcNow || storedToken.IsRevoked)
                return Unauthorized("Geçersiz veya süresi dolmuş refresh token.");

            var user = await _userManager.FindByIdAsync(storedToken.UserId);
            if (user == null)
                return Unauthorized("Kullanıcı bulunamadı.");

            // Eski refresh token'ı iptal et
            storedToken.IsRevoked = true;
            _context.RefreshTokens.Update(storedToken);
            await _context.SaveChangesAsync();

            // Yeni JWT ve Refresh Token üret
            var newJwtToken = GenerateJwtToken(user);
            var newRefreshToken = GenerateRefreshToken();
            await SaveRefreshToken(user.Id, newRefreshToken);

            // Yeni token'ları Cookie olarak ayarla
            SetTokenCookies(newJwtToken, newRefreshToken);

            return Ok(new { message = "Token yenilendi." });
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            if (!Request.Cookies.TryGetValue("refresh_token", out var refreshTokenValue))
                return Unauthorized("Çıkış yapacak token bulunamadı.");

            var storedToken = await _context.RefreshTokens.FirstOrDefaultAsync(t => t.Token == refreshTokenValue);
            if (storedToken != null)
            {
                storedToken.IsRevoked = true;
                _context.RefreshTokens.Update(storedToken);
                await _context.SaveChangesAsync();
            }

            // Cookie'leri temizle
            Response.Cookies.Delete("access_token");
            Response.Cookies.Delete("refresh_token");

            return Ok(new { message = "Başarıyla çıkış yapıldı." });
        }

        // Kullanıcıyı email, username veya telefon ile bulma
        private async Task<IdentityUser> GetUserByIdentifier(string identifier)
        {
            if (identifier.Contains("@"))
                return await _userManager.FindByEmailAsync(identifier);
            if (identifier.All(char.IsDigit))
                return _userManager.Users.SingleOrDefault(u => u.PhoneNumber == identifier);
            return await _userManager.FindByNameAsync(identifier);
        }

        // JWT Token üretme fonksiyonu
        private string GenerateJwtToken(IdentityUser user)
        {
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var jwtConfig = _configuration.GetSection("JWT");
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfig["Secret"]));

            var token = new JwtSecurityToken(
                issuer: jwtConfig["ValidIssuer"],
                audience: jwtConfig["ValidAudience"],
                expires: DateTime.UtcNow.AddMinutes(30),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        // Refresh Token üretme fonksiyonu
        private string GenerateRefreshToken()
        {
            return Guid.NewGuid().ToString();
        }

        // Refresh Token'ı veritabanına kaydetme
        private async Task SaveRefreshToken(string userId, string refreshToken)
        {
            var refreshTokenEntity = new RefreshToken
            {
                Token = refreshToken,
                Expiration = DateTime.UtcNow.AddDays(7),
                IsRevoked = false,
                UserId = userId
            };

            _context.RefreshTokens.Add(refreshTokenEntity);
            await _context.SaveChangesAsync();
        }

        // Token'ları HttpOnly Cookie olarak saklama
        private void SetTokenCookies(string jwtToken, string refreshToken)
        {
            Response.Cookies.Append("access_token", jwtToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddMinutes(30)
            });

            Response.Cookies.Append("refresh_token", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(7)
            });
        }
    }
}
