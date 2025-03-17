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

namespace beratoksz.Controllers.Api
{
    [Route("api/[controller]")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly ApplicationDbContext _context; // Varsayalım ki veritabanı context'iniz bu şekilde

        public TokenController(UserManager<IdentityUser> userManager, IConfiguration configuration, ApplicationDbContext context)
        {
            _userManager = userManager;
            _configuration = configuration;
            _context = context;
        }

        [HttpPost]
        public async Task<IActionResult> Post([FromBody] LoginViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            IdentityUser user = null;

            // Kullanıcıyı email, kullanıcı adı veya telefon numarasına göre bulma
            if (model.LoginIdentifier.Contains("@"))
            {
                user = await _userManager.FindByEmailAsync(model.LoginIdentifier);
            }
            else if (model.LoginIdentifier.All(char.IsDigit))
            {
                user = _userManager.Users.SingleOrDefault(u => u.PhoneNumber == model.LoginIdentifier);
            }
            else
            {
                user = await _userManager.FindByNameAsync(model.LoginIdentifier);
            }

            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(ClaimTypes.Email, user.Email), // Email claim ekleniyor
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                var userRoles = await _userManager.GetRolesAsync(user);
                foreach (var role in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }

                var jwtConfig = _configuration.GetSection("JWT");
                var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfig["Secret"]));

                var token = new JwtSecurityToken(
                    issuer: jwtConfig["ValidIssuer"],
                    audience: jwtConfig["ValidAudience"],
                    expires: DateTime.Now.AddHours(3),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

                // Refresh token üretimi ve veritabanına kaydı
                var refreshTokenValue = Guid.NewGuid().ToString();
                var refreshToken = new RefreshToken
                {
                    Token = refreshTokenValue,
                    Expiration = DateTime.Now.AddDays(7),
                    IsRevoked = false,
                    UserId = user.Id
                };

                _context.RefreshTokens.Add(refreshToken);
                await _context.SaveChangesAsync();

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo,
                    refreshToken = refreshTokenValue
                });
            }
            return Unauthorized();
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
        {
            // İlk olarak, refresh token'ın veritabanında varlığını ve geçerliliğini kontrol ediyoruz.
            var storedToken = await _context.RefreshTokens.FirstOrDefaultAsync(t => t.Token == request.RefreshToken);
            if (storedToken == null || storedToken.Expiration < DateTime.Now || storedToken.IsRevoked)
            {
                return Unauthorized("Invalid refresh token");
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtConfig = _configuration.GetSection("JWT");
            var key = Encoding.UTF8.GetBytes(jwtConfig["Secret"]);

            try
            {
                tokenHandler.ValidateToken(request.AccessToken, new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtConfig["ValidIssuer"],
                    ValidAudience = jwtConfig["ValidAudience"],
                    IssuerSigningKey = new SymmetricSecurityKey(key)
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                // Email claim'ini okuma
                var userEmailClaim = jwtToken.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Email);
                if (userEmailClaim == null)
                {
                    return Unauthorized("Email claim missing in access token");
                }
                var userEmail = userEmailClaim.Value;

                var user = await _userManager.FindByEmailAsync(userEmail);
                if (user == null)
                {
                    return Unauthorized("User not found");
                }

                // Mevcut refresh token'ı tek kullanımlık yapmak için iptal ediyoruz.
                storedToken.IsRevoked = true;
                _context.RefreshTokens.Update(storedToken);
                await _context.SaveChangesAsync();

                // Yeni token ve refresh token üretimi
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfig["Secret"]));
                var newToken = new JwtSecurityToken(
                    issuer: jwtConfig["ValidIssuer"],
                    audience: jwtConfig["ValidAudience"],
                    expires: DateTime.Now.AddHours(3),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

                var newRefreshTokenValue = Guid.NewGuid().ToString();
                var newRefreshToken = new RefreshToken
                {
                    Token = newRefreshTokenValue,
                    Expiration = DateTime.Now.AddDays(7),
                    IsRevoked = false,
                    UserId = user.Id
                };

                _context.RefreshTokens.Add(newRefreshToken);
                await _context.SaveChangesAsync();

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(newToken),
                    expiration = newToken.ValidTo,
                    refreshToken = newRefreshTokenValue
                });
            }
            catch (Exception ex)
            {
                // Hata loglama işlemleri ekleyebilirsiniz
                return Unauthorized("Invalid access token");
            }
        }
    }
}
