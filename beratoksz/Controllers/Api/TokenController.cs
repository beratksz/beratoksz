using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using beratoksz.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.Data;

namespace beratoksz.Controllers.Api
{
    [Route("api/[controller]")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _configuration;

        public TokenController(UserManager<IdentityUser> userManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _configuration = configuration;
        }

        // Mevcut token üretim endpoint'i
        [HttpPost]
        public async Task<IActionResult> Post([FromBody] LoginViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
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

                // Not: Refresh token üretim mekanizmanız burada entegre edilebilir. Örneğimizde sabit bir değer kullanıyoruz.
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo,
                    refreshToken = "my-refresh-token"
                });
            }
            return Unauthorized();
        }

        // Refresh token endpoint'i
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
        {
            // Basit demo doğrulaması: refresh token sabit değer değilse, hata döndür.
            if (request.RefreshToken != "my-refresh-token")
            {
                return Unauthorized("Invalid refresh token");
            }

            // Gerçek uygulamada, eski access token'ı doğrulayıp kullanıcı bilgisini elde etmeniz gerekir.
            // Örneğimizde demo amaçlı sabit kullanıcı bilgisi kullanıyoruz.
            var user = await _userManager.FindByEmailAsync("denemeadmin@example.com");
            if (user == null)
            {
                return Unauthorized("User not found");
            }

            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var jwtConfig = _configuration.GetSection("JWT");
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfig["Secret"]));

            var newToken = new JwtSecurityToken(
                issuer: jwtConfig["ValidIssuer"],
                audience: jwtConfig["ValidAudience"],
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );

            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(newToken),
                expiration = newToken.ValidTo
            });
        }
    }
}
