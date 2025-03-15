using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
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
// using Microsoft.AspNetCore.Identity.Data; // Remove this line if not needed

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

                var refreshToken = Guid.NewGuid().ToString(); // Benzersiz bir refresh token üretin ve veritabanında saklayın

                // Refresh token'ı veritabanında saklama işlemi burada yapılmalı

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo,
                    refreshToken = refreshToken
                });
            }
            return Unauthorized();
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] beratoksz.Models.RefreshRequest request)
        {
            // Refresh token'ı veritabanında doğrulama işlemi burada yapılmalı
            var isValidRefreshToken = true; // Bu değeri veritabanı kontrolü ile belirleyin

            if (!isValidRefreshToken)
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
                    ValidateLifetime = true, // Token süresini kontrol ediyoruz
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtConfig["ValidIssuer"],
                    ValidAudience = jwtConfig["ValidAudience"],
                    IssuerSigningKey = new SymmetricSecurityKey(key)
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                var userEmail = jwtToken.Claims.First(x => x.Type == ClaimTypes.Email).Value;

                var user = await _userManager.FindByEmailAsync(userEmail);
                if (user == null)
                {
                    return Unauthorized("User not found");
                }

                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
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

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(newToken),
                    expiration = newToken.ValidTo
                });
            }
            catch
            {
                return Unauthorized("Invalid access token");
            }
        }
    }
}
