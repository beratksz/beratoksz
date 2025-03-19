using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using beratoksz.Models;  // LoginViewModel sınıfının bulunduğu yer
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using beratoksz.Services;
using Microsoft.AspNetCore.Authorization;

namespace beratoksz.Controllers
{
    [AllowAnonymous]
    public class AccountController : Controller
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly UserSecurityService _userSecurityService;

        public AccountController(SignInManager<IdentityUser> signInManager,
                                 UserManager<IdentityUser> userManager,
                                 UserSecurityService userSecurityService)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _userSecurityService = userSecurityService;

        }

        // GET: /Account/Login
        [HttpGet]

        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        // POST: /Account/Login
        [HttpPost]
        [ValidateAntiForgeryToken]

        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            if (ModelState.IsValid)
            {
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

                if (user != null)
                {
                    var result = await _signInManager.PasswordSignInAsync(user.UserName, model.Password, model.RememberMe, lockoutOnFailure: false);
                    var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
                    var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();

                    if (result.Succeeded)
                    {
                        // Manuel olarak ClaimsPrincipal oluşturup cookie'yi yeniden oluşturuyoruz:
                        var principal = await _signInManager.CreateUserPrincipalAsync(user);
                        await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, principal);

                        await _userSecurityService.LogActivity(user.Id, "Login", ipAddress, userAgent, true);

                        if (await _userManager.IsInRoleAsync(user, "Admin"))
                        {
                            return RedirectToAction("Index", "Home", new { area = "Admin" });
                        }
                        return RedirectToLocal(returnUrl);
                    }
                    else
                    {
                        await _userSecurityService.LogActivity(user.Id, "FailedLogin", ipAddress, userAgent, false);
                    }
                }

                ModelState.AddModelError(string.Empty, "Geçersiz giriş denemesi.");
            }
            return View(model);
        }




        [HttpPost]
        [ValidateAntiForgeryToken]

        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Login", "Account");
        }

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }
    }
}
