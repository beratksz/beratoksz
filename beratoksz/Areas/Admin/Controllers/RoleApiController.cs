using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using beratoksz.Models;

namespace beratoksz.Areas.Admin.Controllers
{
    [Route("api/roles")]
    [ApiController]
    public class RoleApiController : ControllerBase
    {
        private readonly RoleManager<AppRole> _roleManager;

        public RoleApiController(RoleManager<AppRole> roleManager)
        {
            _roleManager = roleManager;
        }

        // ✅ GET: api/roles (Tüm rolleri getir)
        [HttpGet]
        public IActionResult GetRoles()
        {
            var roles = _roleManager.Roles.Select(r => new { r.Id, r.Name }).ToList();
            return Ok(roles);
        }

        // ✅ GET: api/roles/{id} (Belirtilen rolü getir)
        [HttpGet("{id}")]
        public async Task<IActionResult> GetRole(string id)
        {
            var role = await _roleManager.FindByIdAsync(id);
            if (role == null)
                return NotFound();

            return Ok(new { role.Id, role.Name });
        }

        // ✅ POST: api/roles (Yeni rol ekle)
        [HttpPost]
        public async Task<IActionResult> CreateRole([FromBody] RoleViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var role = new AppRole(model.Name)
            {
                NormalizedName = model.Name.ToUpper()
            };

            var result = await _roleManager.CreateAsync(role);
            if (result.Succeeded)
                return CreatedAtAction(nameof(GetRole), new { id = role.Id }, new { role.Id, role.Name });

            return BadRequest(result.Errors);
        }

        // ✅ PUT: api/roles/{id} (Rol güncelleme)
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateRole(string id, [FromBody] RoleViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var role = await _roleManager.FindByIdAsync(id);
            if (role == null)
                return NotFound();

            role.Name = model.Name;
            role.NormalizedName = model.Name.ToUpper();

            var result = await _roleManager.UpdateAsync(role);
            if (result.Succeeded)
                return NoContent();

            return BadRequest(result.Errors);
        }

        // ✅ DELETE: api/roles/{id} (Rol silme)
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteRole(string id)
        {
            var role = await _roleManager.FindByIdAsync(id);
            if (role == null)
                return NotFound();

            var result = await _roleManager.DeleteAsync(role);
            if (result.Succeeded)
                return NoContent();

            return BadRequest(result.Errors);
        }
    }
}
