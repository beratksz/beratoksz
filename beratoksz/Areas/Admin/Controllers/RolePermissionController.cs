using beratoksz.Data;
using beratoksz.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

[Route("api/[controller]")]
[ApiController]
public class RolePermissionController : ControllerBase
{
    private readonly ApplicationDbContext _dbContext;

    public RolePermissionController(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    // 📌 Mevcut rol yetkilerini getir
    [HttpGet]
    public async Task<IActionResult> GetRolePermissions()
    {
        var permissions = await _dbContext.RolePermissions.ToListAsync();
        return Ok(permissions);
    }

    // 📌 Yeni bir rol için yetki ekle
    [HttpPost]
    public async Task<IActionResult> AddPermission([FromBody] RolePermission permission)
    {
        if (string.IsNullOrEmpty(permission.PagePath) || string.IsNullOrEmpty(permission.RoleName))
            return BadRequest("Rol adı ve sayfa yolu boş olamaz.");

        _dbContext.RolePermissions.Add(permission);
        await _dbContext.SaveChangesAsync();
        return Ok(new { message = "İzin başarıyla eklendi." });
    }

    // 📌 Var olan yetkiyi güncelle
    [HttpPut("{id}")]
    public async Task<IActionResult> UpdatePermission(int id, [FromBody] RolePermission permission)
    {
        if (permission == null)
        {
            return BadRequest(new { message = "Geçersiz istek! Gönderilen veri boş olamaz." });
        }

        // ModelState kontrolü yapalım
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var existingPermission = await _dbContext.RolePermissions.FindAsync(id);
        if (existingPermission == null)
        {
            return NotFound(new { message = "Belirtilen ID'ye sahip izin bulunamadı." });
        }

        // Sadece gelen veriyi güncelle
        existingPermission.CanAccess = permission.CanAccess;

        await _dbContext.SaveChangesAsync();

        return Ok(new { message = "İzin başarıyla güncellendi." });
    }


    // 📌 Yetkiyi sil
    [HttpDelete("{id}")]
    public async Task<IActionResult> DeletePermission(int id)
    {
        var permission = await _dbContext.RolePermissions.FindAsync(id);
        if (permission == null)
            return NotFound();

        _dbContext.RolePermissions.Remove(permission);
        await _dbContext.SaveChangesAsync();
        return Ok(new { message = "İzin başarıyla silindi." });
    }
}
