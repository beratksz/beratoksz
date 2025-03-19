using System.ComponentModel.DataAnnotations;

namespace beratoksz.Models
{
    public class RolePermission
    {
        public int Id { get; set; }
        [Required(ErrorMessage = "RoleName boş bırakılamaz.")]
        public string RoleName { get; set; }  // Rol adı (Admin, Manager vs.)
        [Required(ErrorMessage = "PagePath boş bırakılamaz.")]
        public string PagePath { get; set; }  // Sayfa adı ("/Admin/Dashboard", "/Admin/UserManagement" vs.)
        public bool? CanAccess { get; set; }   // Erişim izni (true: erişebilir, false: erişemez)
    }

}
