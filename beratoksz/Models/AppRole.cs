using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace beratoksz.Models
{
    public class AppRole : IdentityRole
    {
        public string Aciklama { get; set; } // Admin ne iş yapar?
        public DateTime OlusturulmaTarihi { get; set; }
        public bool SistemRoluMu { get; set; } = false; // Silinemez gibi

        public AppRole(string roleName) : base(roleName)
        {
            OlusturulmaTarihi = DateTime.UtcNow;
        }
        public AppRole() : base()
        {
        }
    }
}
