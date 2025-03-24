using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace beratoksz.Models
{
    public class AppRole : IdentityRole
    {
        public string Aciklama { get; set; }
        public DateTime OlusturulmaTarihi { get; set; }
        public bool SistemRoluMu { get; set; } = false;

        public AppRole() : base() { }
    }
}
