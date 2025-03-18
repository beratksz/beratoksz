using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace beratoksz.Models
{
    public class EditUserViewModel
    {
        public string Id { get; set; }
        public string Email { get; set; }

        // Yeni alanlar
        public string UserName { get; set; }
        public string NormalizedUserName { get; set; }
        public string NormalizedEmail { get; set; }
        public bool EmailConfirmed { get; set; }
        public string PasswordHash { get; set; }
        public string SecurityStamp { get; set; }
        public string ConcurrencyStamp { get; set; }
        public string PhoneNumber { get; set; }
        public bool PhoneNumberConfirmed { get; set; }
        public bool TwoFactorEnabled { get; set; }
        public DateTimeOffset? LockoutEnd { get; set; }
        public bool LockoutEnabled { get; set; }
        public int AccessFailedCount { get; set; }


        // Tüm rollerin listesi; varsayılan olarak boş liste
        public List<string> Roles { get; set; } = new List<string>();

        // Kullanıcının seçtiği roller; varsayılan olarak boş liste
        public IList<string> SelectedRoles { get; set; } = new List<string>();
    }
}
