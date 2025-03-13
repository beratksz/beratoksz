using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace beratoksz.Models
{
    public class EditUserViewModel
    {
        public string Id { get; set; }

        [EmailAddress]
        public string Email { get; set; }

        // Tüm rollerin listesi
        public List<string> Roles { get; set; }

        // Kullanıcının seçtiği roller
        public IList<string> SelectedRoles { get; set; }
    }
}
