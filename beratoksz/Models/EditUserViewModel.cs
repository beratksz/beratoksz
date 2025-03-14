using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace beratoksz.Models
{
    public class EditUserViewModel
    {
        public string Id { get; set; }

        [EmailAddress]
        public string Email { get; set; }

        // Tüm rollerin listesi; varsayılan olarak boş liste
        public List<string> Roles { get; set; } = new List<string>();

        // Kullanıcının seçtiği roller; varsayılan olarak boş liste
        public IList<string> SelectedRoles { get; set; } = new List<string>();
    }
}
