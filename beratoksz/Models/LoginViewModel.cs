using System.ComponentModel.DataAnnotations;

namespace beratoksz.Models
{
    public class LoginViewModel
    {
        [Required]
        public string LoginIdentifier { get; set; } // Email, kullanıcı adı veya telefon numarası olabilir
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }
        [Display(Name = "Beni Hatırla")]
        public bool RememberMe { get; set; }
    }

}
