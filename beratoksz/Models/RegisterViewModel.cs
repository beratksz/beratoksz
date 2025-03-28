using System.ComponentModel.DataAnnotations;

namespace beratoksz.Models
{
    public class RegisterViewModel
    {
        [Required(ErrorMessage = "Kullanıcı adı zorunludur.")]
        [StringLength(50, ErrorMessage = "Kullanıcı adı en fazla 50 karakter olabilir.")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "Email zorunludur.")]
        [EmailAddress(ErrorMessage = "Geçerli bir email adresi girin.")]
        [StringLength(50, ErrorMessage = "Email en fazla 50 karakter olabilir.")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Telefon numarası zorunludur.")]
        [Phone(ErrorMessage = "Geçerli bir telefon numarası girin.")]
        [StringLength(20, ErrorMessage = "Telefon numarası en fazla 20 karakter olabilir.")]
        public string PhoneNumber { get; set; }

        [Required(ErrorMessage = "Şifre zorunludur.")]
        [DataType(DataType.Password)]
        [StringLength(50, ErrorMessage = "Şifre en fazla 50 karakter olabilir.")]
        public string Password { get; set; }

        [Required(ErrorMessage = "Şifre onayı zorunludur.")]
        [Compare("Password", ErrorMessage = "Şifreler eşleşmiyor.")]
        [DataType(DataType.Password)]
        [StringLength(50, ErrorMessage = "Şifre onayı en fazla 50 karakter olabilir.")]
        public string ConfirmPassword { get; set; }
    }
}
