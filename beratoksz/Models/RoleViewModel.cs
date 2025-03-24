using System.ComponentModel.DataAnnotations;

namespace beratoksz.Models
{
    public class RoleViewModel
    {
        public string? Id { get; set; }


        [Required(ErrorMessage = "Rol adı gereklidir.")]
        [Display(Name = "Rol Adı")]
        public string Name { get; set; }

        [Required(ErrorMessage = "Açıklama gereklidir.")]
        [Display(Name = "Açıklama")]
        public string Aciklama { get; set; }


    }
}
