namespace beratoksz.Models
{
    public class AccountSecurityUpdateDto
    {
        public string? UserName { get; set; }
        public string? CurrentPassword { get; set; }
        public string? NewPassword { get; set; }
        public string? ConfirmPassword { get; set; }
        public string? PhoneNumber { get; set; }
        public bool? EnableTwoFactor { get; set; }
    }

}
