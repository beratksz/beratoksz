namespace beratoksz.Models
{
    public class SiteSettings
    {
        public int Id { get; set; }
        public bool EnableEmailVerification { get; set; }
        public bool EnableTwoFactorAuthentication { get; set; }
        public string SmtpHost { get; set; }
        public int SmtpPort { get; set; }
        public string SmtpUsername { get; set; }
        public string SmtpPassword { get; set; }
        public string EmailFromAddress { get; set; }
        public string EmailFromName { get; set; }
        public string EmailVerificationTemplate { get; set; }
        public string TwoFactorEmailTemplate { get; set; }
        public bool IsActive { get; set; }  // Hangi kayıt aktif?
    }
}
