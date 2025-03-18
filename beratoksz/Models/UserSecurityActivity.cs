namespace beratoksz.Models
{
    public class UserSecurityActivity
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public string ActivityType { get; set; } // Login, FailedLogin, PasswordChange, etc.
        public string IPAddress { get; set; }
        public string UserAgent { get; set; }
        public DateTime Timestamp { get; set; }
        public bool IsSuccess { get; set; } // Giriş başarılı mı?
    }
}
