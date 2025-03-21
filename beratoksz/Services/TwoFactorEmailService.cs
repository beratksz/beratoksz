using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Configuration;

namespace beratoksz.Services
{
    public class TwoFactorEmailService
    {
        private readonly IConfiguration _configuration;

        public TwoFactorEmailService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task SendCodeAsync(string email, string code)
        {
            var smtpClient = new SmtpClient("smtp.hostinger.com")
            {
                Port = 465,
                Credentials = new NetworkCredential("admin@beratoksz.com", "1903Berat1526-"),
                EnableSsl = true
            };

            var mailMessage = new MailMessage
            {
                From = new MailAddress("no-reply@beratoksz.com", "2FA Güvenlik"),
                Subject = "Giriş Doğrulama Kodu",
                Body = $"Merhaba,\n\nGiriş işleminizi tamamlamak için doğrulama kodunuz: {code}\n\nBu kod 5 dakika geçerlidir.",
                IsBodyHtml = false,
            };

            mailMessage.To.Add(email);

            await smtpClient.SendMailAsync(mailMessage);
        }
    }
}
