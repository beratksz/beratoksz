using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using beratoksz.Models;

namespace beratoksz.Services
{
    public class PasswordResetEmailService
    {
        private readonly SettingsService _settingsService;

        public PasswordResetEmailService(SettingsService settingsService)
        {
            _settingsService = settingsService;
        }

        public async Task SendPasswordResetEmailAsync(string email, string resetLink)
        {
            var settings = await _settingsService.GetActiveSettingsAsync();
            if (settings == null)
            {
                throw new System.Exception("Site ayarları bulunamadı.");
            }

            SmtpClient smtpClient = new SmtpClient(settings.SmtpHost)
            {
                Port = settings.SmtpPort,
                Credentials = new NetworkCredential(settings.SmtpUsername, settings.SmtpPassword),
                EnableSsl = true,
            };

            // Şifre sıfırlama şablonunda {LINK} yer tutucusunu resetLink ile değiştiriyoruz
            var body = settings.PasswordResetEmailTemplate.Replace("{LINK}", resetLink);

            MailMessage mail = new MailMessage()
            {
                From = new MailAddress(settings.EmailFromAddress, settings.EmailFromName),
                Subject = "Şifre Sıfırlama",
                Body = body,
                IsBodyHtml = true,
            };
            mail.To.Add(email);

            await smtpClient.SendMailAsync(mail);
        }
    }
}
