using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using beratoksz.Models;

namespace beratoksz.Services
{
    public class EmailConfirmationService
    {
        private readonly SettingsService _settingsService;
        public EmailConfirmationService(SettingsService settingsService)
        {
            _settingsService = settingsService;
        }

        public async Task SendConfirmationEmailAsync(string email, string confirmationLink)
        {
            var settings = await _settingsService.GetActiveSettingsAsync();
            if (settings == null)
            {
                throw new System.Exception("Site ayarları bulunamadı.");
            }

            var smtpClient = new SmtpClient(settings.SmtpHost)
            {
                Port = settings.SmtpPort,
                Credentials = new NetworkCredential(settings.SmtpUsername, settings.SmtpPassword),
                EnableSsl = true
            };

            // Email şablonunda {LINK} yer tutucusunu, confirmation link ile değiştiriyoruz.
            var body = settings.EmailVerificationTemplate.Replace("{LINK}", confirmationLink);

            var mailMessage = new MailMessage
            {
                From = new MailAddress(settings.EmailFromAddress, settings.EmailFromName),
                Subject = "Email Doğrulama",
                Body = body,
                IsBodyHtml = true,
            };

            mailMessage.To.Add(email);
            await smtpClient.SendMailAsync(mailMessage);
        }
    }
}
