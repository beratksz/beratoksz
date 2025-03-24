using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using beratoksz.Services;

namespace beratoksz.Services
{
    public class TwoFactorEmailService
    {
        private readonly SettingsService _settingsService;
        public TwoFactorEmailService(SettingsService settingsService)
        {
            _settingsService = settingsService;
        }

        public async Task SendCodeAsync(string email, string code)
        {
            var settings = await _settingsService.GetActiveSettingsAsync();
            if (settings == null)
            {
                // Ayar bulunamadıysa hata fırlatabilir veya default ayar kullanabilirsiniz.
                throw new System.Exception("Site ayarları bulunamadı.");
            }

            var smtpClient = new SmtpClient(settings.SmtpHost)
            {
                Port = settings.SmtpPort,
                Credentials = new NetworkCredential(settings.SmtpUsername, settings.SmtpPassword),
                EnableSsl = true
            };

            // Şablonda {CODE} yer tutucusunu kod ile değiştiriyoruz
            var body = settings.TwoFactorEmailTemplate.Replace("{CODE}", code);

            var mailMessage = new MailMessage
            {
                From = new MailAddress(settings.EmailFromAddress, settings.EmailFromName),
                Subject = "Giriş Doğrulama Kodu",
                Body = body,
                IsBodyHtml = true,
            };

            mailMessage.To.Add(email);
            await smtpClient.SendMailAsync(mailMessage);
        }
    }
}
