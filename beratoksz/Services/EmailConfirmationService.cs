using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using beratoksz.Models;
using Microsoft.Extensions.Logging;

namespace beratoksz.Services
{
    public class EmailConfirmationService
    {
        private readonly SettingsService _settingsService;
        private readonly ILogger<EmailConfirmationService> _logger;

        public EmailConfirmationService(SettingsService settingsService, ILogger<EmailConfirmationService> logger)
        {
            _settingsService = settingsService;
            _logger = logger;
        }

        public async Task SendConfirmationEmailAsync(string email, string confirmationLink)
        {
            var settings = await _settingsService.GetActiveSettingsAsync();
            if (settings == null)
            {
                throw new Exception("Site ayarları bulunamadı.");
            }

            try
            {
                var smtpClient = new SmtpClient(settings.SmtpHost)
                {
                    Port = settings.SmtpPort,
                    Credentials = new NetworkCredential(settings.SmtpUsername, settings.SmtpPassword),
                    EnableSsl = true
                };

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
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send email to {Email}", email);
                throw; // Hatanın üst kademelere iletilmesi için yeniden fırlatabilirsin.
            }
        }
    }
}
