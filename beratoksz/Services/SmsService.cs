using Microsoft.Extensions.Logging;
using System.Threading.Tasks;
using System;
using beratoksz.Models;

namespace beratoksz.Services
{
    public class SmsService
    {
        private readonly WhatsAppService _whatsapp;
        private readonly ILogger<SmsService> _logger;

        public SmsService(WhatsAppService whatsapp, ILogger<SmsService> logger)
        {
            _whatsapp = whatsapp;
            _logger = logger;
        }

        public async Task SendVerificationCodeAsync(string toPhone, string code, SiteSettings settings)
        {
            if (!settings.PhoneVerificationTemplate.Contains("{CODE}"))
            {
                _logger.LogWarning("Şablon geçersiz. {CODE} bulunamadı.");
                return;
            }

            var message = settings.PhoneVerificationTemplate.Replace("{CODE}", code);
            var success = await _whatsapp.SendMessageAsync(toPhone, message);

            if (!success)
            {
                _logger.LogWarning("WhatsApp mesajı gönderilemedi.");
            }
        }

    }
}
