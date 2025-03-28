namespace beratoksz.Services
{
    public class WhatsAppService
    {
        private readonly HttpClient _httpClient;
        private readonly string _apiUrl;
        private readonly ILogger<WhatsAppService> _logger;

        public WhatsAppService(IConfiguration config, ILogger<WhatsAppService> logger)
        {
            _httpClient = new HttpClient();
            _apiUrl = config["WhatsAppSettings:ApiUrl"];
            _logger = logger;
        }

        public async Task<bool> SendMessageAsync(string phoneNumber, string message)
        {
            var payload = new
            {
                to = phoneNumber + "@c.us",
                message = message
            };

            try
            {
                var response = await _httpClient.PostAsJsonAsync(_apiUrl, payload);
                if (response.IsSuccessStatusCode)
                {
                    _logger.LogInformation("✅ WhatsApp mesajı gönderildi → {Phone}", phoneNumber);
                    return true;
                }
                else
                {
                    _logger.LogWarning("❌ WhatsApp mesajı gönderilemedi: {Status}", response.StatusCode);
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "🔥 WhatsApp API hatası oluştu.");
                return false;
            }
        }
    }

}
