using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace beratoksz.Hubs
{
    public class StatusHub : Hub
    {
        private readonly ILogger<StatusHub> _logger;

        public StatusHub(ILogger<StatusHub> logger)
        {
            _logger = logger;
        }

        public override async Task OnConnectedAsync()
        {
            _logger.LogInformation($"📡 Yeni istemci bağlandı: {Context.ConnectionId}");
            await Clients.Caller.SendAsync("ConnectedSuccessfully", $"Bağlantı başarılı: {Context.ConnectionId}");
        }

        public override async Task OnDisconnectedAsync(System.Exception exception)
        {
            _logger.LogInformation($"❌ İstemci bağlantısı koptu: {Context.ConnectionId}");
        }

        public async Task SendTestMessage(string message)
        {
            _logger.LogInformation($"📨 Test mesajı alındı: {message}");
        }
    }
}
