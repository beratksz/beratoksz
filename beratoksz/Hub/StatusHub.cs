using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace beratoksz.Hubs
{
    public class StatusHub : Hub
    {
        private readonly ILogger<StatusHub> _logger;
        private static int _activeUsers = 0;

        public StatusHub(ILogger<StatusHub> logger)
        {
            _logger = logger;
        }

        public override async Task OnConnectedAsync()
        {
            _logger.LogInformation($"📡 Yeni istemci bağlandı: {Context.ConnectionId}");
            await Clients.Caller.SendAsync("ConnectedSuccessfully", $"Bağlantı başarılı: {Context.ConnectionId}");
            Interlocked.Increment(ref _activeUsers);
            await Clients.All.SendAsync("UpdateActiveUsers", _activeUsers);
            await base.OnConnectedAsync();
        }

        public override async Task OnDisconnectedAsync(System.Exception exception)
        {
            _logger.LogInformation($"❌ İstemci bağlantısı koptu: {Context.ConnectionId}");
            Interlocked.Decrement(ref _activeUsers);
            await Clients.All.SendAsync("UpdateActiveUsers", _activeUsers);
            await base.OnDisconnectedAsync(exception);
        }
        public async Task GetActiveUserCount()
        {
            await Clients.Caller.SendAsync("UpdateActiveUsers", _activeUsers);
        }
        public async Task SendTestMessage(string message)
        {
            _logger.LogInformation($"📨 Test mesajı alındı: {message}");
        }
    }
}
