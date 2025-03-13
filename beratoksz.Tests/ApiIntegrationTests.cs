using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.VisualStudio.TestPlatform.TestHost;
using Newtonsoft.Json;
using Xunit;

namespace beratoksz.Tests
{
    public class ApiIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
    {
        private readonly HttpClient _client;

        public ApiIntegrationTests(WebApplicationFactory<Program> factory)
        {
            _client = factory.CreateClient();
        }

        [Fact]
        public async Task ProtectedEndpoint_Unauthorized_WithoutToken()
        {
            // Arrange & Act: Token olmadan korumalı endpoint'e istek gönderiyoruz.
            var response = await _client.GetAsync("/api/example");

            // Assert: 401 Unauthorized bekliyoruz.
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task ProtectedEndpoint_Authorized_WithToken()
        {
            // Arrange: Önce token almak için /api/token endpoint'ine istek gönderelim.
            var loginData = new
            {
                Email = "denemeadmin@example.com",
                Password = "Admin123!",
                RememberMe = false
            };

            var content = new StringContent(JsonConvert.SerializeObject(loginData), Encoding.UTF8, "application/json");
            var tokenResponse = await _client.PostAsync("/api/token", content);
            tokenResponse.EnsureSuccessStatusCode();

            var tokenResult = JsonConvert.DeserializeObject<TokenResult>(await tokenResponse.Content.ReadAsStringAsync());
            var token = tokenResult.Token;

            // Artık korumalı endpoint'e yetkili istek gönderiyoruz.
            _client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

            // Act
            var response = await _client.GetAsync("/api/example");

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
    }

    public class TokenResult
    {
        public string Token { get; set; }
        public System.DateTime Expiration { get; set; }
    }
}
