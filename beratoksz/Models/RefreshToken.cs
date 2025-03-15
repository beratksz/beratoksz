using System;
using Microsoft.AspNetCore.Identity;

namespace beratoksz.Models
{
    public class RefreshToken
    {
        public int Id { get; set; }
        public string Token { get; set; }
        public DateTime Expiration { get; set; }
        public bool IsRevoked { get; set; }
        public string UserId { get; set; }
        public IdentityUser User { get; set; }

    }
    public sealed class RefreshRequest
    {
        public required string RefreshToken { get; init; }
        public required string AccessToken { get; init; } // Add this line
    }
}

