using beratoksz.Data;
using beratoksz.Models;
using Microsoft.EntityFrameworkCore;

namespace beratoksz.Services
{
    public class UserSecurityService
    {
        private readonly ApplicationDbContext _context;

        public UserSecurityService(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task LogActivity(string userId, string activityType, string ipAddress, string userAgent, bool isSuccess)
        {
            var activity = new UserSecurityActivity
            {
                UserId = userId,
                ActivityType = activityType,
                IPAddress = ipAddress,
                UserAgent = userAgent,
                Timestamp = DateTime.UtcNow,
                IsSuccess = isSuccess
            };

            _context.UserSecurityActivities.Add(activity);
            await _context.SaveChangesAsync();
        }

        public async Task<List<UserSecurityActivity>> GetRecentActivities(string userId, int limit = 10)
        {
            return await _context.UserSecurityActivities
                .Where(x => x.UserId == userId)
                .OrderByDescending(x => x.Timestamp)
                .Take(limit)
                .ToListAsync();
        }
    }

}
