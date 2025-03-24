using beratoksz.Models;
using beratoksz.Data;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace beratoksz.Services
{
    public class SettingsService
    {
        private readonly ApplicationDbContext _context;
        public SettingsService(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<SiteSettings> GetActiveSettingsAsync()
        {
            return await _context.SiteSettings.FirstOrDefaultAsync(s => s.IsActive);
        }

        public async Task<List<SiteSettings>> GetAllSettingsAsync()
        {
            return await _context.SiteSettings.ToListAsync();
        }

        public async Task<SiteSettings> GetSettingsByIdAsync(int id)
        {
            return await _context.SiteSettings.FirstOrDefaultAsync(s => s.Id == id);
        }

        public async Task CreateSettingsAsync(SiteSettings settings)
        {
            _context.SiteSettings.Add(settings);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateSettingsAsync(SiteSettings settings)
        {
            _context.Update(settings);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteSettingsAsync(SiteSettings settings)
        {
            _context.SiteSettings.Remove(settings);
            await _context.SaveChangesAsync();
        }

    }
}
