using Microsoft.EntityFrameworkCore;

namespace beratoksz.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        // DbSet properties go here
        // public DbSet<YourEntity> YourEntities { get; set; }
    }
}
