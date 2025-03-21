using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using beratoksz.Models;

public class AppRoleConfiguration : IEntityTypeConfiguration<AppRole>
{
    public void Configure(EntityTypeBuilder<AppRole> builder)
    {
        builder.Property(r => r.Aciklama)
               .HasMaxLength(250);

        builder.Property(r => r.SistemRoluMu)
               .HasDefaultValue(false);

        builder.Property(r => r.OlusturulmaTarihi)
               .HasDefaultValueSql("GETUTCDATE()");
    }
}
