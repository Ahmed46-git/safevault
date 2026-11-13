using Microsoft.EntityFrameworkCore;

namespace safe_vault;

public sealed class VaultDbContext(DbContextOptions<VaultDbContext> options) : DbContext(options)
{
	public DbSet<VaultUser> Users => Set<VaultUser>();

	protected override void OnModelCreating(ModelBuilder modelBuilder)
	{
		var user = modelBuilder.Entity<VaultUser>();
		user.HasKey(account => account.Id);
		user.Property(account => account.Username).HasMaxLength(32).UseCollation("NOCASE");
		user.HasIndex(account => account.Username).IsUnique();
		user.Property(account => account.PasswordHash).HasMaxLength(100).IsRequired();
		user.Property(account => account.Role).HasMaxLength(16).IsRequired();
	}
}
