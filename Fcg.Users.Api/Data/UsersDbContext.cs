using Microsoft.EntityFrameworkCore;
using Fcg.Users.Api.Models;

namespace Fcg.Users.Api.Data;

public class UsersDbContext : DbContext
{
    public UsersDbContext(DbContextOptions<UsersDbContext> options) : base(options) { }

    public DbSet<User> Users => Set<User>();
    public DbSet<UserGame> UserGames => Set<UserGame>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<User>()
            .HasMany(u => u.Library)
            .WithOne()
            .HasForeignKey(ug => ug.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
