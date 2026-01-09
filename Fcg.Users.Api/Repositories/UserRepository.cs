using Fcg.Users.Api.Data;
using Fcg.Users.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace Fcg.Users.Api.Repositories;

public class UserRepository
{
    private readonly UsersDbContext _context;
    private readonly ILogger<UserRepository> _logger;
    public UserRepository(UsersDbContext context, ILogger<UserRepository> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<User> CreateAsync(User user)
    {
        _logger.LogInformation("Database: Creating user {Email} with Role {Role}", user.Email, user.Role);
        _context.Users.Add(user);
        await _context.SaveChangesAsync();
        return user;
    }

    public async Task<User?> GetByEmailAsync(string email) => await
    _context.Users.FirstOrDefaultAsync(u => u.Email == email);
    public async Task<User?> GetByIdAsync(Guid id) => await _context.Users.Include(u => u.Library).FirstOrDefaultAsync(u => u.Id == id);

    public async Task<IEnumerable<User>> GetAllAsync() => await _context.Users.Include(u => u.Library).ToListAsync();

    public async Task AddGameToLibraryAsync(Guid userId, Guid gameId)
    {
        _logger.LogInformation("Database: Adding game {GameId} to user {UserId}", gameId, userId);
        var exists = await _context.UserGames.AnyAsync(ug => ug.UserId == userId && ug.GameId == gameId);
        if (exists) return;

        _context.UserGames.Add(new UserGame { Id = Guid.NewGuid(), UserId = userId, GameId = gameId });
        await _context.SaveChangesAsync();
    }

    // Remove um usu�rio por id. Retorna true se removido, false se n�o encontrado.
    public async Task<bool> DeleteAsync(Guid id)
    {
        _logger.LogInformation("Database: Attempting to delete user {Id}", id);
        var user = await _context.Users.FindAsync(id);
        if (user == null)
        {
            _logger.LogInformation("Database: User {Id} not found for deletion", id);
            return false;
        }

        _context.Users.Remove(user);
        await _context.SaveChangesAsync();
        _logger.LogInformation("Database: User {Id} deleted successfully", id);
        return true;
    }
}
