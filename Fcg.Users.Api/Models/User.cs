using System.ComponentModel.DataAnnotations;

namespace Fcg.Users.Api.Models;

public class User
{
    [Key]
    public Guid Id { get; set; }
    public string Name { get; set; } = null!;
    public string Email { get; set; } = null!;
    public string PasswordHash { get; set; } = null!;
    public string Role { get; set; } = "User";

    // Navigation property to user's library
    public ICollection<UserGame> Library { get; set; } = new List<UserGame>();
}
