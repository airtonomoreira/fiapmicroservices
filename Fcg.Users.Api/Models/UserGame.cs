using System.ComponentModel.DataAnnotations;

namespace Fcg.Users.Api.Models;

public class UserGame
{
    [Key]
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public Guid GameId { get; set; }
    public DateTime PurchasedDate { get; set; } = DateTime.UtcNow;
}
