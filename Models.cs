using System.ComponentModel.DataAnnotations;

namespace safe_vault;

public sealed class VaultUser
{
	public Guid Id { get; set; } = Guid.NewGuid();

	public required string Username { get; set; }

	public required string PasswordHash { get; set; }

	public string Role { get; set; } = "User";

	public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

/// <summary>Credentials and username for a new account.</summary>
public sealed record RegisterRequest
{
	[Required, StringLength(32, MinimumLength = 3), RegularExpression("^[A-Za-z0-9_-]+$")]
	public required string Username { get; init; }

	[Required, StringLength(72, MinimumLength = 12)]
	public required string Password { get; init; }
}

/// <summary>Credentials used to obtain an access token.</summary>
public sealed record LoginRequest
{
	[Required, StringLength(32, MinimumLength = 3)]
	public required string Username { get; init; }

	[Required, StringLength(72, MinimumLength = 1)]
	public required string Password { get; init; }
}

/// <summary>Public account details.</summary>
public sealed record UserResponse(Guid Id, string Username, string Role, DateTimeOffset CreatedAt);

/// <summary>A short-lived bearer access token.</summary>
public sealed record TokenResponse(string AccessToken, DateTimeOffset ExpiresAt);
