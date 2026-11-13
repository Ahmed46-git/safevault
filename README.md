# SafeVault

SafeVault is a minimal ASP.NET Core API demonstrating validated registration and login, BCrypt password hashing, short-lived JWT authentication, role-based authorization, and parameterized EF Core access using SQLite.

## Run

Set a signing key of at least 32 UTF-8 bytes in the environment. For PowerShell, a fresh local development key can be generated with:

```powershell
$env:Jwt__SigningKey = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
dotnet run
```

The API creates `safevault.db` on startup. The signing key must be supplied through a secret store or environment variable and must not be committed. Production deployments should use HTTPS, a managed secret store, database migrations, request rate limiting, and monitoring. `EnsureCreated` is intended only for this small demonstration.

## Endpoints

- `POST /api/auth/register` creates a regular user account. Usernames are 3-32 ASCII letters, digits, underscores, or hyphens; passwords are 12-72 UTF-8 bytes.
- `POST /api/auth/login` returns a 15-minute bearer token.
- `GET /api/account/me` returns the authenticated user's public account details.
- `GET /api/admin/users?search=...` returns up to 100 public user records and requires the `Admin` role.

New registrations can never choose their own role. Provision the first administrator through a trusted operational process that updates the account role in the database; never expose role assignment on public registration. JSON responses are serialized by ASP.NET Core, and security headers include a restrictive CSP; clients that render returned text as HTML must still encode it at the rendering boundary.
