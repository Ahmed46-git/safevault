using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using safe_vault;

var builder = WebApplication.CreateBuilder(args);
var signingKey = builder.Configuration["Jwt:SigningKey"];
if (string.IsNullOrWhiteSpace(signingKey) || Encoding.UTF8.GetByteCount(signingKey) < 32)
{
    throw new InvalidOperationException("Configure Jwt:SigningKey with at least 32 UTF-8 bytes.");
}

var issuer = builder.Configuration["Jwt:Issuer"] ?? "SafeVault";
var audience = builder.Configuration["Jwt:Audience"] ?? "SafeVault.Api";

builder.Services.AddValidation();
builder.Services.AddDbContext<VaultDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("Vault") ?? "Data Source=safevault.db"));
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey)),
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
            NameClaimType = ClaimTypes.Name,
            RoleClaimType = ClaimTypes.Role
        };
    });
builder.Services.AddAuthorization(options =>
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin")));
builder.Services.AddProblemDetails();

var app = builder.Build();
app.UseExceptionHandler();
app.UseHttpsRedirection();
app.Use(async (context, next) =>
{
    context.Response.Headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'";
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    await next();
});
app.UseAuthentication();
app.UseAuthorization();

using (var scope = app.Services.CreateScope())
{
    var database = scope.ServiceProvider.GetRequiredService<VaultDbContext>();
    await database.Database.EnsureCreatedAsync();
}

app.MapPost("/api/auth/register", async Task<IResult> (RegisterRequest request, VaultDbContext database) =>
{
    if (Encoding.UTF8.GetByteCount(request.Password) > 72)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            [nameof(request.Password)] = ["Password must be at most 72 UTF-8 bytes."]
        });
    }

    if (await database.Users.AnyAsync(user => user.Username == request.Username))
    {
        return Results.Conflict(new { error = "Username is unavailable." });
    }

    var user = new VaultUser
    {
        Username = request.Username,
        PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password, workFactor: 12)
    };
    database.Users.Add(user);
    try
    {
        await database.SaveChangesAsync();
    }
    catch (DbUpdateException)
    {
        return Results.Conflict(new { error = "Username is unavailable." });
    }

    var response = ToUserResponse(user);
    return Results.Created("/api/account/me", response);
});

app.MapPost("/api/auth/login", async Task<IResult> (LoginRequest request, VaultDbContext database) =>
{
    if (Encoding.UTF8.GetByteCount(request.Password) > 72)
    {
        return Results.Unauthorized();
    }

    var user = await database.Users.SingleOrDefaultAsync(account => account.Username == request.Username);
    if (user is null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
    {
        return Results.Unauthorized();
    }

    var expiresAt = DateTimeOffset.UtcNow.AddMinutes(15);
    var token = new JwtSecurityToken(
        issuer: issuer,
        audience: audience,
        claims:
        [
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, user.Role)
        ],
        expires: expiresAt.UtcDateTime,
        signingCredentials: new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey)), SecurityAlgorithms.HmacSha256));

    return Results.Ok(new TokenResponse(new JwtSecurityTokenHandler().WriteToken(token), expiresAt));
});

app.MapGet("/api/account/me", async Task<IResult> (ClaimsPrincipal principal, VaultDbContext database) =>
{
    if (!Guid.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
    {
        return Results.Unauthorized();
    }

    var user = await database.Users.AsNoTracking().SingleOrDefaultAsync(account => account.Id == userId);
    return user is null ? Results.NotFound() : Results.Ok(ToUserResponse(user));
}).RequireAuthorization();

app.MapGet("/api/admin/users", async Task<IResult> (string? search, VaultDbContext database) =>
{
    if (search?.Length > 100)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            [nameof(search)] = ["Search must be 100 characters or fewer."]
        });
    }

    var query = database.Users.AsNoTracking();
    if (!string.IsNullOrWhiteSpace(search))
    {
        query = query.Where(user => user.Username.Contains(search));
    }

    var users = await query.OrderBy(user => user.Username)
        .Select(user => new UserResponse(user.Id, user.Username, user.Role, user.CreatedAt))
        .Take(100)
        .ToListAsync();
    return Results.Ok(users);
}).RequireAuthorization("AdminOnly");

app.Run();

static UserResponse ToUserResponse(VaultUser user) =>
    new(user.Id, user.Username, user.Role, user.CreatedAt);
