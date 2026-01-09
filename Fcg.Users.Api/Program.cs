using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.EntityFrameworkCore;
using Fcg.Users.Api.Data;
using Fcg.Users.Api.Models;
using Fcg.Users.Api.Repositories;
using System.ComponentModel.DataAnnotations;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.OpenApi.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using System.Diagnostics.Metrics;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
// Configure Swagger/OpenAPI with Bearer auth
builder.Services.AddSwaggerGen(c =>
{
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Insira 'Bearer' [espa�o] e o token JWT aqui. Ex: 'Bearer eyJhbGci...'"
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement {
        {
            new OpenApiSecurityScheme {
                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" }
            }, new string[] { }
        }
    });
});

// JWT configuration
var jwtKey = builder.Configuration["Jwt:Key"] ?? "very-strong-default-key-change-me";
var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "fcg";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "fcg-audience";
var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = "Bearer";
    options.DefaultChallengeScheme = "Bearer";
}).AddJwtBearer("Bearer", options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtIssuer,
        ValidAudience = jwtAudience,
        IssuerSigningKey = signingKey
    };
});

// Require authentication by default (endpoints must be authenticated unless marked AllowAnonymous)
builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
});

// Add SQLite DB
var connectionString = builder.Configuration.GetConnectionString("UsersConnection") ?? "Data Source=users.db";
builder.Services.AddDbContext<UsersDbContext>(options => options.UseSqlite(connectionString));

builder.Services.AddScoped<UserRepository>();

// Custom Metrics
var appMeter = new Meter("Fcg.Users.Api", "1.0.0");
var loginCounter = appMeter.CreateCounter<long>("users_login_attempts", description: "Total login attempts");
var userCreatedCounter = appMeter.CreateCounter<long>("users_created_total", description: "Total users created");

// Definição do Recurso (Nome do Serviço, Versão, etc.)
// O AddService tentará ler OTEL_SERVICE_NAME do ambiente, mas definimos um fallback.
Action<ResourceBuilder> configureResource = r => r
    .AddService(
        serviceName: builder.Configuration.GetValue<string>("OTEL_SERVICE_NAME") ?? "users-service",
        serviceVersion: "1.0.0",
        serviceInstanceId: Environment.MachineName);

// Configuração de Tracing e Metrics
builder.Services.AddOpenTelemetry()
    .ConfigureResource(configureResource)
    .WithTracing(tracing =>
    {
        tracing
            .AddAspNetCoreInstrumentation()
            .AddHttpClientInstrumentation()
            .AddOtlpExporter(); // Usa as variáveis de ambiente OTEL_EXPORTER_OTLP_*
    })
    .WithMetrics(metrics =>
    {
        metrics
            .AddAspNetCoreInstrumentation()
            .AddHttpClientInstrumentation()
            .AddRuntimeInstrumentation()
            .AddMeter(appMeter.Name)
            .AddOtlpExporter(); // Usa as variáveis de ambiente OTEL_EXPORTER_OTLP_*
    });

// Configuração de Logs
builder.Logging.AddOpenTelemetry(options =>
{
    options.IncludeScopes = true;
    options.IncludeFormattedMessage = true;
    options.SetResourceBuilder(ResourceBuilder.CreateDefault().AddService(
        builder.Configuration.GetValue<string>("OTEL_SERVICE_NAME") ?? "users-service"));

    options.AddOtlpExporter(); // Usa as variáveis de ambiente OTEL_EXPORTER_OTLP_*
});
var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<UsersDbContext>();
    // Ensure database schema exists even without migrations
    db.Database.EnsureCreated();

    // Seed demo accounts only if DB est� vazio
    if (!db.Users.Any())
    {
        var hasher = new PasswordHasher<Fcg.Users.Api.Models.User>();

        var admin = new Fcg.Users.Api.Models.User
        {
            Id = Guid.NewGuid(),
            Name = "administrador",
            Email = "admin@hotmail.com",
            Role = "Admin"
        };
        admin.PasswordHash = hasher.HashPassword(admin, "123@Admin");

        var user = new Fcg.Users.Api.Models.User
        {
            Id = Guid.NewGuid(),
            Name = "usuario",
            Email = "usuario@hotmail.com",
            Role = "User"
        };
        user.PasswordHash = hasher.HashPassword(user, "123@User");

        db.Users.AddRange(admin, user);
        db.SaveChanges();
    }
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "Users microservice running with DB");

// Health endpoint for orchestration and health checks
app.MapGet("/health", () => Results.Ok(new { status = "Healthy" })).AllowAnonymous();

// New: GET all users (includes admins) - requires Admin role
app.MapGet("/api/users", async (UserRepository repo) =>
{
    var users = await repo.GetAllAsync();
    // Return minimal public info (avoid returning password hashes)
    var list = users.Select(u => new { u.Id, u.Name, u.Email, u.Role, Library = u.Library.Select(l => new { l.GameId, l.PurchasedDate }) });
    return Results.Ok(list);
}).RequireAuthorization(new AuthorizationPolicyBuilder().RequireRole("Admin").Build());

app.MapPost("/api/users", async (CreateUserRequest req, UserRepository repo) =>
{
    var errors = new List<string>();

    // Validate Name
    if (string.IsNullOrWhiteSpace(req.Name) || req.Name.Trim().Length < 3)
        errors.Add("Name � obrigat�rio e deve ter no m�nimo 3 caracteres.");

    // Validate Email
    if (string.IsNullOrWhiteSpace(req.Email) || !new EmailAddressAttribute().IsValid(req.Email))
        errors.Add("Email � obrigat�rio e deve ser v�lido.");

    // Validate Password strength
    var pwd = req.Password ?? string.Empty;
    bool hasUpper = pwd.Any(char.IsUpper);
    bool hasLower = pwd.Any(char.IsLower);
    bool hasDigit = pwd.Any(char.IsDigit);
    bool hasSymbol = pwd.Any(c => !char.IsLetterOrDigit(c));
    if (pwd.Length < 8 || !hasUpper || !hasLower || !hasDigit || !hasSymbol)
        errors.Add("Password deve ter no m�nimo 8 caracteres e conter mai�scula, min�scula, d�gito e s�mbolo.");

    if (errors.Count > 0)
        return Results.BadRequest(new { Errors = errors });

    var user = new User { Id = Guid.NewGuid(), Name = req.Name.Trim(), Email = req.Email.Trim(), Role = "User" };
    // Hash password before saving
    var hasher = new PasswordHasher<User>();
    user.PasswordHash = hasher.HashPassword(user, req.Password);

    var created = await repo.CreateAsync(user);
    // return public info only
    return Results.Created($"/api/users/{created.Id}", new { created.Id, created.Name, created.Email, created.Role });
}).AllowAnonymous();

// New endpoint: create admin user (same validation as normal user, but Role = "Admin")
// Now restricted to Admin role only
app.MapPost("/api/users/admin", async (CreateUserRequest req, UserRepository repo) =>
{
    var errors = new List<string>();

    // Validate Name
    if (string.IsNullOrWhiteSpace(req.Name) || req.Name.Trim().Length < 3)
        errors.Add("Name � obrigat�rio e deve ter no m�nimo 3 caracteres.");

    // Validate Email
    if (string.IsNullOrWhiteSpace(req.Email) || !new EmailAddressAttribute().IsValid(req.Email))
        errors.Add("Email � obrigat�rio e deve ser v�lido.");

    // Validate Password strength
    var pwd = req.Password ?? string.Empty;
    bool hasUpper = pwd.Any(char.IsUpper);
    bool hasLower = pwd.Any(char.IsLower);
    bool hasDigit = pwd.Any(char.IsDigit);
    bool hasSymbol = pwd.Any(c => !char.IsLetterOrDigit(c));
    if (pwd.Length < 8 || !hasUpper || !hasLower || !hasDigit || !hasSymbol)
        errors.Add("Password deve ter no m�nimo 8 caracteres e conter mai�scula, min�scula, d�gito e s�mbolo.");

    if (errors.Count > 0)
        return Results.BadRequest(new { Errors = errors });

    var user = new User { Id = Guid.NewGuid(), Name = req.Name.Trim(), Email = req.Email.Trim(), Role = "Admin" };
    // Hash password before saving
    var hasher = new PasswordHasher<User>();
    user.PasswordHash = hasher.HashPassword(user, req.Password);

    var created = await repo.CreateAsync(user);
    // return public info only
    return Results.Created($"/api/users/{created.Id}", new { created.Id, created.Name, created.Email, created.Role });
}).RequireAuthorization(new AuthorizationPolicyBuilder().RequireRole("Admin").Build());

app.MapPost("/api/login", async (LoginRequest req, UserRepository repo) =>
{
    var user = await repo.GetByEmailAsync(req.Email);
    if (user == null) return Results.Unauthorized();

    // Verify hashed password
    var hasher = new PasswordHasher<User>();
    var verify = hasher.VerifyHashedPassword(user, user.PasswordHash, req.Password);
    if (verify == PasswordVerificationResult.Failed) return Results.Unauthorized();

    // Create JWT
    var claims = new[] {
        new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
        new Claim(JwtRegisteredClaimNames.Email, user.Email),
        new Claim("name", user.Name),
        // include role claim so Jwt contains role information
        new Claim(ClaimTypes.Role, user.Role ?? string.Empty)
    };

    var creds = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);
    var jwt = new JwtSecurityToken(
        issuer: jwtIssuer,
        audience: jwtAudience,
        claims: claims,
        expires: DateTime.UtcNow.AddHours(8),
        signingCredentials: creds
    );

    var token = new JwtSecurityTokenHandler().WriteToken(jwt);

    return Results.Ok(new { Token = token, UserId = user.Id, Email = user.Email });
}).AllowAnonymous();

app.MapGet("/api/users/{id}", async (Guid id, UserRepository repo) =>
{
    var user = await repo.GetByIdAsync(id);
    return user is not null ? Results.Ok(user) : Results.NotFound();
}).RequireAuthorization();

// Endpoint to delete user by id - only admins
app.MapDelete("/api/users/{id}", async (Guid id, UserRepository repo) =>
{
    var deleted = await repo.DeleteAsync(id);
    return deleted ? Results.NoContent() : Results.NotFound();
}).RequireAuthorization(new AuthorizationPolicyBuilder().RequireRole("Admin").Build());

// Endpoint to add a game to user's library called by Games microservice
app.MapPost("/api/users/{id}/library", async (Guid id, AddGameRequest req, UserRepository repo) =>
{
    // Simple validation
    if (id != req.UserId) return Results.BadRequest(new { Message = "UserId mismatch" });

    await repo.AddGameToLibraryAsync(req.UserId, req.GameId);
    return Results.Ok();
}).RequireAuthorization();

app.MapControllers();

app.Run();

record CreateUserRequest(string Name, string Email, string Password);
record LoginRequest(string Email, string Password);
record AddGameRequest(Guid UserId, Guid GameId);