using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;
using PVLBackendApi.Models;
using PVLBackendApi.Services;
using PVLBackendApi.Interfaces;
using Serilog;
using Microsoft.AspNetCore.Diagnostics;

// 🔧 Configure Serilog from appsettings.json
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(new ConfigurationBuilder()
        .AddJsonFile("appsettings.json")
        .AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production"}.json", optional: true)
        .AddEnvironmentVariables()
        .Build())
    .CreateLogger();

var builder = WebApplication.CreateBuilder(args);
builder.Host.UseSerilog();

var configuration = builder.Configuration;
var jwtKey = configuration["Jwt:Key"];
var jwtIssuer = configuration["Jwt:Issuer"];
var jwtAudience = configuration["Jwt:Audience"];
var dbPath = configuration["Database:Path"];
var connectionString = $"Data Source={dbPath}";

// Services
builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseSqlite(connectionString));

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtIssuer,
        ValidAudience = jwtAudience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
    };
});

builder.Services.AddAuthorization();

builder.Services.AddControllers().AddJsonOptions(options =>
{
    options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
    options.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Enter 'Bearer' followed by your JWT",
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement {
        {
            new OpenApiSecurityScheme {
                Reference = new OpenApiReference {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod();
    });
});

builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IUserRepository>(provider =>
{
    var logger = provider.GetRequiredService<ILogger<SqliteUserRepository>>();
    return new SqliteUserRepository(dbPath, logger);
});

var app = builder.Build();

// 🌐 Request logging with correlation ID
app.Use(async (context, next) =>
{
    var traceId = Guid.NewGuid().ToString();
    context.Items["TraceId"] = traceId;
    Log.Information("Trace {TraceId}: {Method} {Path}", traceId, context.Request.Method, context.Request.Path);
    await next.Invoke();
    Log.Information("Trace {TraceId}: Response {StatusCode}", traceId, context.Response.StatusCode);
});

// 🧯 Exception logging
app.UseExceptionHandler(errorApp =>
{
    errorApp.Run(async context =>
    {
        var exception = context.Features.Get<IExceptionHandlerFeature>()?.Error;
        Log.Error(exception, "Unhandled exception occurred.");
        context.Response.StatusCode = 500;
        await context.Response.WriteAsync("An error occurred.");
    });
});

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseAuthorization();
app.UseCors();

// 🔐 Secure endpoint
app.MapGet("/users", [Authorize] async (AuthDbContext db) =>
{
    var users = await db.Users.ToListAsync();
    return Results.Ok(users);
});

// 🔑 Login endpoint
app.MapPost("/login", async (LoginRequest login, AuthDbContext db) =>
{
    Log.Information("Login attempt: Username='{Username}'", login.Username);

    var user = await db.Users.FirstOrDefaultAsync(u => u.Username == login.Username);

    if (user is null)
    {
        Log.Warning("User '{Username}' not found.", login.Username);
        return Results.Unauthorized();
    }

    var isValid = BCrypt.Net.BCrypt.Verify(login.Password, user.PasswordHash);
    Log.Information("Password verification for '{Username}': {IsValid}", login.Username, isValid);

    if (!isValid)
        return Results.Unauthorized();

    var claims = new[]
    {
        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
        new Claim(ClaimTypes.Name, user.Username)
    };

    var token = new JwtSecurityToken(
        issuer: jwtIssuer,
        audience: jwtAudience,
        claims: claims,
        expires: DateTime.UtcNow.AddHours(2),
        signingCredentials: new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
            SecurityAlgorithms.HmacSha256)
    );

    var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
    Log.Information("JWT issued for user '{Username}'", user.Username);
    return Results.Ok(new { token = tokenString });
});

// 🩺 Health check endpoint
app.MapGet("/health", () =>
{
    var dbExists = File.Exists(dbPath);
    var walExists = File.Exists($"{dbPath}-wal");
    var shmExists = File.Exists($"{dbPath}-shm");

    Log.Information("Health check: DB={DbExists}, WAL={WalExists}, SHM={ShmExists}", dbExists, walExists, shmExists);

    return Results.Ok(new
    {
        dbExists,
        walExists,
        shmExists
    });
});

app.MapControllers();

// 🧠 DB initialization and WAL status
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    db.Database.EnsureCreated();

    Log.Information("Ensured database is created at path: {DbPath}", dbPath);

    try
    {
        using var connection = new Microsoft.Data.Sqlite.SqliteConnection(connectionString);
        connection.Open();

        var command = connection.CreateCommand();
        command.CommandText = "PRAGMA journal_mode;";
        var mode = command.ExecuteScalar()?.ToString();
        Log.Information("SQLite journal mode: {JournalMode}", mode);

        if (File.Exists($"{dbPath}-wal"))
            Log.Information("WAL file detected — DB is in active use.");

        if (File.Exists($"{dbPath}-shm"))
            Log.Information("SHM file detected — shared memory coordination active.");
    }
    catch (Exception ex)
    {
        Log.Error(ex, "Failed to inspect SQLite DB journal mode.");
    }
}

app.Run();
