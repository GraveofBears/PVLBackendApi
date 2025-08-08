using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using PVLBackendApi.Interfaces;
using PVLBackendApi.Models;

namespace PVLBackendApi.Services
{
    public class AuthService : IAuthService
    {
        private readonly IUserRepository _repo;
        private readonly IConfiguration _config;
        private readonly ILogger<AuthService> _logger;

        public AuthService(IUserRepository repo, IConfiguration config, ILogger<AuthService> logger)
        {
            _repo = repo;
            _config = config;
            _logger = logger;
        }

        /// <summary>
        /// Verifies the user's credentials and returns login result.
        /// </summary>
        public async Task<LoginResult> VerifyLoginAsync(string username, string password)
        {
            _logger.LogInformation("🔐 Login attempt for user: {Username}", username);

            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            {
                _logger.LogWarning("❌ Login failed: Missing username or password.");
                return new LoginResult
                {
                    Success = false,
                    Message = "Username and password are required."
                };
            }

            var user = await _repo.GetUserByUsernameAsync(username);
            if (user is null)
            {
                _logger.LogWarning("❌ Login failed: User '{Username}' not found.", username);
                return new LoginResult
                {
                    Success = false,
                    Message = "User not found."
                };
            }

            // 🧪 Deep diagnostics
            _logger.LogInformation("🔍 Incoming password: '{Password}'", password);
            _logger.LogInformation("🔍 Stored hash for '{Username}': '{Hash}'", username, user.PasswordHash);

            bool passwordValid;
            try
            {
                passwordValid = BCrypt.Net.BCrypt.Verify(password, user.PasswordHash);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Error during password verification for user '{Username}'.", username);
                return new LoginResult
                {
                    Success = false,
                    Message = "Internal error during password verification."
                };
            }

            _logger.LogInformation("✅ Password verification result for '{Username}': {IsValid}", username, passwordValid);

            if (!passwordValid)
            {
                _logger.LogWarning("❌ Login failed: Invalid password for user '{Username}'.", username);
                return new LoginResult
                {
                    Success = false,
                    Message = "Invalid password."
                };
            }

            if (user.IsSuspended)
            {
                _logger.LogWarning("🚫 Login failed: Account for user '{Username}' is suspended.", username);
                return new LoginResult
                {
                    Success = false,
                    Message = "Account is suspended. Please contact support."
                };
            }

            _logger.LogInformation("✅ Login successful for user: {Username}", username);
            return new LoginResult
            {
                Success = true,
                Message = "Login successful.",
                User = user
            };
        }

        /// <summary>
        /// Generates a JWT token for the authenticated user.
        /// </summary>
        public string GenerateJwtToken(string username)
        {
            _logger.LogInformation("🔐 Generating JWT token for user: {Username}", username);

            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_config["Jwt:Key"] ?? throw new InvalidOperationException("Missing JWT Key")));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.Name, username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddHours(2),
                signingCredentials: creds
            );

            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
            _logger.LogInformation("✅ JWT token generated for user: {Username}", username);

            return tokenString;
        }
    }
}
