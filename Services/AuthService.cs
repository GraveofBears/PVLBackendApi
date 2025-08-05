using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using PVLBackendApi.Interfaces;
using PVLBackendApi.Models;
using PVLBackendApi.Services;

namespace PVLBackendApi.Services
{
    public class AuthService : IAuthService
    {
        private readonly IUserRepository _repo;
        private readonly IConfiguration _config;

        public AuthService(IUserRepository repo, IConfiguration config)
        {
            _repo = repo;
            _config = config;
        }

        /// <summary>
        /// Verifies the user's credentials and returns login result.
        /// </summary>
        public async Task<LoginResult> VerifyLoginAsync(string username, string password)
        {
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            {
                return new LoginResult
                {
                    Success = false,
                    Message = "Username and password are required."
                };
            }

            var user = await _repo.GetUserByUsernameAsync(username);
            if (user is null)
            {
                return new LoginResult
                {
                    Success = false,
                    Message = "User not found."
                };
            }

            bool passwordValid = PasswordHelper.VerifyPassword(user.PasswordHash, password);
            if (!passwordValid)
            {
                return new LoginResult
                {
                    Success = false,
                    Message = "Invalid password."
                };
            }

            if (user.IsSuspended)
            {
                return new LoginResult
                {
                    Success = false,
                    Message = "Account is suspended. Please contact support."
                };
            }

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

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
