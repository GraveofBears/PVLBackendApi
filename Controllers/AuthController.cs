using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using PVLBackendApi.Models;
using PVLBackendApi.Interfaces;
using System.Linq;

namespace PVLBackendApi.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(IAuthService authService, ILogger<AuthController> logger)
        {
            _authService = authService;
            _logger = logger;
        }

        public class LoginRequest
        {
            [Required]
            [JsonPropertyName("username")]
            public string Username { get; set; }

            [Required]
            [JsonPropertyName("password")]
            public string Password { get; set; }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            _logger.LogInformation("🔐 Received login request for user: {Username}", request.Username);

            if (!ModelState.IsValid)
            {
                _logger.LogWarning("⚠️ Login request model validation failed for user: {Username}", request.Username);
                return BadRequest(new
                {
                    success = false,
                    message = "Invalid login request."
                });
            }

            // 🧪 Password Diagnostics
            if (request.Password != null)
            {
                _logger.LogInformation("🔍 Incoming password: '{Password}'", request.Password);
                _logger.LogInformation("🔍 Length: {Length}", request.Password.Length);
                _logger.LogInformation("🔍 Char codes: {Codes}", string.Join(",", request.Password.Select(c => (int)c)));
                _logger.LogInformation("🔍 Hex: {Hex}", string.Join(" ", request.Password.Select(c => ((int)c).ToString("X2"))));
            }

            var result = await _authService.VerifyLoginAsync(request.Username, request.Password);

            if (result is null)
            {
                _logger.LogError("❌ AuthService returned null for user: {Username}", request.Username);
                return StatusCode(500, new
                {
                    success = false,
                    message = "Internal authentication error."
                });
            }

            if (!result.Success)
            {
                _logger.LogWarning("❌ Login failed for user '{Username}': {Message}", request.Username, result.Message);
                return Unauthorized(new
                {
                    success = false,
                    message = result.Message
                });
            }

            var token = _authService.GenerateJwtToken(result.User.Username);
            _logger.LogInformation("✅ JWT token generated for user: {Username}", result.User.Username);

            return Ok(new
            {
                success = true,
                message = "Login successful.",
                token = token,
                user = new
                {
                    username = result.User.Username,
                    displayName = result.User.Username // Customize if needed
                }
            });
        }
    }
}
