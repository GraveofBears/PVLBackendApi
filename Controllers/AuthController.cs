using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using PVLBackendApi.Models;
using PVLBackendApi.Services;
using PVLBackendApi.Controllers;
using PVLBackendApi.Interfaces;



namespace PVLBackendApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest("Invalid login request.");
            }

            var result = await _authService.VerifyLoginAsync(request.Username, request.Password);

            if (!result.Success)
            {
                return Unauthorized(new
                {
                    success = false,
                    message = result.Message
                });
            }

            var token = _authService.GenerateJwtToken(result.User.Username);

            return Ok(new
            {
                success = true,
                message = result.Message,
                token = token,
                user = new
                {
                    username = result.User.Username,
                    displayName = result.User.Username
                }
            });
        }
    }
}
