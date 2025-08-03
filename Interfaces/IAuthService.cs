using PVLBackendApi.Models;

namespace PVLBackendApi.Interfaces;

public interface IAuthService
{
    Task<LoginResult> VerifyLoginAsync(string username, string password);
    string GenerateJwtToken(string username);
}
