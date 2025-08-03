using PVLBackendApi.Models;

namespace PVLBackendApi.Interfaces;

public interface IUserRepository
{
    Task<User?> GetUserByUsernameAsync(string username);
    Task CreateUserAsync(User user);
    Task<IEnumerable<User>> GetAllUsersAsync();
}
