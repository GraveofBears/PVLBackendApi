using Microsoft.Data.Sqlite;
using PVLBackendApi.Models;
using PVLBackendApi.Services;
using PVLBackendApi.Interfaces;



public class SqliteUserRepository : IUserRepository
{
    private readonly string _connectionString;

    public SqliteUserRepository(string dbPath)
    {
        _connectionString = $"Data Source={dbPath}";
    }

    public User? GetUserByUsername(string username)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        var command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM Users WHERE Username = $username";
        command.Parameters.AddWithValue("$username", username);

        using var reader = command.ExecuteReader();
        if (reader.Read())
        {
            return new User
            {
                Username = reader.GetString(reader.GetOrdinal("username")),
                PasswordHash = reader.GetString(reader.GetOrdinal("passwordHash")),
                IsSuspended = reader.GetInt32(reader.GetOrdinal("isSuspended")) != 0
                // Pull other fields if needed
            };
        }

        return null;
    }

    public async Task<User?> GetUserByUsernameAsync(string username)
    {
        return await Task.Run(() => GetUserByUsername(username));
    }

    public async Task CreateUserAsync(User user)
    {
        // Implement user creation logic here
        await Task.CompletedTask;
    }

    public async Task<IEnumerable<User>> GetAllUsersAsync()
    {
        // Implement logic to get all users here
        return await Task.FromResult(new List<User>());
    }
}
