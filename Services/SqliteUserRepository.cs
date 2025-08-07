using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using PVLBackendApi.Models;
using PVLBackendApi.Interfaces;
using System.Collections.Generic;
using System.Threading.Tasks;

public class SqliteUserRepository : IUserRepository
{
    private readonly string _connectionString;
    private readonly ILogger<SqliteUserRepository> _logger;

    public SqliteUserRepository(string dbPath, ILogger<SqliteUserRepository> logger)
    {
        _connectionString = $"Data Source={dbPath}";
        _logger = logger;
    }

    public User? GetUserByUsername(string username)
    {
        _logger.LogInformation("Attempting to retrieve user by username: {Username}", username);

        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            _logger.LogInformation("Opened SQLite connection to: {ConnectionString}", _connectionString);

            var command = connection.CreateCommand();
            command.CommandText = "SELECT * FROM Users WHERE Username = $username";
            command.Parameters.AddWithValue("$username", username);

            using var reader = command.ExecuteReader();
            if (reader.Read())
            {
                var user = new User
                {
                    Username = reader.GetString(reader.GetOrdinal("username")),
                    PasswordHash = reader.GetString(reader.GetOrdinal("passwordHash")),
                    IsSuspended = reader.GetInt32(reader.GetOrdinal("isSuspended")) != 0
                    // Add other fields as needed
                };

                _logger.LogInformation("User '{Username}' found in database.", username);
                return user;
            }

            _logger.LogWarning("User '{Username}' not found in database.", username);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while retrieving user '{Username}'", username);
            return null;
        }
    }

    public async Task<User?> GetUserByUsernameAsync(string username)
    {
        return await Task.Run(() => GetUserByUsername(username));
    }

    public async Task CreateUserAsync(User user)
    {
        _logger.LogWarning("CreateUserAsync is not yet implemented.");
        await Task.CompletedTask;
    }

    public async Task<IEnumerable<User>> GetAllUsersAsync()
    {
        _logger.LogWarning("GetAllUsersAsync is not yet implemented.");
        return await Task.FromResult(new List<User>());
    }
}
