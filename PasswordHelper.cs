using BCrypt.Net;
using Serilog;

public static class PasswordHelper
{
    /// <summary>
    /// Hashes a plain-text password using BCrypt with enhanced work factor.
    /// </summary>
    public static string HashPassword(string password)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            Log.Warning("Attempted to hash an empty or null password.");
            throw new ArgumentException("Password cannot be null or empty.", nameof(password));
        }

        Log.Information("Hashing password using BCrypt.");
        return BCrypt.Net.BCrypt.EnhancedHashPassword(password);
    }

    /// <summary>
    /// Verifies an input password against a hashed password using BCrypt.
    /// </summary>
    public static bool VerifyPassword(string hashedPassword, string inputPassword)
    {
        if (string.IsNullOrWhiteSpace(hashedPassword) || string.IsNullOrWhiteSpace(inputPassword))
        {
            Log.Warning("Password verification failed due to empty input.");
            return false;
        }

        try
        {
            var result = BCrypt.Net.BCrypt.EnhancedVerify(inputPassword, hashedPassword);
            Log.Information("Password verification result: {Result}", result);
            return result;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Exception during password verification.");
            return false;
        }
    }
}
