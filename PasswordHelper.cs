using BCrypt.Net;

public static class PasswordHelper
{
    /// <summary>
    /// Hashes a plain-text password using BCrypt with enhanced work factor.
    /// </summary>
    public static string HashPassword(string password)
    {
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("Password cannot be null or empty.", nameof(password));

        return BCrypt.Net.BCrypt.EnhancedHashPassword(password);
    }

    /// <summary>
    /// Verifies an input password against a hashed password using BCrypt.
    /// </summary>
    public static bool VerifyPassword(string hashedPassword, string inputPassword)
    {
        if (string.IsNullOrWhiteSpace(hashedPassword) || string.IsNullOrWhiteSpace(inputPassword))
            return false;

        try
        {
            return BCrypt.Net.BCrypt.EnhancedVerify(inputPassword, hashedPassword);
        }
        catch
        {
            // If verification throws (e.g., invalid format), fail gracefully.
            return false;
        }
    }
}
