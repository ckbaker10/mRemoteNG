using System;
using System.Linq;

namespace mRemoteNG.Security.Policy;

public static class MasterPasswordValidator
{
    // This is a public legacy format constant, not a user credential.
    public const string LegacyDefaultPassword = "mR3m";

    public static string GetError(string password, SecurityPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (!policy.HasPasswordRequirements) return null;
        if (string.IsNullOrWhiteSpace(password))
            return "Machine policy requires a personal master password.";
        // The existing PKCS#5 conversion rejects UTF-16 code units above 255.
        // Reject unsupported managed passwords before a later save can fail.
        if (password.Any(c => c > byte.MaxValue))
            return "The master password contains characters unsupported by the legacy connection-file encoding.";
        if (password == LegacyDefaultPassword)
            return "Machine policy requires a personal master password.";
        if (password.Length < policy.MinimumMasterPasswordLength)
            return "The master password is shorter than machine policy permits.";
        if (policy.RequireUppercase && !password.Any(char.IsUpper))
            return "The master password must contain an uppercase letter.";
        if (policy.RequireLowercase && !password.Any(char.IsLower))
            return "The master password must contain a lowercase letter.";
        if (policy.RequireDigit && !password.Any(char.IsDigit))
            return "The master password must contain a digit.";
        if (policy.RequireSpecialCharacter && !password.Any(IsSpecial))
            return "The master password must contain a special character other than whitespace.";
        return null;
    }

    private static bool IsSpecial(char value) => !char.IsLetterOrDigit(value) && !char.IsWhiteSpace(value);

    public static void Validate(string password, SecurityPolicy policy)
    {
        string error = GetError(password, policy);
        if (error != null) throw new InvalidOperationException(error);
    }
}
