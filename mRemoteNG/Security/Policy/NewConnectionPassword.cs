using System;
using System.Linq;
using System.Security;
using mRemoteNG.Tools;

namespace mRemoteNG.Security.Policy;

public static class NewConnectionPassword
{
    // A null result preserves the existing unprotected-file behavior when unmanaged.
    // Cancellation throws before a connection model or destination file is created.
    public static string Request(SecurityPolicy policy, Func<Optional<SecureString>> requestPassword)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(requestPassword);
        if (!policy.HasPasswordRequirements) return null;
        var result = requestPassword();
        if (result == null || !result.Any()) throw new OperationCanceledException();
        using SecureString key = result.First();
        string password = key.ConvertToUnsecureString();
        MasterPasswordValidator.Validate(password, policy);
        return password;
    }
}
