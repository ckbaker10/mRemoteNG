using System;

namespace mRemoteNG.Security.Policy;

public static class ExportPolicy
{
    public static bool AllowsPlaintext(SecurityPolicy policy) => policy.AllowPlaintextExport && !policy.RequireFullEncryption;

    public static void ValidatePlaintext(SecurityPolicy policy)
    {
        if (!AllowsPlaintext(policy))
            throw new InvalidOperationException("Machine policy prohibits plaintext connection exports.");
    }
}
