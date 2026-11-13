using System;
using System.Collections.Generic;

namespace mRemoteNG.Security.Policy;

/// <summary>
/// A validated machine-policy snapshot. Missing values preserve unmanaged behavior.
/// Cipher engine, block cipher mode and full-file encryption are not part of this policy:
/// administrators set them through the existing Security options registry values.
/// </summary>
public sealed class SecurityPolicy
{
    /// <summary>The registry value names this policy reads.</summary>
    public static IReadOnlyList<string> ValueNames { get; } =
    [
        nameof(RequireMasterPassword), nameof(MinimumMasterPasswordLength), nameof(RequireUppercase),
        nameof(RequireLowercase), nameof(RequireDigit), nameof(RequireSpecialCharacter),
        nameof(AllowPersistentUnlock), nameof(AllowPlaintextExport), nameof(MinimumKdfIterations),
        nameof(EnforceEncryptionOptions)
    ];

    public bool RequireMasterPassword { get; }
    public int MinimumMasterPasswordLength { get; }
    public bool RequireUppercase { get; }
    public bool RequireLowercase { get; }
    public bool RequireDigit { get; }
    public bool RequireSpecialCharacter { get; }
    public bool AllowPersistentUnlock { get; }
    public bool AllowPlaintextExport { get; }
    public int MinimumKdfIterations { get; }

    /// <summary>
    /// Makes the administrator values of the Security options binding for existing files too:
    /// files whose protection differs from them are not opened, and formats that cannot meet
    /// them are refused. Without it those values only preset and lock the options.
    /// </summary>
    public bool EnforceEncryptionOptions { get; }

    public bool HasPasswordRequirements => RequireMasterPassword || MinimumMasterPasswordLength > 0
        || RequireUppercase || RequireLowercase || RequireDigit || RequireSpecialCharacter;

    /// <summary>
    /// DPAPI protection opens the connections file for the Windows account without any password.
    /// That is a persistent unlock and leaves no master password to enforce requirements on.
    /// </summary>
    public bool AllowsDpapiConnectionProtection => AllowPersistentUnlock && !HasPasswordRequirements;

    public SecurityPolicy(IReadOnlyDictionary<string, object> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        RequireMasterPassword = Boolean(values, nameof(RequireMasterPassword), false);
        MinimumMasterPasswordLength = Integer(values, nameof(MinimumMasterPasswordLength), 0, 1024);
        RequireUppercase = Boolean(values, nameof(RequireUppercase), false);
        RequireLowercase = Boolean(values, nameof(RequireLowercase), false);
        RequireDigit = Boolean(values, nameof(RequireDigit), false);
        RequireSpecialCharacter = Boolean(values, nameof(RequireSpecialCharacter), false);
        AllowPersistentUnlock = Boolean(values, nameof(AllowPersistentUnlock), true);
        AllowPlaintextExport = Boolean(values, nameof(AllowPlaintextExport), true);
        MinimumKdfIterations = Integer(values, nameof(MinimumKdfIterations), 0, 10000000);
        EnforceEncryptionOptions = Boolean(values, nameof(EnforceEncryptionOptions), false);
        if (MinimumKdfIterations is > 0 and < 1000)
            throw Invalid(nameof(MinimumKdfIterations));
    }

    private static bool Boolean(IReadOnlyDictionary<string, object> values, string name, bool fallback)
    {
        if (!values.TryGetValue(name, out object value)) return fallback;
        return value switch { 0 => false, 1 => true, _ => throw Invalid(name) };
    }

    private static int Integer(IReadOnlyDictionary<string, object> values, string name, int min, int max)
    {
        if (!values.TryGetValue(name, out object value)) return 0;
        return value is int number && number >= min && number <= max ? number : throw Invalid(name);
    }

    private static InvalidOperationException Invalid(string name) =>
        new("Invalid machine security policy: " + name + ". Contact your administrator.");
}
