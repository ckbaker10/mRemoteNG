using System;
using System.Collections.Generic;

namespace mRemoteNG.Security.Policy;

/// <summary>A validated machine-policy snapshot. Missing values preserve unmanaged behavior.</summary>
public sealed class SecurityPolicy
{
    public bool RequireMasterPassword { get; }
    public bool AllowPersistentUnlock { get; }
    public int MinimumMasterPasswordLength { get; }
    public bool RequireUppercase { get; }
    public bool RequireLowercase { get; }
    public bool RequireDigit { get; }
    public bool RequireSpecialCharacter { get; }
    public bool RequireFullEncryption { get; }
    public bool AllowPasswordExport { get; }
    public bool AllowPlaintextExport { get; }
    public string EncryptionEngine { get; }
    public string BlockCipherMode { get; }
    public int MinimumKdfIterations { get; }

    public bool HasPasswordRequirements => RequireMasterPassword || MinimumMasterPasswordLength > 0
        || RequireUppercase || RequireLowercase || RequireDigit || RequireSpecialCharacter
        || RequireFullEncryption;

    public SecurityPolicy(IReadOnlyDictionary<string, object> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        RequireMasterPassword = Boolean(values, nameof(RequireMasterPassword), false);
        AllowPersistentUnlock = Boolean(values, nameof(AllowPersistentUnlock), true);
        MinimumMasterPasswordLength = Integer(values, nameof(MinimumMasterPasswordLength), 0, 1024);
        RequireUppercase = Boolean(values, nameof(RequireUppercase), false);
        RequireLowercase = Boolean(values, nameof(RequireLowercase), false);
        RequireDigit = Boolean(values, nameof(RequireDigit), false);
        RequireSpecialCharacter = Boolean(values, nameof(RequireSpecialCharacter), false);
        RequireFullEncryption = Boolean(values, nameof(RequireFullEncryption), false);
        AllowPasswordExport = Boolean(values, nameof(AllowPasswordExport), true);
        AllowPlaintextExport = Boolean(values, nameof(AllowPlaintextExport), true);
        EncryptionEngine = Choice(values, nameof(EncryptionEngine), "AES", "Serpent", "Twofish");
        BlockCipherMode = Choice(values, nameof(BlockCipherMode), "GCM", "EAX", "CCM");
        MinimumKdfIterations = Integer(values, nameof(MinimumKdfIterations), 0, 10000000);
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

    private static string Choice(IReadOnlyDictionary<string, object> values, string name, params string[] choices)
    {
        if (!values.TryGetValue(name, out object value)) return null;
        if (value is string text && Array.IndexOf(choices, text) >= 0) return text;
        throw Invalid(name);
    }

    private static InvalidOperationException Invalid(string name) =>
        new("Invalid machine security policy: " + name + ". Contact your administrator.");
}
