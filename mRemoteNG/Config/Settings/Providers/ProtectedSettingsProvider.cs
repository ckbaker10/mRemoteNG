using System;
using System.Collections.Generic;
using System.Configuration;
using System.Runtime.Versioning;
using System.Security;
using mRemoteNG.Security.Policy;

namespace mRemoteNG.Config.Settings.Providers;

/// <summary>Protects persisted secret strings without changing their in-memory application representation.</summary>
[SupportedOSPlatform("windows")]
public sealed class ProtectedSettingsProvider : ChooseProvider
{
    private readonly Func<SecurityPolicy> _policy;
    private readonly Func<bool> _unlocked;
    private readonly Func<SecureString> _copyKey;
    private readonly Func<bool> _migration;

    public ProtectedSettingsProvider()
    {
        _policy = () => MachineSecurityPolicy.Current;
        _unlocked = () => SettingsSecretSession.IsUnlocked;
        _copyKey = SettingsSecretSession.CopyKey;
        _migration = () => SettingsSecretSession.MigrationRequested;
    }

    public ProtectedSettingsProvider(SecurityPolicy policy, Func<SecureString> copyKey, bool migration = false)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(copyKey);
        _policy = () => policy;
        _unlocked = () => true;
        _copyKey = copyKey;
        _migration = () => migration;
    }

    private static readonly HashSet<string> Secrets = new(StringComparer.Ordinal)
    {
        "DefaultPassword", "SQLPass", "UpdateProxyAuthPass", "AdminRolePassword",
        "ConDefaultPassword", "ConDefaultRDGatewayPassword", "ConDefaultVNCProxyPassword",
        "ConDefaultRDGatewayAccessToken"
    };

    private static bool IsSecret(SettingsProperty property) => property.PropertyType == typeof(string) && Secrets.Contains(property.Name);
    private static string Purpose(SettingsContext context, string name) => context["GroupName"] + "." + name;

    public override SettingsPropertyValueCollection GetPropertyValues(SettingsContext context, SettingsPropertyCollection properties)
    {
        var values = base.GetPropertyValues(context, properties);
        SecurityPolicy policy = _policy();
        foreach (SettingsPropertyValue value in values)
        {
            if (!IsSecret(value.Property) || value.SerializedValue is not string stored || string.IsNullOrEmpty(stored)) continue;
            if (stored.StartsWith(ProtectedSettingsValue.Prefix, StringComparison.Ordinal))
            {
                using SecureString key = _copyKey();
                value.SerializedValue = ProtectedSettingsValue.Decrypt(stored, key, policy,
                    _migration(), Purpose(context, value.Name));
                value.IsDirty = false;
            }
            else if (policy.HasPasswordRequirements && !_migration())
                throw new InvalidOperationException("Legacy sensitive settings require an explicit --migrate-settings run before use.");
        }
        return values;
    }

    public override void SetPropertyValues(SettingsContext context, SettingsPropertyValueCollection values)
    {
        SecurityPolicy policy = _policy();
        if (!policy.HasPasswordRequirements && !_unlocked())
        {
            base.SetPropertyValues(context, values);
            return;
        }
        using SecureString key = _copyKey();
        var protectedValues = new SettingsPropertyValueCollection();
        foreach (SettingsPropertyValue original in values)
        {
            object serialized = original.SerializedValue;
            if (IsSecret(original.Property) && serialized is string clear && !string.IsNullOrEmpty(clear))
                serialized = ProtectedSettingsValue.Encrypt(clear, key, policy, Purpose(context, original.Name));
            protectedValues.Add(new SettingsPropertyValue(original.Property)
            {
                SerializedValue = serialized,
                IsDirty = original.IsDirty
            });
        }
        // Never replace the application's live values with ciphertext.
        base.SetPropertyValues(context, protectedValues);
    }
}
