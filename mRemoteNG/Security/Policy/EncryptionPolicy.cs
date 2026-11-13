using System;
using System.Runtime.Versioning;
using System.Xml;
using mRemoteNG.Config.Serializers.ConnectionSerializers.Xml;
using mRemoteNG.Config.Settings.Registry;
using mRemoteNG.Security.SymmetricEncryption;

namespace mRemoteNG.Security.Policy;

/// <summary>The encryption that stored connections must meet.</summary>
public sealed record EncryptionRequirements(
    bool FullFileEncryption, bool DpapiForbidden, string Engine, string Mode, int MinimumKdfIterations)
{
    public static EncryptionRequirements None { get; } = new(false, false, null, null, 0);

    public bool RestrictsCipher => Engine != null || Mode != null || MinimumKdfIterations > 0;

    /// <summary>
    /// The policy KDF minimum always applies. The administrator values of the Security options
    /// only become requirements when the policy enforces them.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static EncryptionRequirements From(SecurityPolicy policy, OptRegistrySecurityPage administrator)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (!policy.EnforceEncryptionOptions || administrator == null)
            return None with { MinimumKdfIterations = policy.MinimumKdfIterations };

        int administratorKdf = administrator.EncryptionKeyDerivationIterations.IsValid
            ? administrator.EncryptionKeyDerivationIterations.Value : 0;
        return new EncryptionRequirements(
            administrator.EncryptCompleteConnectionsFile.IsSet && administrator.EncryptCompleteConnectionsFile.Value,
            administrator.UseDpapiProtection.IsSet && !administrator.UseDpapiProtection.Value,
            administrator.EncryptionEngine.IsValid ? administrator.EncryptionEngine.Value : null,
            administrator.EncryptionBlockCipherMode.IsValid ? administrator.EncryptionBlockCipherMode.Value : null,
            Math.Max(policy.MinimumKdfIterations, administratorKdf));
    }
}

[SupportedOSPlatform("windows")]
public static class EncryptionPolicy
{
    private const string DpapiKeyProtection = "Dpapi";
    private static readonly Lazy<OptRegistrySecurityPage> Administrator = new(() => new OptRegistrySecurityPage());

    public static EncryptionRequirements Current
    {
        get
        {
            SecurityPolicy policy = MachineSecurityPolicy.Current;
            return EncryptionRequirements.From(policy, policy.EnforceEncryptionOptions ? Administrator.Value : null);
        }
    }

    public static void Validate(ICryptographyProvider provider) => Validate(provider, Current);

    /// <summary>Refuses to write with a provider that does not meet the requirements.</summary>
    public static void Validate(ICryptographyProvider provider, EncryptionRequirements requirements)
    {
        ArgumentNullException.ThrowIfNull(provider);
        if (provider is DpapiCryptographyProvider)
        {
            // Engine, mode and iterations of a DPAPI provider are placeholders, not its protection.
            ConnectionProtectionPolicy.EnsureDpapiAllowed();
            if (requirements.DpapiForbidden)
                throw new InvalidOperationException("Encryption parameters do not meet machine policy.");
            return;
        }

        if (requirements.Engine != null && provider.CipherEngine.ToString() != requirements.Engine
            || requirements.Mode != null && provider.CipherMode.ToString() != requirements.Mode
            || provider.KeyDerivationIterations < requirements.MinimumKdfIterations)
            throw new InvalidOperationException("Encryption parameters do not meet machine policy.");
    }

    public static void ValidateLegacySql() => ValidateLegacySql(Current);

    public static void ValidateLegacySql(EncryptionRequirements requirements)
    {
        if (requirements.FullFileEncryption || requirements.RestrictsCipher)
            throw new InvalidOperationException("The legacy SQL connection format cannot meet the configured encryption policy.");
    }

    public static void ValidateConnectionsFile(XmlElement root, double confVersion) =>
        ValidateConnectionsFile(root, confVersion, Current);

    /// <summary>Refuses to open a connections file whose protection does not meet the requirements.</summary>
    public static void ValidateConnectionsFile(XmlElement root, double confVersion, EncryptionRequirements requirements)
    {
        ArgumentNullException.ThrowIfNull(root);
        if (requirements.FullFileEncryption && (confVersion < 2.6 || !root.GetAttributeAsBool("FullFileEncryption")))
            throw new InvalidOperationException("Machine policy requires full connection-file encryption. Migrate the file before enabling policy.");

        if (root.GetAttribute("KeyProtection") == DpapiKeyProtection)
        {
            // DPAPI files keep EncryptionEngine, BlockCipherMode and KdfIterations only for XML
            // shape compatibility. Judge them by their real protection instead.
            ConnectionProtectionPolicy.EnsureDpapiAllowed();
            if (requirements.DpapiForbidden)
                throw new InvalidOperationException("Connection-file encryption parameters do not meet machine policy.");
            return;
        }

        if (requirements.Engine != null && root.GetAttribute("EncryptionEngine") != requirements.Engine
            || requirements.Mode != null && root.GetAttribute("BlockCipherMode") != requirements.Mode
            || requirements.MinimumKdfIterations > 0 && root.GetAttributeAsInt("KdfIterations") < requirements.MinimumKdfIterations)
            throw new InvalidOperationException("Connection-file encryption parameters do not meet machine policy.");
    }
}
