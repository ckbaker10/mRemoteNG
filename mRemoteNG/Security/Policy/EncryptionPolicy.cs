using System;
using System.Runtime.Versioning;

namespace mRemoteNG.Security.Policy;

[SupportedOSPlatform("windows")]
public static class EncryptionPolicy
{
    public static void Validate(ICryptographyProvider provider)
    {
        SecurityPolicy policy = MachineSecurityPolicy.Current;
        if (policy.EncryptionEngine != null && provider.CipherEngine.ToString() != policy.EncryptionEngine
            || policy.BlockCipherMode != null && provider.CipherMode.ToString() != policy.BlockCipherMode
            || provider.KeyDerivationIterations < policy.MinimumKdfIterations)
            throw new InvalidOperationException("Encryption parameters do not meet machine policy.");
    }

    public static void ValidateLegacySql()
    {
        SecurityPolicy policy = MachineSecurityPolicy.Current;
        if (policy.RequireFullEncryption || policy.EncryptionEngine != null || policy.BlockCipherMode != null
            || policy.MinimumKdfIterations > 0)
            throw new InvalidOperationException("The legacy SQL connection format cannot meet the configured encryption policy.");
    }

    public static void Apply()
    {
        SecurityPolicy policy = MachineSecurityPolicy.Current;
        var options = Properties.OptionsSecurityPage.Default;
        if (policy.RequireFullEncryption) options.EncryptCompleteConnectionsFile = true;
        if (policy.EncryptionEngine != null)
            options.EncryptionEngine = Enum.Parse<BlockCipherEngines>(policy.EncryptionEngine);
        if (policy.BlockCipherMode != null)
            options.EncryptionBlockCipherMode = Enum.Parse<BlockCipherModes>(policy.BlockCipherMode);
        options.EncryptionKeyDerivationIterations = Math.Max(options.EncryptionKeyDerivationIterations,
            policy.MinimumKdfIterations);
    }
}
