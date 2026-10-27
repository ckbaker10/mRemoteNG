using System;
using System.Runtime.Versioning;

namespace mRemoteNG.Security.Policy;

[SupportedOSPlatform("windows")]
public static class EncryptionPolicy
{
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
