using System;
using System.Security;
using mRemoteNG.Security.SymmetricEncryption;

namespace mRemoteNG.Security.Policy;

public static class SecretStorePolicy
{
    public static void ValidateKey(SecureString key, SecurityPolicy policy)
    {
        if (policy.HasPasswordRequirements)
            MasterPasswordValidator.Validate(key?.ConvertToUnsecureString(), policy);
    }

    public static void ValidateEncryption(ICryptographyProvider provider, SecurityPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(policy);
        // Legacy providers expose enum defaults even though they use CBC and MD5.
        if ((policy.HasPasswordRequirements || policy.EncryptionEngine != null
                || policy.BlockCipherMode != null || policy.MinimumKdfIterations > 0)
                && provider is not AeadCryptographyProvider
            || policy.EncryptionEngine != null && provider.CipherEngine.ToString() != policy.EncryptionEngine
            || policy.BlockCipherMode != null && provider.CipherMode.ToString() != policy.BlockCipherMode
            || provider.KeyDerivationIterations < policy.MinimumKdfIterations)
            throw new InvalidOperationException("Encryption parameters do not meet machine policy.");
    }
}
