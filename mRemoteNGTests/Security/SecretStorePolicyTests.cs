using System;
using System.Collections.Generic;
using System.Security;
using mRemoteNG.Security;
using mRemoteNG.Security.Factories;
using mRemoteNG.Security.Policy;
using NUnit.Framework;

namespace mRemoteNGTests.Security
{
    public class SecretStorePolicyTests
    {
        private static SecurityPolicy Policy(string name, object value) =>
            new(new Dictionary<string, object> { [name] = value });

        [TestCase("mR3m")]
        [TestCase("")]
        [TestCase(null)]
        public void ManagedSecretStoresRejectDefaultOrMissingKeys(string password)
        {
            using var key = password?.ConvertToSecureString();
            Assert.Throws<InvalidOperationException>(() =>
                SecretStorePolicy.ValidateKey(key, Policy("RequireMasterPassword", 1)));
        }

        [Test]
        public void CipherMetadataCannotDisguiseLegacyImplementation()
        {
            Assert.Throws<InvalidOperationException>(() =>
                SecretStorePolicy.ValidateEncryption(new LegacyMetadataProvider(), Policy("BlockCipherMode", "GCM")));
        }

        [Test]
        public void PersistedKdfDowngradeIsRejectedAfterLoadingMetadata()
        {
            var provider = new CryptoProviderFactory(BlockCipherEngines.AES, BlockCipherModes.GCM).Build();
            var policy = Policy("MinimumKdfIterations", 100000);
            provider.KeyDerivationIterations = 100000;
            Assert.DoesNotThrow(() => SecretStorePolicy.ValidateEncryption(provider, policy));
            provider.KeyDerivationIterations = 1000;
            Assert.Throws<InvalidOperationException>(() => SecretStorePolicy.ValidateEncryption(provider, policy));
        }

        [Test]
        public void UnmanagedLegacyStoresRemainReadable()
        {
            var policy = new SecurityPolicy(new Dictionary<string, object>());
            Assert.DoesNotThrow(() => SecretStorePolicy.ValidateKey(null, policy));
            Assert.DoesNotThrow(() => SecretStorePolicy.ValidateEncryption(new LegacyMetadataProvider(), policy));
        }

        private sealed class LegacyMetadataProvider : ICryptographyProvider
        {
            public int BlockSizeInBytes => 16;
            public BlockCipherEngines CipherEngine => BlockCipherEngines.AES;
            public BlockCipherModes CipherMode => BlockCipherModes.GCM;
            public int KeyDerivationIterations { get; set; }
            public string Encrypt(string value, SecureString key) => throw new NotSupportedException();
            public string Decrypt(string value, SecureString key) => throw new NotSupportedException();
        }
    }
}
