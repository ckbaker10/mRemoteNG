using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using mRemoteNG.Security;
using mRemoteNG.Security.KeyManagement;
using mRemoteNG.Security.Policy;
using NUnit.Framework;

namespace mRemoteNGTests.Security
{
    [TestFixture]
    public class DpapiMasterKeyPolicyTests
    {
        [Test]
        public async Task ForbiddenProviderDoesNotReadOrDeleteExistingFile()
        {
            string path = Path.GetTempFileName();
            try
            {
                byte[] original = { 1, 2, 3, 4 };
                File.WriteAllBytes(path, original);
                var policy = new SecurityPolicy(new Dictionary<string, object> { ["AllowPersistentUnlock"] = 0 });
                var provider = new DpapiMasterKeyProvider(path, policy);

                Assert.That(provider.IsAvailable, Is.False);
                Assert.That(await provider.GetKeyAsync(), Is.Null);
                Assert.That(File.ReadAllBytes(path), Is.EqualTo(original));
            }
            finally { File.Delete(path); }
        }

        [Test]
        public void ForbiddenProviderCannotPersistKeyEvenWhenCalledDirectly()
        {
            string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".bin");
            var policy = new SecurityPolicy(new Dictionary<string, object> { ["AllowPersistentUnlock"] = 0 });
            var provider = new DpapiMasterKeyProvider(path, policy);
            using var key = "synthetic-key".ConvertToSecureString();

            Assert.Throws<InvalidOperationException>(() => provider.StoreKey(key));
            Assert.That(File.Exists(path), Is.False);
        }
    }
}
