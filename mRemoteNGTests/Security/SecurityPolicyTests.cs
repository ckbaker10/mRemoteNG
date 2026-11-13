using System;
using System.Collections.Generic;
using mRemoteNG.Security.Policy;
using NUnit.Framework;

namespace mRemoteNGTests.Security
{
    [TestFixture]
    public class SecurityPolicyTests
    {
        [Test]
        public void MissingValuesPreserveUnmanagedBehavior()
        {
            var policy = new SecurityPolicy(new Dictionary<string, object>());
            Assert.That(policy.HasPasswordRequirements, Is.False);
            Assert.That(policy.AllowPlaintextExport, Is.True);
            Assert.That(policy.AllowPersistentUnlock, Is.True);
            Assert.That(policy.MinimumKdfIterations, Is.Zero);
            Assert.That(policy.AllowsDpapiConnectionProtection, Is.True);
            Assert.That(policy.EnforceEncryptionOptions, Is.False);
        }

        [TestCase("RequireMasterPassword", "true")]
        [TestCase("RequireMasterPassword", 2)]
        [TestCase("AllowPersistentUnlock", -1)]
        [TestCase("MinimumMasterPasswordLength", 1025)]
        [TestCase("MinimumMasterPasswordLength", "16")]
        [TestCase("MinimumKdfIterations", 999)]
        [TestCase("MinimumKdfIterations", 10000001)]
        [TestCase("AllowPlaintextExport", "0")]
        [TestCase("EnforceEncryptionOptions", 2)]
        public void InvalidPolicyFailsClosed(string key, object value)
        {
            Assert.Throws<InvalidOperationException>(() => new SecurityPolicy(new Dictionary<string, object> { [key] = value }));
        }

        [Test]
        public void PolicyCopiesValuesInsteadOfKeepingMutableSource()
        {
            var source = new Dictionary<string, object> { ["RequireMasterPassword"] = 1 };
            var policy = new SecurityPolicy(source);
            source["RequireMasterPassword"] = 0;
            Assert.That(policy.RequireMasterPassword, Is.True);
        }

        [TestCase("MinimumMasterPasswordLength", 16)]
        [TestCase("RequireUppercase", 1)]
        [TestCase("RequireSpecialCharacter", 1)]
        public void PasswordRelatedRequirementsCannotBeBypassedByOmittingRequireFlag(string key, int value)
        {
            var policy = new SecurityPolicy(new Dictionary<string, object> { [key] = value });
            Assert.That(policy.HasPasswordRequirements, Is.True);
        }

        [TestCase("RequireMasterPassword", 1)]
        [TestCase("MinimumMasterPasswordLength", 12)]
        [TestCase("RequireDigit", 1)]
        [TestCase("AllowPersistentUnlock", 0)]
        public void DpapiConnectionProtectionIsExcludedByPasswordAndUnlockPolicy(string key, int value)
        {
            var policy = new SecurityPolicy(new Dictionary<string, object> { [key] = value });
            Assert.That(policy.AllowsDpapiConnectionProtection, Is.False);
        }

        [TestCase("AllowPlaintextExport", 0)]
        [TestCase("MinimumKdfIterations", 600000)]
        public void UnrelatedPolicyKeepsDpapiConnectionProtectionAvailable(string key, int value)
        {
            var policy = new SecurityPolicy(new Dictionary<string, object> { [key] = value });
            Assert.That(policy.AllowsDpapiConnectionProtection, Is.True);
        }
    }
}
