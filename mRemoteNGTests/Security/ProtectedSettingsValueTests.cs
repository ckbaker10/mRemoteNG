using System;
using System.Collections.Generic;
using mRemoteNG.Security;
using mRemoteNG.Security.Policy;
using NUnit.Framework;

namespace mRemoteNGTests.Security
{
    [TestFixture]
    public class ProtectedSettingsValueTests
    {
        private static readonly SecurityPolicy Policy = new(new Dictionary<string, object>());

        [Test]
        public void RoundTripUsesFreshSaltAndDoesNotContainPlaintext()
        {
            using var key = "Synthetic-Master-Key-1!".ConvertToSecureString();
            const string secret = "synthetic-password-do-not-persist";
            string first = ProtectedSettingsValue.Encrypt(secret, key, Policy);
            string second = ProtectedSettingsValue.Encrypt(secret, key, Policy);
            Assert.That(first, Is.Not.EqualTo(second));
            Assert.That(first, Does.Not.Contain(secret));
            Assert.That(ProtectedSettingsValue.Decrypt(first, key, Policy), Is.EqualTo(secret));
        }

        [Test]
        public void WrongKeyCannotDecrypt()
        {
            using var key = "Synthetic-Master-Key-1!".ConvertToSecureString();
            using var wrong = "Different-Master-Key-2!".ConvertToSecureString();
            string encrypted = ProtectedSettingsValue.Encrypt("synthetic", key, Policy);
            Assert.Throws<EncryptionException>(() => ProtectedSettingsValue.Decrypt(encrypted, wrong, Policy));
        }

        [Test]
        public void EnvelopeCannotBeMovedToAnotherSetting()
        {
            using var key = "Synthetic-Master-Key-1!".ConvertToSecureString();
            string encrypted = ProtectedSettingsValue.Encrypt("synthetic", key, Policy, "group.first");
            Assert.Throws<InvalidOperationException>(() => ProtectedSettingsValue.Decrypt(encrypted, key, Policy, purpose: "group.second"));
        }

        [Test]
        public void UnicodeKeysWithTheSameLowBytesAreDistinct()
        {
            using var key = "Synthetic-ä-1!".ConvertToSecureString();
            using var other = "Synthetic-Ǥ-1!".ConvertToSecureString();
            string encrypted = ProtectedSettingsValue.Encrypt("synthetic", key, Policy);
            Assert.Throws<EncryptionException>(() => ProtectedSettingsValue.Decrypt(encrypted, other, Policy));
        }

        [TestCase("plaintext")]
        [TestCase("mrng-settings-v1:not-base64")]
        [TestCase("mrng-settings-v1:bnVsbA==")]
        public void MalformedEnvelopeIsRejected(string value)
        {
            using var key = "Synthetic-Master-Key-1!".ConvertToSecureString();
            Assert.Throws<InvalidOperationException>(() => ProtectedSettingsValue.Decrypt(value, key, Policy));
        }

        [Test]
        public void RaisingPolicyRequiresExplicitMigrationAndNewEnvelope()
        {
            using var key = "Synthetic-Master-Key-1!".ConvertToSecureString();
            string previous = ProtectedSettingsValue.Encrypt("synthetic", key, Policy);
            var raised = new SecurityPolicy(new Dictionary<string, object> { ["MinimumKdfIterations"] = 150000 });
            Assert.Throws<InvalidOperationException>(() => ProtectedSettingsValue.Decrypt(previous, key, raised));
            string clear = ProtectedSettingsValue.Decrypt(previous, key, raised, migration: true);
            string migrated = ProtectedSettingsValue.Encrypt(clear, key, raised);
            Assert.That(ProtectedSettingsValue.Decrypt(migrated, key, raised), Is.EqualTo("synthetic"));
        }
    }
}
