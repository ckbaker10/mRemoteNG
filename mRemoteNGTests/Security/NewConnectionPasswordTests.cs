using System;
using System.Collections.Generic;
using System.Security;
using mRemoteNG.Security;
using mRemoteNG.Security.Policy;
using mRemoteNG.Tools;
using NUnit.Framework;

namespace mRemoteNGTests.Security
{
    public class NewConnectionPasswordTests
    {
        private static readonly SecurityPolicy Managed = new(new Dictionary<string, object>
        {
            ["RequireMasterPassword"] = 1, ["MinimumMasterPasswordLength"] = 16
        });

        [Test]
        public void UnmanagedCreationDoesNotPrompt()
        {
            var policy = new SecurityPolicy(new Dictionary<string, object>());
            Assert.That(NewConnectionPassword.Request(policy, () => throw new Exception("Unexpected prompt")), Is.Null);
        }

        [Test]
        public void CancelStopsCreation()
        {
            Assert.Throws<OperationCanceledException>(() =>
                NewConnectionPassword.Request(Managed, () => Optional<SecureString>.Empty));
        }

        [TestCase("mR3m")]
        [TestCase("short")]
        public void InvalidPasswordCannotReachFirstSave(string value)
        {
            Assert.Throws<InvalidOperationException>(() => NewConnectionPassword.Request(Managed,
                () => new Optional<SecureString>(value.ConvertToSecureString())));
        }

        [Test]
        public void ValidPasswordIsSelectedAndPromptKeyDisposed()
        {
            var key = "Synthetic-Master-Key-123!".ConvertToSecureString();
            string password = NewConnectionPassword.Request(Managed, () => new Optional<SecureString>(key));
            Assert.That(password, Is.EqualTo("Synthetic-Master-Key-123!"));
            Assert.Throws<ObjectDisposedException>(() => { _ = key.Length; });
        }
    }
}
