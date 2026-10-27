using System;
using System.Collections.Generic;
using mRemoteNG.Security.Policy;
using NUnit.Framework;

namespace mRemoteNGTests.Security;

[TestFixture]
public class SecurityPolicyTests
{
    [Test]
    public void MissingValuesPreserveUnmanagedBehavior()
    {
        var policy = new SecurityPolicy(new Dictionary<string, object>());
        Assert.That(policy.HasPasswordRequirements, Is.False);
        Assert.That(policy.AllowPasswordExport, Is.True);
        Assert.That(policy.AllowPlaintextExport, Is.True);
        Assert.That(policy.AllowPersistentUnlock, Is.True);
        Assert.That(policy.MinimumKdfIterations, Is.Zero);
        Assert.That(policy.EncryptionEngine, Is.Null);
    }

    [TestCase("RequireMasterPassword", "true")]
    [TestCase("RequireMasterPassword", 2)]
    [TestCase("AllowPersistentUnlock", -1)]
    [TestCase("MinimumMasterPasswordLength", 1025)]
    [TestCase("MinimumMasterPasswordLength", "16")]
    [TestCase("MinimumKdfIterations", 999)]
    [TestCase("MinimumKdfIterations", 10000001)]
    [TestCase("EncryptionEngine", "unknown")]
    [TestCase("BlockCipherMode", "CBC")]
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
    [TestCase("RequireFullEncryption", 1)]
    public void PasswordRelatedRequirementsCannotBeBypassedByOmittingRequireFlag(string key, int value)
    {
        var policy = new SecurityPolicy(new Dictionary<string, object> { [key] = value });
        Assert.That(policy.HasPasswordRequirements, Is.True);
    }
}
