using System;
using System.Collections.Generic;
using mRemoteNG.Security.Policy;
using NUnit.Framework;

namespace mRemoteNGTests.Security;

[TestFixture]
public class ExportPolicyTests
{
    [TestCase("AllowPlaintextExport", 0)]
    [TestCase("RequireFullEncryption", 1)]
    public void EitherProtectionBlocksPlaintextFormats(string key, int value)
    {
        var policy = new SecurityPolicy(new Dictionary<string, object> { [key] = value });
        Assert.That(ExportPolicy.AllowsPlaintext(policy), Is.False);
        Assert.Throws<InvalidOperationException>(() => ExportPolicy.ValidatePlaintext(policy));
    }

    [Test]
    public void UnmanagedModeRetainsPlaintextExport()
    {
        var policy = new SecurityPolicy(new Dictionary<string, object>());
        Assert.DoesNotThrow(() => ExportPolicy.ValidatePlaintext(policy));
    }
}
