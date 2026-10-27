using System;
using mRemoteNG.Security;
using mRemoteNG.Security.KeyManagement;
using NUnit.Framework;

namespace mRemoteNGTests.Security;

[TestFixture]
public class UnlockSessionTests
{
    [Test]
    public void SessionOwnsItsKeyAndReturnsIndependentCopies()
    {
        var original = "synthetic-key".ConvertToSecureString();
        using var session = new UnlockSession(original);
        original.Dispose();
        using (var first = session.CopyKey())
            Assert.That(first.ConvertToUnsecureString(), Is.EqualTo("synthetic-key"));
        using var second = session.CopyKey();
        Assert.That(second.ConvertToUnsecureString(), Is.EqualTo("synthetic-key"));
    }

    [Test]
    public void DisposedSessionCannotProvideAKey()
    {
        using var key = "synthetic-key".ConvertToSecureString();
        var session = new UnlockSession(key);
        session.Dispose();
        session.Dispose();
        Assert.Throws<ObjectDisposedException>(() => session.CopyKey());
    }

    [Test]
    public void EmptyKeyCannotCreateAnUnlockedSession()
    {
        using var key = "".ConvertToSecureString();
        Assert.Throws<ArgumentException>(() => new UnlockSession(key));
    }
}
