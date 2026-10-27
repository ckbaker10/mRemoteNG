using System;
using Microsoft.Win32;
using mRemoteNG.Security.Policy;
using NUnit.Framework;

namespace mRemoteNGTests.Security;

[TestFixture]
[Platform("Win")]
public class MachineSecurityPolicyRegistryTests
{
    private string _path;
    private RegistryKey _key;

    [SetUp]
    public void CreateIsolatedSource()
    {
        _path = @"Software\mRemoteNGTests\" + Guid.NewGuid().ToString("N");
        _key = Registry.CurrentUser.CreateSubKey(_path);
    }

    [TearDown]
    public void RemoveOnlyThisTestsSource()
    {
        _key?.Dispose();
        Registry.CurrentUser.DeleteSubKeyTree(_path, throwOnMissingSubKey: false);
    }

    [Test]
    public void RegistryNamesAreCaseInsensitiveAndSnapshotIsIndependent()
    {
        _key.SetValue("requiremasterpassword", 1, RegistryValueKind.DWord);
        var snapshot = MachineSecurityPolicy.ReadFrom(_key);
        _key.SetValue("RequireMasterPassword", 0, RegistryValueKind.DWord);
        Assert.That(snapshot.RequireMasterPassword, Is.True);
        Assert.That(MachineSecurityPolicy.ReadFrom(_key).RequireMasterPassword, Is.False);
    }

    [Test]
    public void StringCannotImpersonateDword()
    {
        _key.SetValue("RequireMasterPassword", "1", RegistryValueKind.String);
        Assert.Throws<InvalidOperationException>(() => MachineSecurityPolicy.ReadFrom(_key));
    }

    [Test]
    public void ExpandStringCannotImpersonateString()
    {
        _key.SetValue("EncryptionEngine", "AES", RegistryValueKind.ExpandString);
        Assert.Throws<InvalidOperationException>(() => MachineSecurityPolicy.ReadFrom(_key));
    }

    [Test]
    public void QwordCannotImpersonateDword()
    {
        _key.SetValue("MinimumMasterPasswordLength", 16L, RegistryValueKind.QWord);
        Assert.Throws<InvalidOperationException>(() => MachineSecurityPolicy.ReadFrom(_key));
    }
}
