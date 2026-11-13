using System.Collections.Generic;
using System.Threading;
using mRemoteNG.Config.Serializers.ConnectionSerializers.Xml;
using mRemoteNG.Connection;
using mRemoteNG.Security;
using mRemoteNG.Security.Factories;
using mRemoteNG.Security.Policy;
using mRemoteNG.Security.SymmetricEncryption;
using mRemoteNG.Tools;
using mRemoteNG.Tree;
using mRemoteNG.Tree.Root;
using NUnit.Framework;

namespace mRemoteNGTests.Security;

[TestFixture]
[NonParallelizable]
public class ConnectionProtectionPolicyTests
{
    private bool _useDpapi;
    private int _kdfIterations;

    [SetUp]
    public void RememberOptions()
    {
        _useDpapi = mRemoteNG.Properties.OptionsSecurityPage.Default.UseDpapiProtection;
        _kdfIterations = mRemoteNG.Properties.OptionsSecurityPage.Default.EncryptionKeyDerivationIterations;
    }

    [TearDown]
    public void RestoreOptions()
    {
        mRemoteNG.Properties.OptionsSecurityPage.Default.UseDpapiProtection = _useDpapi;
        mRemoteNG.Properties.OptionsSecurityPage.Default.EncryptionKeyDerivationIterations = _kdfIterations;
    }

    private static System.IDisposable Policy(string key, int value) =>
        MachineSecurityPolicy.OverrideForTesting(new SecurityPolicy(new Dictionary<string, object> { [key] = value }));

    [TestCase("RequireMasterPassword", 1)]
    [TestCase("AllowPersistentUnlock", 0)]
    public void ApplyTurnsDpapiProtectionOffWhenPolicyForbidsIt(string key, int value)
    {
        mRemoteNG.Properties.OptionsSecurityPage.Default.UseDpapiProtection = true;
        using (Policy(key, value))
            ConnectionProtectionPolicy.Apply();
        Assert.That(mRemoteNG.Properties.OptionsSecurityPage.Default.UseDpapiProtection, Is.False);
    }

    [Test]
    public void ApplyKeepsDpapiProtectionWithoutPolicy()
    {
        mRemoteNG.Properties.OptionsSecurityPage.Default.UseDpapiProtection = true;
        ConnectionProtectionPolicy.Apply();
        Assert.That(mRemoteNG.Properties.OptionsSecurityPage.Default.UseDpapiProtection, Is.True);
    }

    [Test]
    public void FactoryRefusesDpapiAgainstPolicyInsteadOfSavingWithoutPassword()
    {
        mRemoteNG.Properties.OptionsSecurityPage.Default.UseDpapiProtection = true;
        using (Policy("RequireMasterPassword", 1))
            Assert.Throws<EncryptionException>(() => new ConnectionsFileCryptoProviderFactory().Build());
    }

    [Test]
    public void KdfIterationsAreRaisedToThePolicyMinimum()
    {
        mRemoteNG.Properties.OptionsSecurityPage.Default.EncryptionKeyDerivationIterations = 10000;
        using (Policy("MinimumKdfIterations", 600000))
            Assert.That(new CryptoProviderFactoryFromSettings().Build().KeyDerivationIterations, Is.EqualTo(600000));
    }

    [Test]
    public void HigherConfiguredKdfIterationsAreKept()
    {
        mRemoteNG.Properties.OptionsSecurityPage.Default.EncryptionKeyDerivationIterations = 700000;
        using (Policy("MinimumKdfIterations", 600000))
            Assert.That(new CryptoProviderFactoryFromSettings().Build().KeyDerivationIterations, Is.EqualTo(700000));
    }

    [Test]
    [Platform("Win")]
    [Apartment(ApartmentState.STA)]
    public void DpapiProtectedFileIsNotOpenedAgainstPolicy()
    {
        var model = new ConnectionTreeModel();
        var root = new RootNodeInfo(RootNodeType.Connection);
        root.AddChild(new ConnectionInfo { Name = "policy-test", Hostname = "test-host.example" });
        model.AddRootNode(root);
        string xml = new XmlConnectionSerializerFactory().Build(new DpapiCryptographyProvider(), model).Serialize(root);

        using (Policy("AllowPersistentUnlock", 0))
        {
            var deserializer = new XmlConnectionsDeserializer(() => new Optional<System.Security.SecureString>());
            Assert.Throws<EncryptionException>(() => deserializer.Deserialize(xml));
        }
    }
}
