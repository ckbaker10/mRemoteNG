using System;
using System.Collections.Generic;
using System.Threading;
using System.Xml;
using Microsoft.Win32;
using mRemoteNG.Config.Settings.Registry;
using mRemoteNG.Security;
using mRemoteNG.Security.Factories;
using mRemoteNG.Security.Policy;
using mRemoteNG.Security.SymmetricEncryption;
using mRemoteNG.Tools.WindowsRegistry;
using NUnit.Framework;

namespace mRemoteNGTests.Security;

[TestFixture]
public class EncryptionPolicyTests
{
    private static readonly EncryptionRequirements Serpent = EncryptionRequirements.None with { Engine = "Serpent" };

    private static XmlElement Root(string attributes)
    {
        var document = new XmlDocument();
        document.LoadXml("<Connections " + attributes + " />");
        return document.DocumentElement;
    }

    private const string DpapiRoot =
        "EncryptionEngine=\"AES\" BlockCipherMode=\"GCM\" KdfIterations=\"0\" FullFileEncryption=\"false\" KeyProtection=\"Dpapi\"";

    [Test]
    public void DpapiFileIsNotJudgedByItsPlaceholderCipherAttributes()
    {
        var requirements = Serpent with { Mode = "EAX", MinimumKdfIterations = 600000 };
        Assert.DoesNotThrow(() => EncryptionPolicy.ValidateConnectionsFile(Root(DpapiRoot), 2.9, requirements));
    }

    [Test]
    public void DpapiFileIsRefusedWhenTheAdministratorTurnedDpapiOff()
    {
        var requirements = EncryptionRequirements.None with { DpapiForbidden = true };
        Assert.Throws<InvalidOperationException>(() => EncryptionPolicy.ValidateConnectionsFile(Root(DpapiRoot), 2.9, requirements));
    }

    [Test]
    public void DpapiFileMustStillMeetFullFileEncryption()
    {
        var requirements = EncryptionRequirements.None with { FullFileEncryption = true };
        Assert.Throws<InvalidOperationException>(() => EncryptionPolicy.ValidateConnectionsFile(Root(DpapiRoot), 2.9, requirements));
    }

    [TestCase("EncryptionEngine=\"AES\" BlockCipherMode=\"GCM\" KdfIterations=\"600000\"")]
    [TestCase("EncryptionEngine=\"Serpent\" BlockCipherMode=\"GCM\" KdfIterations=\"1000\"")]
    public void PasswordFileBelowRequirementsIsRefused(string attributes)
    {
        var requirements = Serpent with { MinimumKdfIterations = 600000 };
        Assert.Throws<InvalidOperationException>(() => EncryptionPolicy.ValidateConnectionsFile(Root(attributes), 2.9, requirements));
    }

    [Test]
    public void PasswordFileMeetingRequirementsIsAccepted()
    {
        var requirements = Serpent with { MinimumKdfIterations = 600000 };
        var root = Root("EncryptionEngine=\"Serpent\" BlockCipherMode=\"GCM\" KdfIterations=\"700000\"");
        Assert.DoesNotThrow(() => EncryptionPolicy.ValidateConnectionsFile(root, 2.9, requirements));
    }

    [Test]
    public void DpapiProviderIsNotJudgedByItsPlaceholderCipher()
    {
        var requirements = Serpent with { MinimumKdfIterations = 600000 };
        Assert.DoesNotThrow(() => EncryptionPolicy.Validate(new DpapiCryptographyProvider(), requirements));
    }

    [Test]
    public void PasswordProviderBelowTheKdfMinimumIsRefused()
    {
        ICryptographyProvider provider = new CryptoProviderFactory(BlockCipherEngines.AES, BlockCipherModes.GCM).Build();
        provider.KeyDerivationIterations = 1000;
        var requirements = EncryptionRequirements.None with { MinimumKdfIterations = 600000 };
        Assert.Throws<InvalidOperationException>(() => EncryptionPolicy.Validate(provider, requirements));
    }

    [Test]
    public void LegacySqlIsOnlyRefusedWhenItCannotMeetRequirements()
    {
        Assert.DoesNotThrow(() => EncryptionPolicy.ValidateLegacySql(EncryptionRequirements.None));
        Assert.Throws<InvalidOperationException>(() => EncryptionPolicy.ValidateLegacySql(Serpent));
    }

    [TestFixture]
    [Platform("Win")]
    [Apartment(ApartmentState.STA)] // OptRegistrySecurityPage constructs a WinForms control.
    public class AdministratorValues
    {
        private string _path;
        private bool _encryptComplete;
        private bool _useDpapi;
        private BlockCipherEngines _engine;

        [SetUp]
        public void CreateIsolatedOptions()
        {
            var options = mRemoteNG.Properties.OptionsSecurityPage.Default;
            _encryptComplete = options.EncryptCompleteConnectionsFile;
            _useDpapi = options.UseDpapiProtection;
            _engine = options.EncryptionEngine;
            _path = @"Software\mRemoteNGTests\" + Guid.NewGuid().ToString("N");
            WinRegistryEntry<bool>.New(RegistryHive.CurrentUser, _path, "EncryptCompleteConnectionsFile", true).Write();
            WinRegistryEntry<bool>.New(RegistryHive.CurrentUser, _path, "UseDpapiProtection", false).Write();
            WinRegistryEntry<string>.New(RegistryHive.CurrentUser, _path, "EncryptionEngine", "Serpent").Write();
        }

        [TearDown]
        public void RemoveIsolatedOptions()
        {
            Registry.CurrentUser.DeleteSubKeyTree(_path, throwOnMissingSubKey: false);
            // The page applies the registry values to the shared options; put them back.
            var options = mRemoteNG.Properties.OptionsSecurityPage.Default;
            options.EncryptCompleteConnectionsFile = _encryptComplete;
            options.UseDpapiProtection = _useDpapi;
            options.EncryptionEngine = _engine;
        }

        private static SecurityPolicy Policy(Dictionary<string, object> values) => new(values);

        [Test]
        public void AdministratorValuesOnlyPresetOptionsWithoutEnforcement()
        {
            var policy = Policy(new Dictionary<string, object> { ["MinimumKdfIterations"] = 600000 });
            var requirements = EncryptionRequirements.From(policy, new OptRegistrySecurityPage(RegistryHive.CurrentUser, _path));
            Assert.That(requirements, Is.EqualTo(EncryptionRequirements.None with { MinimumKdfIterations = 600000 }));
        }

        [Test]
        public void EnforcementMakesAdministratorValuesBinding()
        {
            var policy = Policy(new Dictionary<string, object> { ["EnforceEncryptionOptions"] = 1 });
            var requirements = EncryptionRequirements.From(policy, new OptRegistrySecurityPage(RegistryHive.CurrentUser, _path));
            Assert.That(requirements.FullFileEncryption, Is.True);
            Assert.That(requirements.DpapiForbidden, Is.True);
            Assert.That(requirements.Engine, Is.EqualTo("Serpent"));
        }
    }
}
