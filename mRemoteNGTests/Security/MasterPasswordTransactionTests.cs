using System;
using System.IO;
using System.Linq;
using System.Xml.Linq;
using mRemoteNG.Config.Connections;
using mRemoteNG.Connection;
using mRemoteNG.Security;
using mRemoteNG.Security.Factories;
using mRemoteNG.Tree;
using mRemoteNG.Tree.Root;
using NUnit.Framework;

namespace mRemoteNGTests.Security;

public class MasterPasswordTransactionTests
{
    private const string OldPassword = "Synthetic-Old-Master-Key-123!";
    private const string NewPassword = "Synthetic-New-Master-Key-456!";

    [Test]
    public void RealSaveFailurePreservesTheFileAndKeyBeforeSuccessfulRekey()
    {
        if (!OperatingSystem.IsWindows()) Assert.Ignore("Windows replacement sharing semantics are required.");
        string directory = Path.Combine(Path.GetTempPath(), "mrng-rekey-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "connections.xml");
        var root = new RootNodeInfo(RootNodeType.Connection) { PasswordString = OldPassword };
        root.AddChild(new ConnectionInfo { Name = "Synthetic connection", Password = "synthetic-connection-password" });
        var model = new ConnectionTreeModel();
        model.AddRootNode(root);
        var saver = new XmlConnectionsSaver(path, new SaveFilter());
        try
        {
            saver.Save(model);
            string original = File.ReadAllText(path);
            using (var held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                Assert.Throws<IOException>(() => root.ChangePasswordAndSave(NewPassword, () => saver.Save(model)));
                Assert.That(root.PasswordString, Is.EqualTo(OldPassword));
                Assert.That(File.ReadAllText(path), Is.EqualTo(original));
            }
            root.ChangePasswordAndSave(NewPassword, () => saver.Save(model));
            string updated = File.ReadAllText(path);
            Assert.That(updated, Is.Not.EqualTo(original));
            Assert.That(updated, Does.Not.Contain(OldPassword).And.Not.Contain(NewPassword).And.Not.Contain("synthetic-connection-password"));
            XElement document = XDocument.Parse(updated).Root;
            var provider = new CryptoProviderFactoryFromSettings().Build();
            using var newKey = NewPassword.ConvertToSecureString();
            using var oldKey = OldPassword.ConvertToSecureString();
            string verifier = document.Attribute("Protected").Value;
            Assert.That(provider.Decrypt(verifier, newKey), Is.EqualTo("ThisIsProtected"));
            Assert.Catch(() => provider.Decrypt(verifier, oldKey));
            if (document.Attribute("FullFileEncryption").Value == "true")
                document = XElement.Parse("<Nodes>" + provider.Decrypt(document.Value, newKey) + "</Nodes>");
            string encryptedSecret = document.Descendants().Single(node => node.Name.LocalName == "Node").Attribute("Password").Value;
            Assert.That(provider.Decrypt(encryptedSecret, newKey), Is.EqualTo("synthetic-connection-password"));
        }
        finally { Directory.Delete(directory, true); }
    }

    [Test]
    public void SuccessfulSaveUsesAndRetainsTheNewPassword()
    {
        var root = new RootNodeInfo(RootNodeType.Connection) { PasswordString = OldPassword };
        int saves = 0;
        root.ChangePasswordAndSave(NewPassword, () =>
        {
            Assert.That(root.PasswordString, Is.EqualTo(NewPassword));
            saves++;
        });
        Assert.That(saves, Is.EqualTo(1));
        Assert.That(root.PasswordString, Is.EqualTo(NewPassword));
        Assert.That(root.Password, Is.True);
    }

    [Test]
    public void FailedSaveRestoresTheOldPasswordAndPropagatesTheOriginalFailure()
    {
        var root = new RootNodeInfo(RootNodeType.Connection) { PasswordString = OldPassword };
        var failure = new IOException("Synthetic write failure");
        Assert.That(Assert.Throws<IOException>(() => root.ChangePasswordAndSave(NewPassword, () => throw failure)),
            Is.SameAs(failure));
        Assert.That(root.PasswordString, Is.EqualTo(OldPassword));
        Assert.That(root.Password, Is.True);
    }

    [Test]
    public void FailedFirstProtectionRestoresTheExactUnprotectedState()
    {
        var root = new RootNodeInfo(RootNodeType.Connection);
        Assert.Throws<IOException>(() => root.ChangePasswordAndSave(NewPassword, () => throw new IOException("Synthetic")));
        Assert.That(root.Password, Is.False);
        Assert.That(root.PasswordString, Is.EqualTo(root.DefaultPassword));
    }

    [Test]
    public void MissingSaveCallbackCannotChangeThePassword()
    {
        var root = new RootNodeInfo(RootNodeType.Connection) { PasswordString = OldPassword };
        Assert.Throws<ArgumentNullException>(() => root.ChangePasswordAndSave(NewPassword, null));
        Assert.That(root.PasswordString, Is.EqualTo(OldPassword));
    }
}
