using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using mRemoteNG.Security;
using mRemoteNG.Security.Policy;
using NUnit.Framework;

namespace mRemoteNGTests.Security
{
    [TestFixture]
    public class GroupPolicyTemplateTests
    {
        private static readonly XNamespace Ns = "http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions";
        private static string PoliciesPath => Path.Combine(AppContext.BaseDirectory, "Policies");

        [Test]
        public void TemplatesCoverExactlyTheTypedMachinePolicyContract()
        {
            var document = XDocument.Load(Path.Combine(PoliciesPath, "mRemoteNG.Security.admx"));
            var policies = document.Descendants(Ns + "policy").ToArray();
            var names = policies.Select(p => (string)p.Attribute("name")).ToArray();
            var contract = typeof(SecurityPolicy).GetProperties().Where(p => p.Name != nameof(SecurityPolicy.HasPasswordRequirements)).ToArray();
            Assert.That(names, Is.Unique);
            Assert.That(names, Is.EquivalentTo(contract.Select(p => p.Name)));
            foreach (var policy in policies)
            {
                string name = (string)policy.Attribute("name");
                Assert.That((string)policy.Attribute("key"), Is.EqualTo(MachineSecurityPolicy.RegistryPath));
                Assert.That((string)policy.Attribute("class"), Is.EqualTo("Machine"));
                var type = contract.Single(p => p.Name == name).PropertyType;
                if (type == typeof(bool))
                {
                    Assert.That((string)policy.Attribute("valueName"), Is.EqualTo(name));
                    Assert.That((string)policy.Element(Ns + "enabledValue")?.Element(Ns + "decimal")?.Attribute("value"), Is.EqualTo("1"));
                    Assert.That((string)policy.Element(Ns + "disabledValue")?.Element(Ns + "decimal")?.Attribute("value"), Is.EqualTo("0"));
                }
                else
                {
                    var element = policy.Element(Ns + "elements")!.Elements().Single();
                    Assert.That((string)element.Attribute("valueName"), Is.EqualTo(name));
                    Assert.That(element.Name.LocalName, Is.EqualTo(type == typeof(int) ? "decimal" : "enum"));
                }
            }
        }

        [TestCase("en-US")]
        [TestCase("de-DE")]
        public void EveryReferencedStringAndPresentationIsPresent(string language)
        {
            var definition = XDocument.Load(Path.Combine(PoliciesPath, "mRemoteNG.Security.admx"));
            var resources = XDocument.Load(Path.Combine(PoliciesPath, language, "mRemoteNG.Security.adml"));
            var strings = resources.Descendants(Ns + "string").Select(e => (string)e.Attribute("id")).Where(id => id != null).ToArray();
            var presentations = resources.Descendants(Ns + "presentation").Select(e => (string)e.Attribute("id")).ToArray();
            Assert.That(strings, Is.Unique);
            Assert.That(presentations, Is.Unique);
            foreach (Match reference in Regex.Matches(definition.ToString(), @"\$\((string|presentation)\.([^)]+)\)"))
                Assert.That(reference.Groups[1].Value == "string" ? strings : presentations,
                    Does.Contain(reference.Groups[2].Value));
            foreach (var presentation in resources.Descendants(Ns + "presentation"))
            {
                string id = (string)presentation.Attribute("id");
                var policy = definition.Descendants(Ns + "policy").Single(p => (string)p.Attribute("name") == id);
                string elementId = (string)policy.Element(Ns + "elements")!.Elements().Single().Attribute("id");
                Assert.That((string)presentation.Elements().Single().Attribute("refId"), Is.EqualTo(elementId));
            }
        }

        [TestCase("EncryptionEngine", typeof(BlockCipherEngines))]
        [TestCase("BlockCipherMode", typeof(BlockCipherModes))]
        public void CipherChoicesMatchSupportedProviderEnums(string policyName, Type enumType)
        {
            var definition = XDocument.Load(Path.Combine(PoliciesPath, "mRemoteNG.Security.admx"));
            var policy = definition.Descendants(Ns + "policy").Single(p => (string)p.Attribute("name") == policyName);
            Assert.That(policy.Descendants(Ns + "value").Elements(Ns + "string").Select(p => p.Value),
                Is.EquivalentTo(Enum.GetNames(enumType)));
        }
    }
}
