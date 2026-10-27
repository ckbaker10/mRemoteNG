using System;
using System.Collections.Generic;
using mRemoteNG.Security.Policy;
using NUnit.Framework;

namespace mRemoteNGTests.Security
{
    [TestFixture]
    public class MasterPasswordValidatorTests
    {
        private static SecurityPolicy Required() => new(new Dictionary<string, object>
        {
            ["RequireMasterPassword"] = 1, ["MinimumMasterPasswordLength"] = 12,
            ["RequireUppercase"] = 1, ["RequireLowercase"] = 1,
            ["RequireDigit"] = 1, ["RequireSpecialCharacter"] = 1
        });

        [TestCase(null)]
        [TestCase("")]
        [TestCase("mR3m")]
        [TestCase("Short1!")]
        [TestCase("alllowercase1!")]
        [TestCase("ALLUPPERCASE1!")]
        [TestCase("NoDigitsHere!!")]
        [TestCase("NoSymbolsHere1")]
        [TestCase("HasOnlySpace1 ")]
        public void RejectsWeakPasswords(string password)
        {
            Assert.Throws<InvalidOperationException>(() => MasterPasswordValidator.Validate(password, Required()));
        }

        [TestCase("ValidSynthetic1!")]
        [TestCase(" ÄpfelSynthetic1! ")]
        public void AcceptsCompliantPasswordWithoutModifyingIt(string password)
        {
            Assert.That(MasterPasswordValidator.GetError(password, Required()), Is.Null);
        }

        [Test]
        public void UnmanagedModeDoesNotImposeNewPasswordRequirements()
        {
            Assert.DoesNotThrow(() => MasterPasswordValidator.Validate("mR3m", new SecurityPolicy(new Dictionary<string, object>())));
        }

        [Test]
        public void UnsupportedLegacyKeyIsRejectedBeforeEncryption()
        {
            var derivation = new mRemoteNG.Security.KeyDerivation.Pkcs5S2KeyGenerator(256, 1000);
            var salt = new byte[16]; // Synthetic compatibility test, not a production salt.
            Assert.Throws<OverflowException>(() => derivation.DeriveKey("mŒ3m", salt));
            var policy = new SecurityPolicy(new Dictionary<string, object> { ["RequireMasterPassword"] = 1 });
            Assert.Throws<InvalidOperationException>(() => MasterPasswordValidator.Validate("mŒ3m", policy));
        }

        [Test]
        public void UnsupportedCharacterCannotSatisfyManagedUppercaseRule()
        {
            var policy = new SecurityPolicy(new Dictionary<string, object> { ["RequireUppercase"] = 1 });
            Assert.Throws<InvalidOperationException>(() => MasterPasswordValidator.Validate("Đsynthetic1!", policy));
        }

        [Test]
        public void UnsupportedCharacterIsRejectedUnderPersonalPasswordRequirement()
        {
            var policy = new SecurityPolicy(new Dictionary<string, object> { ["RequireMasterPassword"] = 1 });
            Assert.Throws<InvalidOperationException>(() => MasterPasswordValidator.Validate(new string('Ġ', 16), policy));
        }
    }
}
