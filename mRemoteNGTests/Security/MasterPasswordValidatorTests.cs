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
    }
}
