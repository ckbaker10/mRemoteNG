using System.Collections.Generic;
using mRemoteNG.Security.Policy;
using NUnit.Framework;

namespace mRemoteNGTests.Security
{
    [TestFixture]
    public class MachineSecurityPolicyOverrideTests
    {
        [Test]
        public void TestsRunWithUnmanagedMachinePolicyByDefault()
        {
            Assert.That(MachineSecurityPolicy.Current.HasPasswordRequirements, Is.False);
            Assert.That(MachineSecurityPolicy.Current.RequireFullEncryption, Is.False);
        }

        [Test]
        public void OverrideAppliesUntilDisposed()
        {
            var managed = new SecurityPolicy(new Dictionary<string, object> { ["RequireFullEncryption"] = 1 });
            SecurityPolicy before = MachineSecurityPolicy.Current;

            using (MachineSecurityPolicy.OverrideForTesting(managed))
                Assert.That(MachineSecurityPolicy.Current, Is.SameAs(managed));

            Assert.That(MachineSecurityPolicy.Current, Is.SameAs(before));
        }
    }
}
