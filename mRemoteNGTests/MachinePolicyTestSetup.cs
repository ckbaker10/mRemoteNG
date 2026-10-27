using System;
using System.Collections.Generic;
using mRemoteNG.Security.Policy;
using NUnit.Framework;

/// <summary>
/// Runs every test against an unmanaged machine policy so that results do not depend on
/// the HKLM policy of the build machine. Policy tests set their own values explicitly.
/// </summary>
[SetUpFixture]
public class MachinePolicyTestSetup
{
    private IDisposable _policy;

    [OneTimeSetUp]
    public void UseUnmanagedMachinePolicy()
    {
        _policy = MachineSecurityPolicy.OverrideForTesting(new SecurityPolicy(new Dictionary<string, object>()));
    }

    [OneTimeTearDown]
    public void RestoreMachinePolicy()
    {
        _policy?.Dispose();
    }
}
