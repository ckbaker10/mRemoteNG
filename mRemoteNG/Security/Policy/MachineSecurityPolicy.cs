using System;
using System.Collections.Generic;
using System.Runtime.Versioning;
using System.Threading;
using Microsoft.Win32;
using mRemoteNG.App.Info;

namespace mRemoteNG.Security.Policy;

/// <summary>Loads machine policy once per process. No user-writable fallback is used.</summary>
[SupportedOSPlatform("windows")]
public static class MachineSecurityPolicy
{
    /// <summary>The existing Security area; option values live in its <c>Options</c> subkey.</summary>
    public const string RegistryPath = WindowsRegistryInfo.Security;
    private static readonly Lazy<SecurityPolicy> Snapshot = new(Read);
    private static SecurityPolicy _testPolicy;

    public static SecurityPolicy Current => Volatile.Read(ref _testPolicy) ?? Snapshot.Value;

    /// <summary>Replaces the machine policy for tests until the returned scope is disposed.</summary>
    internal static IDisposable OverrideForTesting(SecurityPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        SecurityPolicy previous = Interlocked.Exchange(ref _testPolicy, policy);
        return new TestPolicyScope(previous);
    }

    private static SecurityPolicy Read()
    {
        try
        {
            using RegistryKey machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using RegistryKey key = machine.OpenSubKey(RegistryPath, writable: false);
            return ReadFrom(key);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException
                                   or System.IO.IOException)
        {
            // Do not log values or silently continue with weaker user settings.
            throw new InvalidOperationException("Cannot read machine security policy. Contact your administrator.");
        }
    }

    /// <summary>Parses an already-open policy source; Current always opens the fixed HKLM path.</summary>
    public static SecurityPolicy ReadFrom(RegistryKey key)
    {
        var values = new Dictionary<string, object>(StringComparer.Ordinal);
        if (key != null)
            foreach (string name in key.GetValueNames())
            {
                string policyName = FindPolicyName(name);
                if (policyName == null) continue;
                if (key.GetValueKind(name) != RegistryValueKind.DWord)
                    throw new InvalidOperationException("Invalid registry type for machine security policy: " + policyName + ".");
                values[policyName] = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            }
        return new SecurityPolicy(values);
    }

    private static string FindPolicyName(string valueName)
    {
        foreach (string policyName in SecurityPolicy.ValueNames)
            if (string.Equals(policyName, valueName, StringComparison.OrdinalIgnoreCase))
                return policyName;
        return null;
    }

    private sealed class TestPolicyScope(SecurityPolicy previous) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
                Volatile.Write(ref _testPolicy, previous);
        }
    }
}
