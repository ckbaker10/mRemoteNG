using System;
using System.Collections.Generic;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace mRemoteNG.Security.Policy;

/// <summary>Loads machine policy once per process. No user-writable fallback is used.</summary>
[SupportedOSPlatform("windows")]
public static class MachineSecurityPolicy
{
    public const string RegistryPath = @"SOFTWARE\Policies\mRemoteNG\Security";
    private static readonly Lazy<SecurityPolicy> Snapshot = new(Read);
    public static SecurityPolicy Current => Snapshot.Value;

    private static SecurityPolicy Read()
    {
        try
        {
            using RegistryKey machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using RegistryKey key = machine.OpenSubKey(RegistryPath, writable: false);
            var values = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            if (key != null)
                foreach (string name in key.GetValueNames())
                    values[name] = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            return new SecurityPolicy(values);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException
                                   or System.IO.IOException)
        {
            // Do not log values or silently continue with weaker user settings.
            throw new InvalidOperationException("Cannot read machine security policy. Contact your administrator.");
        }
    }
}
