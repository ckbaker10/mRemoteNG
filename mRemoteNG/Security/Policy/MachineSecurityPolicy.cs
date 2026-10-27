using System;
using System.Collections.Generic;
using System.Runtime.Versioning;
using System.Reflection;
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
        var values = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        if (key != null)
            foreach (string name in key.GetValueNames())
            {
                var property = typeof(SecurityPolicy).GetProperty(name,
                    BindingFlags.Instance | BindingFlags.Public | BindingFlags.IgnoreCase);
                if (property == null || property.Name == nameof(SecurityPolicy.HasPasswordRequirements)) continue;
                var expected = property.PropertyType == typeof(string) ? RegistryValueKind.String : RegistryValueKind.DWord;
                if (key.GetValueKind(name) != expected)
                    throw new InvalidOperationException("Invalid registry type for machine security policy: " + property.Name + ".");
                values[property.Name] = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            }
        return new SecurityPolicy(values);
    }
}
