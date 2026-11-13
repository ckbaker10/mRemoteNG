using System;

namespace mRemoteNG.Security.Policy;

/// <summary>Applies machine policy to the protection of the connections file.</summary>
public static class ConnectionProtectionPolicy
{
    public static bool DpapiAllowed => MachineSecurityPolicy.Current.AllowsDpapiConnectionProtection;

    /// <summary>Turns DPAPI protection off when policy forbids it; policy wins over option values.</summary>
    public static void Apply()
    {
        if (!DpapiAllowed)
            Properties.OptionsSecurityPage.Default.UseDpapiProtection = false;
    }

    /// <summary>Refuses to open or create a DPAPI-protected connections file against policy.</summary>
    public static void EnsureDpapiAllowed()
    {
        if (!DpapiAllowed)
            throw new EncryptionException(
                "Machine security policy does not allow connections files protected with the Windows account (DPAPI). Contact your administrator.");
    }

    /// <summary>The KDF iteration count to use: the configured value, raised to the policy minimum.</summary>
    public static int EffectiveKdfIterations(int configured) =>
        Math.Max(configured, MachineSecurityPolicy.Current.MinimumKdfIterations);
}
