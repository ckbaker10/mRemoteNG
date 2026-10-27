using System;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Security;
using System.Windows.Forms;
using mRemoteNG.App.Info;
using mRemoteNG.Config.DataProviders;
using mRemoteNG.Security.KeyManagement;
using mRemoteNG.UI.Forms;

namespace mRemoteNG.Security.Policy;

[SupportedOSPlatform("windows")]
public static class SettingsSecretSession
{
    private const string VerifierPurpose = "mRemoteNG settings unlock verifier";
    private static UnlockSession _session;
    public static bool IsUnlocked => _session != null;
    public static bool MigrationRequested { get; private set; }
    private static string VerifierPath => Path.Combine(SettingsFileInfo.SettingsPath, "settings-unlock.verifier");

    public static bool Initialize(string[] args)
    {
        MigrationRequested = args.Contains("--migrate-settings", StringComparer.Ordinal);
        SecurityPolicy policy = MachineSecurityPolicy.Current;
        if (!policy.HasPasswordRequirements && !File.Exists(VerifierPath) && !MigrationRequested) return true;
        bool existing = File.Exists(VerifierPath);
        using var dialog = new FrmPassword("Settings master password", newPasswordMode: !existing, useTheme: false);
        var result = dialog.GetKey();
        if (!result.Any()) return false;
        using SecureString key = result.First();
        MasterPasswordValidator.Validate(key.ConvertToUnsecureString(), policy);
        if (existing && ProtectedSettingsValue.Decrypt(File.ReadAllText(VerifierPath), key, policy,
                migration: MigrationRequested, purpose: VerifierPurpose) != VerifierPurpose)
            throw new InvalidOperationException("The settings master password is incorrect.");
        if (!existing)
            AtomicFile.WriteAllText(VerifierPath, ProtectedSettingsValue.Encrypt(VerifierPurpose, key, policy, VerifierPurpose));
        _session = new UnlockSession(key);
        AppDomain.CurrentDomain.ProcessExit += (_, _) => _session?.Dispose();
        return true;
    }

    public static SecureString CopyKey()
    {
        if (_session == null)
            throw new InvalidOperationException("Protected settings require an interactive unlock. Restart the application.");
        return _session.CopyKey();
    }

    public static void Migrate()
    {
        if (!MigrationRequested) throw new InvalidOperationException("An explicit settings migration is required.");
        ApplicationSettingsBase[] groups = { Properties.Settings.Default, Properties.OptionsCredentialsPage.Default,
            Properties.OptionsDBsPage.Default, Properties.OptionsUpdatesPage.Default, Properties.OptionsRbac.Default };
        foreach (var group in groups)
        {
            foreach (SettingsProperty property in group.Properties) _ = group[property.Name];
            foreach (SettingsPropertyValue value in group.PropertyValues) value.IsDirty = true;
            group.Save();
        }
        using SecureString key = CopyKey();
        AtomicFile.WriteAllText(VerifierPath, ProtectedSettingsValue.Encrypt(VerifierPurpose, key,
            MachineSecurityPolicy.Current, VerifierPurpose));
    }
}
