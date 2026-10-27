using System.Configuration;
using mRemoteNG.Config.Settings.Providers;

namespace mRemoteNG.Properties
{
    [SettingsProvider(typeof(ProtectedSettingsProvider))]
    internal sealed partial class Settings { }

    [SettingsProvider(typeof(ProtectedSettingsProvider))]
    internal sealed partial class OptionsCredentialsPage { }

    [SettingsProvider(typeof(ProtectedSettingsProvider))]
    internal sealed partial class OptionsDBsPage { }

    [SettingsProvider(typeof(ProtectedSettingsProvider))]
    internal sealed partial class OptionsUpdatesPage { }

    [SettingsProvider(typeof(ProtectedSettingsProvider))]
    internal sealed partial class OptionsRbac { }
}
