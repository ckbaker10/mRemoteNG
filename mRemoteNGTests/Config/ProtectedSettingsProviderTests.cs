using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Security;
using mRemoteNG.Config.Settings.Providers;
using mRemoteNG.Security;
using mRemoteNG.Security.Policy;
using NUnit.Framework;

namespace mRemoteNGTests.Config;

[TestFixture]
public class ProtectedSettingsProviderTests
{
    [Test]
    public void ProviderPersistsCiphertextWhileKeepingLiveValuesUnchanged()
    {
        using SecureString key = "Synthetic-Master-Key-1!".ConvertToSecureString();
        var policy = new SecurityPolicy(new Dictionary<string, object> { ["RequireMasterPassword"] = 1 });
        var provider = new ProtectedSettingsProvider(policy, key.Copy);
        provider.Initialize("ProtectedSettingsProvider", new NameValueCollection());
        var raw = new ChooseProvider();
        raw.Initialize("RawSettingsProvider", new NameValueCollection());
        var context = new SettingsContext { ["GroupName"] = "mRemoteNGTests." + Guid.NewGuid().ToString("N") };
        var property = new SettingsProperty("SQLPass")
        {
            PropertyType = typeof(string), SerializeAs = SettingsSerializeAs.String,
            Provider = provider, DefaultValue = ""
        };
        property.Attributes.Add(typeof(UserScopedSettingAttribute), new UserScopedSettingAttribute());
        var properties = new SettingsPropertyCollection { property };
        var original = raw.GetPropertyValues(context, properties);
        const string secret = "synthetic-sensitive-setting";
        var live = new SettingsPropertyValue(property) { PropertyValue = secret, IsDirty = true };
        var values = new SettingsPropertyValueCollection { live };
        try
        {
            provider.SetPropertyValues(context, values);
            Assert.That(live.PropertyValue, Is.EqualTo(secret));
            string stored = (string)raw.GetPropertyValues(context, properties)["SQLPass"].SerializedValue;
            Assert.That(stored, Does.StartWith(ProtectedSettingsValue.Prefix));
            Assert.That(stored, Does.Not.Contain(secret));
            Assert.That(provider.GetPropertyValues(context, properties)["SQLPass"].PropertyValue, Is.EqualTo(secret));
        }
        finally
        {
            // Restore only this test's setting; portable Reset would remove other settings.
            original["SQLPass"].IsDirty = true;
            raw.SetPropertyValues(context, original);
        }
    }

    [Test]
    public void LegacyValuesRequireExplicitMigrationAndCanThenBeReadNormally()
    {
        using SecureString key = "Synthetic-Master-Key-1!".ConvertToSecureString();
        var policy = new SecurityPolicy(new Dictionary<string, object> { ["RequireMasterPassword"] = 1 });
        var provider = new ProtectedSettingsProvider(policy, key.Copy);
        var migration = new ProtectedSettingsProvider(policy, key.Copy, migration: true);
        var raw = new ChooseProvider();
        provider.Initialize("ProtectedSettingsProvider", new NameValueCollection());
        migration.Initialize("MigrationSettingsProvider", new NameValueCollection());
        raw.Initialize("RawSettingsProvider", new NameValueCollection());
        var context = new SettingsContext { ["GroupName"] = "mRemoteNGTests." + Guid.NewGuid().ToString("N") };
        var property = new SettingsProperty("SQLPass")
        {
            PropertyType = typeof(string), SerializeAs = SettingsSerializeAs.String,
            Provider = provider, DefaultValue = ""
        };
        property.Attributes.Add(typeof(UserScopedSettingAttribute), new UserScopedSettingAttribute());
        var properties = new SettingsPropertyCollection { property };
        var original = raw.GetPropertyValues(context, properties);
        const string legacy = "synthetic-legacy-setting";
        try
        {
            raw.SetPropertyValues(context, new SettingsPropertyValueCollection
            {
                new SettingsPropertyValue(property) { PropertyValue = legacy, IsDirty = true }
            });
            Assert.Throws<InvalidOperationException>(() => provider.GetPropertyValues(context, properties));
            var values = migration.GetPropertyValues(context, properties);
            Assert.That(values["SQLPass"].PropertyValue, Is.EqualTo(legacy));
            values["SQLPass"].IsDirty = true;
            migration.SetPropertyValues(context, values);
            Assert.That(provider.GetPropertyValues(context, properties)["SQLPass"].PropertyValue, Is.EqualTo(legacy));
        }
        finally
        {
            original["SQLPass"].IsDirty = true;
            raw.SetPropertyValues(context, original);
        }
    }
}
