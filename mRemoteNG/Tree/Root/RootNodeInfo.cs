using System;
using System.ComponentModel;
using mRemoteNG.Connection;
using mRemoteNG.Container;
using mRemoteNG.Tools;
using mRemoteNG.Resources.Language;
using System.Runtime.Versioning;

namespace mRemoteNG.Tree.Root
{
    [SupportedOSPlatform("windows")]
    [DefaultProperty("Name")]
    public class RootNodeInfo(RootNodeType rootType, string uniqueId) : ContainerInfo(uniqueId)
    {
        private string _name = Language.Connections;
        private string _customPassword = "";
        private bool _password;

        public RootNodeInfo(RootNodeType rootType)
            : this(rootType, Guid.NewGuid().ToString())
        {
        }

        #region Public Properties

        [LocalizedAttributes.LocalizedCategory(nameof(Language.Miscellaneous)),
         Browsable(true),
         LocalizedAttributes.LocalizedDefaultValue(nameof(Language.Connections)),
         LocalizedAttributes.LocalizedDisplayName(nameof(Language.Name)),
         LocalizedAttributes.LocalizedDescription(nameof(Language.PropertyDescriptionName))]
        public override string Name
        {
            get => _name;
            set => _name = value;
        }
        
        [LocalizedAttributes.LocalizedCategory(nameof(Language.Miscellaneous)),
         Browsable(true),
         LocalizedAttributes.LocalizedDisplayName(nameof(Language.PasswordProtect)),
         LocalizedAttributes.LocalizedDescription(nameof(Language.PropertyDescriptionPasswordProtect)),
         TypeConverter(typeof(MiscTools.YesNoTypeConverter))]
        public new bool Password
        {
            get => _password;
            set
            {
                if (!value && !string.IsNullOrEmpty(_customPassword)
                    && mRemoteNG.Security.Policy.MachineSecurityPolicy.Current.HasPasswordRequirements)
                    throw new InvalidOperationException("Machine policy requires master password protection.");
                _password = value;
            }
        }

        [Browsable(false)]
        public string PasswordString
        {
            get => (Password && !string.IsNullOrEmpty(_customPassword)) ? _customPassword : DefaultPassword;
            set
            {
                mRemoteNG.Security.Policy.MasterPasswordValidator.Validate(value,
                    mRemoteNG.Security.Policy.MachineSecurityPolicy.Current);
                _customPassword = value;
                Password = !string.IsNullOrEmpty(value) && _customPassword != DefaultPassword;
            }
        }

        [Browsable(false)] public string DefaultPassword { get; } = mRemoteNG.Security.Policy.MasterPasswordValidator.LegacyDefaultPassword;

        /// <summary>Commits a password change only when the supplied atomic save succeeds.</summary>
        public void ChangePasswordAndSave(string password, Action save)
        {
            ArgumentNullException.ThrowIfNull(save);
            string previousPassword = _customPassword;
            bool previousProtection = _password;
            try
            {
                PasswordString = password;
                save();
            }
            catch
            {
                // Restore the exact prior state, including an unprotected legacy
                // root. Revalidating it could mask the original write failure.
                _customPassword = previousPassword;
                _password = previousProtection;
                throw;
            }
        }

        [Browsable(false)] public RootNodeType Type { get; set; } = rootType;

        public override TreeNodeType GetTreeNodeType()
        {
            return Type == RootNodeType.Connection
                ? TreeNodeType.Root
                : TreeNodeType.PuttyRoot;
        }
        #endregion
    }
}