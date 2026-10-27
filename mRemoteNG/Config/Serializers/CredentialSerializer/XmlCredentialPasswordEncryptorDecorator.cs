using System;
using System.Collections.Generic;
using System.Security;
using System.Xml.Linq;
using mRemoteNG.Credential;
using mRemoteNG.Security;
using mRemoteNG.Security.Policy;

namespace mRemoteNG.Config.Serializers.CredentialSerializer
{
    public class XmlCredentialPasswordEncryptorDecorator : ISecureSerializer<IEnumerable<ICredentialRecord>, string>
    {
        private readonly ISerializer<IEnumerable<ICredentialRecord>, string> _baseSerializer;
        private readonly ICryptographyProvider _cryptographyProvider;
        private readonly SecurityPolicy _policy;

        public XmlCredentialPasswordEncryptorDecorator(ICryptographyProvider cryptographyProvider, ISerializer<IEnumerable<ICredentialRecord>, string> baseSerializer,
            SecurityPolicy policy = null)
        {
            if (baseSerializer == null)
                throw new ArgumentNullException(nameof(baseSerializer));
            if (cryptographyProvider == null)
                throw new ArgumentNullException(nameof(cryptographyProvider));

            _baseSerializer = baseSerializer;
            _cryptographyProvider = cryptographyProvider;
            _policy = policy ?? MachineSecurityPolicy.Current;
        }


        public string Serialize(IEnumerable<ICredentialRecord> credentialRecords, SecureString key)
        {
            if (credentialRecords == null)
                throw new ArgumentNullException(nameof(credentialRecords));

            SecretStorePolicy.ValidateKey(key, _policy);
            SecretStorePolicy.ValidateEncryption(_cryptographyProvider, _policy);
            string baseReturn = _baseSerializer.Serialize(credentialRecords);
            string encryptedReturn = EncryptPasswordAttributes(baseReturn, key);
            return encryptedReturn;
        }

        private string EncryptPasswordAttributes(string xml, SecureString encryptionKey)
        {
            XDocument xdoc = XDocument.Parse(xml);
            SetEncryptionAttributes(xdoc, encryptionKey);
            foreach (XElement element in xdoc.Descendants())
            {
                XAttribute passwordAttribute = element.Attribute("Password");
                if (passwordAttribute == null) continue;
                string encryptedPassword = _cryptographyProvider.Encrypt(passwordAttribute.Value, encryptionKey);
                passwordAttribute.Value = encryptedPassword;
            }

            return xdoc.Declaration + Environment.NewLine + xdoc;
        }

        private void SetEncryptionAttributes(XDocument xdoc, SecureString encryptionKey)
        {
            xdoc.Root?.SetAttributeValue("EncryptionEngine", _cryptographyProvider.CipherEngine);
            xdoc.Root?.SetAttributeValue("BlockCipherMode", _cryptographyProvider.CipherMode);
            xdoc.Root?.SetAttributeValue("KdfIterations", _cryptographyProvider.KeyDerivationIterations);
            xdoc.Root?.SetAttributeValue("Auth", _cryptographyProvider.Encrypt(RandomGenerator.RandomString(20), encryptionKey));
        }
    }
}