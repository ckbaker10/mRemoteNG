using System;
using System.Security;
using System.Text;
using System.Text.Json;
using mRemoteNG.Security.Factories;

namespace mRemoteNG.Security.Policy;

/// <summary>Versioned setting envelopes using the application's existing authenticated encryption provider.</summary>
public static class ProtectedSettingsValue
{
    public const string Prefix = "mrng-settings-v1:";
    private sealed record Envelope(string Engine, string Mode, int KdfIterations, string Ciphertext);
    private sealed record Payload(string Purpose, string Value);

    public static string Encrypt(string value, SecureString key, SecurityPolicy policy, string purpose = "")
    {
        var engine = Enum.Parse<BlockCipherEngines>(policy.EncryptionEngine ?? "AES");
        var mode = Enum.Parse<BlockCipherModes>(policy.BlockCipherMode ?? "GCM");
        var provider = new CryptoProviderFactory(engine, mode).Build();
        provider.KeyDerivationIterations = Math.Max(100000, policy.MinimumKdfIterations);
        using SecureString encodedKey = EncodeKey(key);
        var envelope = new Envelope(engine.ToString(), mode.ToString(), provider.KeyDerivationIterations,
            provider.Encrypt(JsonSerializer.Serialize(new Payload(purpose, value)), encodedKey));
        return Prefix + Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(envelope)));
    }

    public static string Decrypt(string value, SecureString key, SecurityPolicy policy, bool migration = false,
        string purpose = "")
    {
        if (value == null || !value.StartsWith(Prefix, StringComparison.Ordinal))
            throw new InvalidOperationException("The setting is not a protected settings envelope.");
        Envelope envelope;
        try
        {
            envelope = JsonSerializer.Deserialize<Envelope>(Convert.FromBase64String(value.Substring(Prefix.Length)));
        }
        catch (Exception ex) when (ex is JsonException or FormatException)
        {
            throw new InvalidOperationException("The protected setting is invalid.");
        }
        if (envelope == null || !Enum.TryParse(envelope.Engine, out BlockCipherEngines engine)
            || !Enum.IsDefined(engine) || !Enum.TryParse(envelope.Mode, out BlockCipherModes mode)
            || !Enum.IsDefined(mode) || envelope.KdfIterations < 1000 || envelope.KdfIterations > 10000000
            || string.IsNullOrEmpty(envelope.Ciphertext))
            throw new InvalidOperationException("The protected setting has invalid encryption parameters.");
        if (!migration && (policy.EncryptionEngine != null && policy.EncryptionEngine != envelope.Engine
            || policy.BlockCipherMode != null && policy.BlockCipherMode != envelope.Mode
            || envelope.KdfIterations < policy.MinimumKdfIterations))
            throw new InvalidOperationException("The protected setting requires explicit policy migration.");
        var provider = new CryptoProviderFactory(engine, mode).Build();
        provider.KeyDerivationIterations = envelope.KdfIterations;
        using SecureString encodedKey = EncodeKey(key);
        Payload payload = JsonSerializer.Deserialize<Payload>(provider.Decrypt(envelope.Ciphertext, encodedKey));
        if (payload == null || payload.Purpose != purpose)
            throw new InvalidOperationException("The protected setting belongs to a different purpose.");
        return payload.Value;
    }

    // The legacy provider accepts byte-oriented PKCS#5 passwords. This new format
    // uses an ASCII representation of the full UTF-8 key, avoiding Unicode truncation.
    private static SecureString EncodeKey(SecureString key) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(key.ConvertToUnsecureString())).ConvertToSecureString();
}
