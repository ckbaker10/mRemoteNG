using System;
using System.Security;

namespace mRemoteNG.Security.KeyManagement;

/// <summary>Owns a process-lifetime copy of an interactive key, with no persistence or default key.</summary>
public sealed class UnlockSession : IDisposable
{
    private readonly object _gate = new();
    private SecureString _key;

    public UnlockSession(SecureString key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length == 0) throw new ArgumentException("An unlock key is required.", nameof(key));
        _key = key.Copy();
        _key.MakeReadOnly();
    }

    /// <summary>The caller owns and must dispose the returned copy.</summary>
    public SecureString CopyKey()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_key == null, this);
            return _key.Copy();
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _key?.Dispose();
            _key = null;
        }
    }
}
