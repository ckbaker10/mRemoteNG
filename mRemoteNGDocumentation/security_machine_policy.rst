Machine security policy
=======================

Administrators can set machine policy in the 64-bit registry view at
``HKEY_LOCAL_MACHINE\SOFTWARE\Policies\mRemoteNG\Security``. Restart mRemoteNG
after changes. The snapshot is read once per process; HKCU is never consulted.
Missing values retain unmanaged behavior. Invalid configured values block policy
consumers rather than silently falling back to user settings.

Boolean values use REG_DWORD 0 or 1. Integer values use REG_DWORD. String choices
use REG_SZ and are case sensitive. Policy values take precedence over the legacy
``SOFTWARE\mRemoteNG\Security\Options`` defaults.

The encryption settings consumer supports ``RequireFullEncryption`` (boolean),
``EncryptionEngine`` (AES, Serpent, Twofish), ``BlockCipherMode`` (GCM, EAX, CCM)
and ``MinimumKdfIterations`` (0 for no minimum, otherwise 1000 through 10000000).
Cipher combinations must also be supported by the existing crypto provider.

The typed contract additionally reserves ``RequireMasterPassword``,
``MinimumMasterPasswordLength`` (0 through 1024 UTF-16 code units),
``RequireUppercase``, ``RequireLowercase``, ``RequireDigit``,
``RequireSpecialCharacter``, ``AllowPersistentUnlock``, ``AllowPasswordExport``
and ``AllowPlaintextExport`` for their separate enforcement changes. These flags
alone are not an enforcement claim until the corresponding consumers are installed.
No password or unlock key belongs in the registry.

Master password requirements
----------------------------

``RequireMasterPassword=1`` rejects the public legacy default key and empty or
whitespace-only master passwords. Minimum length and character-class rules also
imply a personal master password. Length is measured in UTF-16 code units;
characters are not trimmed or normalized. A special character is neither a
letter, digit nor whitespace. Rules are checked at creation, loading and saving,
including direct XML compilation and SQL serialization.
The shared validator also checks the effective byte-oriented PKCS#5 password
used by existing connection formats. Unicode aliases of the public legacy key,
effective whitespace keys and character classes lost in byte conversion are
rejected. The legacy file encoding is not silently changed by policy enforcement.

Existing noncompliant files are rejected. Migrate them before enabling policy;
the application does not silently weaken policy for legacy data. Full encryption
or cipher/KDF requirements reject the legacy SQL format, which cannot provide
these guarantees. A failed XML serialization is propagated rather than returning
an empty document that could overwrite the original file.
