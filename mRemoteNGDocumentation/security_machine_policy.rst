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
Registry value names are case insensitive. Registry kinds are checked strictly;
REG_EXPAND_SZ and REG_QWORD are not accepted as substitutes for REG_SZ and REG_DWORD.

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
