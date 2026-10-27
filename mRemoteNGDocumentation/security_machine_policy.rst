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

Additional policy values are ``RequireMasterPassword``,
``MinimumMasterPasswordLength`` (0 through 1024 UTF-16 code units),
``RequireUppercase``, ``RequireLowercase``, ``RequireDigit``,
``RequireSpecialCharacter``, ``AllowPersistentUnlock``, ``AllowPasswordExport``
and ``AllowPlaintextExport``. Their enforcement is described below.
No password or unlock key belongs in the registry.

Master password requirements
----------------------------

``RequireMasterPassword=1`` rejects the public legacy default key and empty or
whitespace-only master passwords. Minimum length and character-class rules also
imply a personal master password. Length is measured in UTF-16 code units;
characters are not trimmed or normalized. A special character is neither a
letter, digit nor whitespace. Rules are checked at creation, loading and saving,
including direct XML compilation and SQL serialization.

Existing noncompliant files are rejected. Migrate them before enabling policy;
the application does not silently weaken policy for legacy data. Full encryption
or cipher/KDF requirements reject the legacy SQL format, which cannot provide
these guarantees. A failed XML serialization is propagated rather than returning
an empty document that could overwrite the original file.

With ``AllowPersistentUnlock=0``, DPAPI providers cannot read or write cached
master passwords, including direct provider calls. The settings initializer
skips providers capable of persistent unlock and uses the password provider.
Existing cached files are left untouched and must be handled explicitly during
migration. The legacy noninteractive options repository refuses to open under
this policy until an interactive store is supplied; it never opens a plaintext
replacement database as a fallback.

Sensitive settings storage
--------------------------

Managed mode protects persisted default connection, gateway, VNC proxy, SQL,
update proxy and administrator setting strings with versioned authenticated
envelopes. The existing cryptography provider is used with independent random
salts; each envelope is bound to its settings group and property name. The new
format represents master-key text as full UTF-8 bytes before key derivation.
The settings master password is kept only in a process-lifetime unlock session.
A persisted encrypted verifier checks input but cannot automatically unlock it.
It is separate from each connection file's password; changing a connection
password does not silently rotate or invalidate the settings key.

Run ``mRemoteNG.exe --migrate-settings`` explicitly to migrate legacy settings or
raise encryption parameters. This prompts for the settings master password,
rewrites the supported settings groups and exits without opening the normal UI.
A failed migration can be repeated with the same settings key; legacy backups
are neither deleted nor declared protected by this operation. Existing weak
connection files must be migrated separately before policy activation. Settings
master-password rotation is not performed by this migration command.

Normal managed startup refuses legacy sensitive setting values. Unsupported
experimental SQLite options storage is rejected under managed secret-storage
policy rather than pretending its ordinary SQLite backend provides encryption.
SQLite connection-profile payloads already use field-level encryption; configured
cryptographic requirements are validated for their provider. All newly generated
connection and portable settings files use atomic replacement, and write errors
are propagated. Unmanaged users keep legacy settings behavior until they opt into
protected settings migration.

Export policy
-------------

``AllowPasswordExport=0`` caps the export filter in addition to existing credential
restrictions. ``AllowPlaintextExport=0`` or ``RequireFullEncryption=1`` blocks CSV
serialization, including direct serializer calls. XML export uses the selected
root's key and honors full encryption; denied operations do not write output.
