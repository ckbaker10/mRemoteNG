Machine security policy
=======================

Administrators can set machine policy as ``REG_DWORD`` values directly in
``HKEY_LOCAL_MACHINE\SOFTWARE\mRemoteNG\Security`` (64-bit registry view).
The option values of the Security page stay in the ``Options`` subkey below it.
Restart mRemoteNG after changes. The snapshot is read once per process; HKCU is
never consulted. Missing values retain unmanaged behavior. Invalid configured
values block policy consumers rather than silently falling back to user settings.

Boolean values use 0 or 1. Registry value names are case insensitive. Registry
kinds are checked strictly; ``REG_SZ`` and ``REG_QWORD`` are not accepted as
substitutes for ``REG_DWORD``. Values not listed here are ignored.

Cipher engine, block cipher mode, full-file encryption and Windows account
(DPAPI) protection are set with the existing Security options values in
``SOFTWARE\mRemoteNG\Security\Options``; this policy does not duplicate them.
By default those values only preset and lock the options. ``EnforceEncryptionOptions``
(boolean) reserves making them binding for existing files and storage formats as well.

``MinimumKdfIterations`` (0 for no minimum, otherwise 1000 through 10000000)
raises the key derivation iterations used for new encryption to at least this
value, whatever the option value is.

DPAPI protection opens the connections file for the Windows account without a
password. It is therefore not allowed when ``AllowPersistentUnlock`` is 0 or any
master password requirement is set: the DPAPI option is switched off and locked,
and connections files protected with DPAPI are not opened. Save such a file with
a master password before the policy is applied.

The typed contract additionally reserves ``RequireMasterPassword``,
``MinimumMasterPasswordLength`` (0 through 1024 UTF-16 code units),
``RequireUppercase``, ``RequireLowercase``, ``RequireDigit``,
``RequireSpecialCharacter``, ``AllowPersistentUnlock`` and
``AllowPlaintextExport`` for their separate enforcement changes. Apart from the
DPAPI rule above, these flags are not an enforcement claim until the
corresponding consumers are installed. Use ``AllowExportPasswords`` in
``SOFTWARE\mRemoteNG\Credentials`` to forbid exporting passwords.
No password or unlock key belongs in the registry.
