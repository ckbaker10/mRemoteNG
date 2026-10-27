Security administrative templates
=================================

The templates in ``policies/`` configure the implemented machine security policy.
They contain no company domain names, passwords, certificates or binary allowlists.
Use a build containing all corresponding enforcement changes; an older executable
does not gain enforcement merely because the registry values exist.

Installation
------------

Copy ``mRemoteNG.Security.admx`` into the administrative templates directory and
the matching ``en-US/mRemoteNG.Security.adml`` or ``de-DE/mRemoteNG.Security.adml``
into its language subdirectory. For local evaluation this is
``%SystemRoot%\PolicyDefinitions``. For domain use, an administrator can install
them in the domain's Central Store after testing. The category is under Computer
Configuration, Administrative Templates, mRemoteNG, Security.

Values are read from the 64-bit view of
``HKLM\SOFTWARE\Policies\mRemoteNG\Security``. A full application restart is
required. HKCU and user preferences cannot relax machine policy. New policy has
precedence over legacy ``SOFTWARE\mRemoteNG\Security\Options`` defaults.

Enabled and disabled behavior
-----------------------------

* Boolean policies write REG_DWORD 1 when enabled and 0 when disabled. Thus
  **disable** ``AllowPersistentUnlock``, ``AllowPasswordExport`` and
  ``AllowPlaintextExport`` to apply their corresponding prohibitions.
* Enabled length and KDF policies write the selected REG_DWORD. Enabled cipher
  policies write the selected REG_SZ. Disabling or unconfiguring those parameter
  policies removes the managed value. Unconfigured booleans also remove their
  managed values. Previously saved stronger user defaults are not automatically reset.
* Missing values preserve unmanaged behavior. Invalid types, values or unreadable
  configured policy do not silently fall back to weaker settings.
* Character-class, minimum-length and full-encryption requirements imply a personal
  master password even if ``RequireMasterPassword`` itself is disabled.

Rollout
-------

Choose approved length, character classes, engine, authenticated mode and KDF
iterations for the actual client hardware. Editor starting values are examples
for configuration, not an already approved company baseline or benchmark result.
Migrate connection files and sensitive settings before normal managed use.
Use ``--migrate-settings`` for settings migration, and handle old backups separately.
No master password is distributed through GPO. Domain account password rules do
not automatically validate a local mRemoteNG master password.

Test each policy state and the effective application behavior in a dedicated OU.
Use a standard-user client to verify that local preferences cannot weaken it.
Application-version control is separate: deploy and validate an App Control or
AppLocker policy for the exact approved EXE, DLLs, plugins and helpers. These
administrative templates do not restrict which executable Windows can run.

The file format follows Microsoft's `PolicyDefinitions schema
<https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/schema-root>`_.
