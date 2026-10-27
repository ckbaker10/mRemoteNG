Company application control preparation
======================================

These helpers are separate from the generic application and GPO-template changes.
They generate deployment artifacts or install into a new protected directory only
when explicitly invoked. They do not modify a domain GPO, install an App Control
policy, obtain a certificate or sign anything automatically.

Preparation
-----------

Create and verify the final release inventory first. On Windows, supply an
already reviewed multiple-format base policy and its approved SHA-256 to
``New-ApprovedAppControlPolicy.ps1``. The base must enable UMCI, supplemental
policies and .NET Dynamic Code Security. The helper rejects broad file-path
allows, Managed Installer and Intelligent Security Graph trust. It generates a
hash-only supplement from the final release, checks its rules and re-verifies
the release before compiling the CIP file. The output record binds the source
commit, release manifest, base policy, generated XML and binary hashes.

These checks do not prove that every other deployed base, supplemental or signer
rule is sufficiently restrictive. Review effective publisher trust and run
negative tests against other signed and unsigned mRemoteNG versions. No unrelated
allow rule may admit an unapproved build. Inventory hashes are not substituted for
the Authenticode/PE hashes computed by ConfigCI.

``Install-ApprovedRelease.ps1`` requires elevation and a new destination below
Program Files. It rejects existing destinations and reparse-point ancestors,
sets inherited read/execute access for Users and full access only for System and
Administrators, copies the exact release and verifies it again. An update uses
a new release directory and a separately reviewed policy update.

Lab and production acceptance
-----------------------------

Validate in an isolated VM and snapshot it before policy enforcement. Test the
approved EXE, DLLs, plugins, helpers, RDP/SSH and COM paths. Test modified binaries,
different versions and unapproved renamed/portable copies. An identical copy of
the approved bytes has the same approved identity and can be allowed by hash
regardless of its filename; forbidding that as well would require an additional
location constraint beyond the single-version requirement.

Audit-mode success does not prove enforcement. Switch the reviewed lab base to
enforced mode only with a tested recovery path, then repeat the negative tests.
For protection against administrator policy tampering, prepare signed policies
and Secure Boot with an authorized signing and recovery process. An unsigned lab
policy is not evidence for that stronger production configuration. A signing
identity, final Windows target matrix and production distribution repository must
be selected before company rollout.

The implementation uses Microsoft's `New-CIPolicy
<https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy>`_
and the documented `supplemental policy workflow
<https://learn.microsoft.com/en-us/windows-server/security/osconfig/osconfig-how-to-configure-app-control-for-business>`_.
