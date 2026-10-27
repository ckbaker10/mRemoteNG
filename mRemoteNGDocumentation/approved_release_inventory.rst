Approved release inventory
==========================

The enterprise helper scripts prepare an exact inventory for a company build.
They do not sign binaries, approve a release, install it or change Windows policy.
The final post-signing EXE, DLLs, plugins, helpers and runtime must all be present
in one release directory. Reparse points are rejected rather than followed.

Run ``New-ReleaseManifest.ps1`` on Windows with the release directory, exact
40-character source commit and an output path outside that directory. Optional
``-RequireValidSignatures`` rejects executable components without a valid
Authenticode signature. No signing private key or certificate password is accepted.
``Test-ReleaseManifest.ps1`` rejects modified, added, missing and duplicate files.
``ReleaseManifest.Tests.ps1`` exercises successful and failed verification using
only temporary synthetic files.

The manifest records ordinary SHA-256 file inventory hashes. App Control uses
its own Authenticode/PE rule hashes, which must be generated from the same final
files with Windows policy tooling. Do not paste inventory hashes into rules as
if the two formats were interchangeable. Hashing a directory does not prove
that it contains every dynamically loaded dependency; validate that coverage
during the Windows acceptance test. A new build requires a new inventory and
explicitly updated release policy.
