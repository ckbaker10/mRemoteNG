# Prüfung der Firmenanforderungen an mRemoteNG

Stand: 27.10.2026. Untersucht wurde der Fork `ckbaker10/mRemoteNG`,
Commit `e3b0108e5ea06c9b8baedcfa385e1b18e9de2385`.
Der Projektstand bezeichnet sich als `1.78.2-dev` und zielt auf
`.NET 10 / Windows` (`mRemoteNG/mRemoteNG.csproj:12–18`).

**Ergebnis: Die vier Anforderungen sind im untersuchten Stand nicht vollständig
erfüllt.** Verschlüsselung und mehrere zentral verteilbare Einstellungen sind
vorhanden. Eine verbindliche Masterpasswort- und Komplexitätsrichtlinie fehlt.
Die Freigabe genau eines Programmstands muss zusätzlich durch Windows erzwungen
werden. Eine GPO-Konfiguration allein schließt die Anwendungslücken nicht.

| Anforderung | Bewertung | Begründung |
| --- | --- | --- |
| Gespeicherte Passwörter verschlüsseln | Teilweise abgedeckt | XML-Verbindungen verschlüsseln Passwortfelder; ohne eigenes Masterpasswort wird ein eingebauter Standardschlüssel benutzt. CSV-Export erlaubt Klartext. |
| Masterpasswort nicht speichern | Für den normalen XML-Pfad grundsätzlich vorhanden, insgesamt nicht verbindlich abgesichert | Der XML-Serializer speichert einen verschlüsselten Prüftext statt des Masterpassworts. Ein separater Settings-Keystore enthält dagegen Code für reversible DPAPI-Speicherung eines Masterpassworts. Dessen Aktivierung ist im untersuchten Startpfad nicht nachgewiesen. |
| Masterpasswort mit Komplexitätsregeln, zentral erzwingbar | Nicht erfüllt | Keine entsprechende Registry-Richtlinie; vorhandene Constraint-Klassen sind nicht mit der Eingabe verbunden. Der Dialog ignoriert sogar das Ergebnis seiner einfachen Prüfung. |
| Nur eine freigegebene, unveränderte Anwendungsversion | Extern umsetzbar | App Control for Business beziehungsweise AppLocker plus geschützte Installation und vollständige Freigabe aller geladenen Komponenten nötig. Kein entsprechender anwendungsinterner Schutz nachgewiesen. |

## 1. Verschlüsselung gespeicherter Passwörter

Der aktuelle XML-Serializer 2.9 erbt von 2.8. Dort wird das Verbindungspasswort
mit `_cryptographyProvider.Encrypt(...)` geschrieben. Der Standard in
`mRemoteNG/Properties/OptionsSecurityPage.settings:5–15` ist AES/GCM mit 10.000
KDF-Iterationen; vollständige Dateiverschlüsselung ist standardmäßig aus.
Der AEAD-Provider verwendet 256-Bit-Schlüssel und zufälliges 128-Bit-Salt.
Die Ableitung erfolgt durch `Pkcs5S2KeyGenerator` (PBKDF2).
Die Zahl 10.000 beschreibt den Istzustand, keine Sicherheitsempfehlung.

Belege:

- `mRemoteNG/Config/Serializers/ConnectionSerializers/Xml/XmlConnectionNodeSerializer29.cs:12–15`
- `mRemoteNG/Config/Serializers/ConnectionSerializers/Xml/XmlConnectionNodeSerializer28.cs:177–179`
- `mRemoteNG/Security/SymmetricEncryption/AeadCryptographyProvider.cs:34–39,125–135`
- `mRemoteNG/Security/KeyDerivation/Pkcs5S2KeyGenerator.cs:24–32`

**Entscheidende Einschränkung:** `RootNodeInfo.PasswordString` fällt ohne
aktivierten eigenen Passwortschutz auf einen im Quellcode enthaltenen
Standardschlüssel zurück (`mRemoteNG/Tree/Root/RootNodeInfo.cs:41–54`).
Damit sind Felder technisch verschlüsselt, aber nicht zuverlässig vor jemandem
geschützt, der die Datei und den öffentlich bekannten Programmcode besitzt.
Auch vollständige Dateiverschlüsselung erzwingt kein eigenes Masterpasswort:
`XmlConnectionsDocumentCompiler.cs:27–37` verwendet denselben Schlüsselpfad.

Zusätzliche Einstellungen wie SQL-, Proxy- und Standard-Zugangspasswörter
verwenden an mehreren Stellen `Runtime.EncryptionKey`. Dieser wird aus dem
Standard eines neuen Root-Knotens initialisiert (`mRemoteNG/App/Runtime.cs:56`;
beispielsweise `UI/Forms/OptionsPages/SqlServerPage.cs:127`).
Auch diese Speicherorte müssen in die Härtung aufgenommen werden; ein eigenes
Passwort am Verbindungsbaum schützt nicht automatisch sämtliche Einstellungen.

**Klartextausgabe ist weiterhin möglich:**
`CsvConnectionsSerializerMremotengFormat.cs:117–119` schreibt `con.Password`
direkt in CSV. Auch VNC-Proxy- und RD-Gateway-Passwörter werden direkt
angehängt (Zeilen 177 und 185). `App/Export.cs:62–63` übernimmt die Auswahl
aus dem Dialog und überschreibt den SaveFilter. Die globale Einstellung
`AllowExportPasswords` wird im Anwendungscode nur eingelesen und für den
Hinweis auf der Credentials-Seite ausgewertet; im Exportpfad fehlt die Prüfung.
Sie ist daher derzeit keine wirksame Sperre für diesen Exportpfad.

Für die Firmenanforderung müssen Klartextexporte einschließlich Nebenpasswörtern
zentral gesperrt und alle Speichervorgänge mit einem persönlichen, ausreichend
starken Schlüssel abgesichert werden. Der bloße Nachweis von AES genügt nicht.

## 2. Masterpasswort und Komplexität

Im klassischen XML-Verbindungspfad serialisiert
`XmlRootNodeSerializer.cs:28–34` einen verschlüsselten bekannten Prüftext im
Attribut `Protected`. Das Masterpasswort selbst wird dort nicht gespeichert.
Salt, KDF-Parameter und ein verschlüsselter Prüftext sind zum Entsperren nötig
und erlauben Offline-Passwortversuche; sie ersetzen kein starkes Masterpasswort.

Während der Sitzung hält `RootNodeInfo.cs:16,44–50` das Masterpasswort als
verwalteten `string` im RAM. Falls mit „nicht gespeichert“ auch Arbeitsspeicher,
Auslagerungsdateien oder Prozessabbilder gemeint sind, erfüllt dieser Ansatz die
strengere Auslegung nicht. Für den üblichen Fall „nicht dauerhaft auf Platte
ablegen, bei jedem Start eingeben“ ist der XML-Ansatz grundsätzlich geeignet.

**Die Eingabeprüfung ist fehlerhaft:**

- `UI/Controls/ConnectionInfoPropertyGrid/ConnectionInfoPropertyGrid.cs:352–371`
  öffnet beim Aktivieren des Passwortschutzes `MiscTools.PasswordDialog(...)`.
- `Tools/MiscTools.cs:39–47` verwendet standardmäßig den Neupasswortmodus.
- `UI/Forms/FrmPassword.cs:140–151` prüft nur mindestens drei Zeichen und
  Übereinstimmung mit der Wiederholung.
- `FrmPassword.cs:91–96` ruft diese Prüfung auf, ignoriert ihren Rückgabewert
  und setzt anschließend immer `DialogResult.OK`. Der Aufrufer verwirft nur
  Abbruch beziehungsweise ein leeres Passwort. Ein kurzes, nichtleeres Passwort
  oder eine abweichende Wiederholung wird auf diesem Codepfad nicht abgewiesen.

Klassen für Mindestlänge, Groß-/Kleinbuchstaben, Zahlen und Sonderzeichen liegen
unter `Security/PasswordCreation/` und besitzen Tests. Die Quelltextsuche findet
jedoch keine Verwendung dieser Constraints außerhalb ihrer Definitionen und
Tests. Weder sie noch eine Windows-Domänenpasswortrichtlinie erzwingen hier
automatisch die Komplexität des lokalen Masterpassworts.

**Separaten Settings-Keystore berücksichtigen:**
`Config/Settings/Store/SettingsStoreInitializer.cs:67–91` kann das eingegebene
Masterpasswort an `DpapiMasterKeyProvider.StoreKey(...)` übergeben. Dieser
verschlüsselt es reversibel mit Windows-DPAPI und schreibt es auf Platte
(`Security/KeyManagement/DpapiMasterKeyProvider.cs:63–78`). Verschlüsselt
abgelegt wäre bei der Anforderung „darf nicht gespeichert sein“ ebenfalls
unzulässig. Die Suche findet keine Instanziierung des Initializers im normalen
Anwendungsstart; dieser Befund belegt vorhandenen Code, keine beobachtete
Speicherung im laufenden Produkt. `OptionsRepositoryManager.cs:83–101` enthält
bereits einen Pfad zum Lesen eines vorhandenen DPAPI-Keystores.

Erforderliche Ergänzungen: eigenes Masterpasswort verbindlich machen,
Deaktivierung sperren, Komplexität zentral prüfen, fehlerhafte Dialogprüfung
korrigieren und persistente Entsperrmechanismen per Richtlinie ausschließen.
Bei bestehenden Dateien muss eine Migration beziehungsweise Ablehnung
schwacher Schutzkonfigurationen vorgesehen werden.

## 3. Was bereits über GPO verteilbar ist

Die Anwendung liest maschinenweite Registry-Einstellungen. Sie können über
GPO-Registry-Einstellungen verteilt werden; im untersuchten Repository gibt
es keine ADMX-/ADML-Vorlagen. Ein natives administratives Vorlagenpaket müsste
ergänzt werden. Die vorhandenen Schlüssel liegen unter `SOFTWARE\mRemoteNG`,
nicht unter einem automatisch angenommenen `SOFTWARE\Policies`-Pfad.

Unter `HKLM\SOFTWARE\mRemoteNG\Security\Options` sind vorhanden:

| Wertname | Registry-Typ laut Projektdokumentation | Wirkung |
| --- | --- | --- |
| `EncryptCompleteConnectionsFile` | `REG_SZ` (`true`/`false`) | Vollständige XML-Dateiverschlüsselung vorgeben |
| `EncryptionEngine` | `REG_SZ` | Zum Beispiel `AES` vorgeben |
| `EncryptionBlockCipherMode` | `REG_SZ` | Zum Beispiel `GCM` vorgeben |
| `EncryptionKeyDerivationIterations` | `REG_DWORD` | KDF-Iterationszahl vorgeben |

`Config/Settings/Registry/OptRegistrySecurityPage.cs:32–44,65–100` liest und
übernimmt diese Werte. `UI/Forms/OptionsPages/SecurityPage.cs:78–106` sperrt
zugehörige Oberflächenfelder, wenn Registry-Vorgaben gesetzt sind.
`Config/Connections/XmlConnectionsSaver.cs:36` verwendet die Einstellung für
vollständige Verschlüsselung beim regulären Speichern. Der XML-Export in
`App/Export.cs:87–99` setzt dagegen `UseFullEncryption` nicht aus dieser Vorgabe;
auch dieser Unterschied muss bei einer verbindlichen Richtlinie geschlossen werden.

Unter `HKLM\SOFTWARE\mRemoteNG\Credentials` existieren unter anderem
`AllowSavePasswords` und `AllowExportPasswords`
(`Config/Settings/Registry/CommonRegistrySettings.cs:99–106`).
Speichern ganz zu untersagen ersetzt die gewünschte sichere Speicherung nicht;
die Exportsperre hat die oben beschriebene Durchsetzungslücke.

Es fehlen Richtlinien für verpflichtendes Masterpasswort, Passwortkomplexität
und Verbot persistenter Masterpasswörter. GPO-Vorgaben müssen künftig auch
beim Öffnen, Importieren, Speichern und Exportieren geprüft werden.
Eine Sperre einzelner Dialogfelder allein reicht nicht.

## 4. Genau eine unveränderte Version zulassen

Diese Anforderung ist mit Windows-Anwendungskontrolle grundsätzlich umsetzbar.
Für eine exakte Freigabe bieten sich Hashregeln für die freigegebenen Binärdateien
an. Eine signierte Anwendung kann alternativ über Herausgeber, Produkt,
Dateiname und exakt eingegrenzte Version freigegeben werden.
Breite Herausgeber-, Verzeichnis- oder zusätzliche Freigaberegeln dürfen keine
andere mRemoteNG-Version zulassen. Umbenannte oder portable Kopien müssen von
derselben wirksamen Richtlinie erfasst werden.

Microsoft beschreibt dafür [AppLocker-Regelbedingungen und die Option Exactly](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/working-with-applocker-rules)
und [Hashregeln](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-file-hash-rule-condition-in-applocker).
AppLocker kann über GPO verteilt werden. App Control for Business ist für einen
stärkeren geräteweiten Schutz zu prüfen; insbesondere können
[signierte Richtlinien mit Secure Boot](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/use-signed-policies-to-protect-appcontrol-against-tampering)
auch die Manipulation der Richtlinie durch Administratoren erschweren.

Zum freigegebenen Umfang gehören EXE, DLLs, Plugins, Hilfsprogramme und die
relevante Laufzeit. Der Fork sucht Plugins auch in konfigurierbaren Verzeichnissen
(`Plugins/PluginService.cs:35–59,87–95`) und lädt Assemblies dynamisch
(`App/ProgramRoot.cs:178–234`). Deshalb muss die Richtlinie auch geladenen Code
abdecken. Für .NET ist Microsofts Dokumentation zu
[Dynamic Code Security und Kompatibilitätsgrenzen](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/appcontrol-and-dotnet)
zu beachten und mit diesem .NET-10-/WinForms-/COM-Programm praktisch zu testen.

Die Installation gehört in ein für normale Benutzer nicht beschreibbares
Verzeichnis; Benutzer sollten keine lokalen Administratorrechte erhalten.
Updates müssen als neue Freigabe ausgerollt werden. Das Abschalten des internen
Updaters allein sperrt weder fremde Versionen noch geänderte DLLs.
`App/Checks/AppUpdater.cs:167–180` prüft heruntergeladene Updates per Authenticode;
das ersetzt keine Ausführungskontrolle sämtlicher Programmdateien.
`SignAssembly=False` im Projekt beschreibt außerdem .NET-Assembly-Signierung
und beweist nicht, dass veröffentlichte Programme keine Authenticode-Signatur haben.

## 5. Nächste Schritte und Abnahme

1. Firmenrichtlinie konkretisieren: Mindestlänge, erlaubte beziehungsweise
   erforderliche Zeichenklassen, Umgang mit bestehenden Dateien sowie Schutz
   gegenüber Standardbenutzern oder zusätzlich lokalen Administratoren.
2. Richtlinienprüfung im Anwendungskern ergänzen, vorhandene Registry-Anbindung
   erweitern und ADMX/ADML erstellen. Den Passwortdialog und die Exportpfade
   korrigieren. Settings-, Credential- und Nebenpasswörter mit einbeziehen.
3. Einen geprüften Build samt Abhängigkeiten freigeben und die Windows-
   Anwendungskontrolle auf dem tatsächlich eingesetzten Windows-Stand testen.
4. Auf einem Windows-Testclient nachweisen: kein Klartext in Speicherdateien,
   Backups oder Exporten; Masterpasswort nach Neustart erneut nötig; schwache
   Passwörter und fehlender Schutz werden abgelehnt; Registry-Vorgaben bleiben
   wirksam; alte, veränderte und portable Builds sowie manipulierte Plugins
   starten beziehungsweise laden nicht. Prüfen, dass der freigegebene Build
   mit RDP/SSH und den benötigten Plugins weiter funktioniert.

Es wurden ausschließlich Quellen und Projektkonfiguration statisch untersucht.
Kein Windows-Laufzeittest, keine Domänen-GPO-Abnahme, kein Kryptografie-Audit und
keine Prüfung veröffentlichter Installer/Binärsignaturen wurden durchgeführt.
Auf dem Analysehost ist .NET SDK 8.0.132 vorhanden; das Projekt und seine
Windows-CI benötigen .NET 10. Für den reinen Bericht ist kein Build erforderlich.

## Reproduzierbare Nachweise

Lokaler Klon: `/opt/paseo-development/mRemoteNG`.
Werkzeuge: Git 2.43.0, ripgrep 15.2.0, Python 3.12.3.
Die Sammlung wurde mit dem Skill `analysis-evidence` aufgezeichnet; Rohdaten
liegen ausschließlich unter dem lokal ignorierten `work/`.

Exakter Aufruf aus dem Repository:

```sh
python3 /home/developer/.codex/skills/analysis-evidence/scripts/evidence.py --output work/security-review-2026-10-27/evidence-complete --input work/security-review-2026-10-27/collect.py --tool-version 'Python 3.12.3; git 2.43.0; ripgrep 15.2.0' -- python3 work/security-review-2026-10-27/collect.py
```

`work/security-review-2026-10-27/evidence-complete/metadata.json` enthält Befehl,
Arbeitsverzeichnis, Werkzeugversionen, Hostzeitstempel und Exitstatus 0.
`stdout.log` enthält nummerierte Quelltexte, deren SHA-256 und die exakten
Suchbefehle; `stderr.log` enthält die Fehlerausgabe. Die Rohdaten bleiben lokal.
Die Sammeldatei hat SHA-256
`fcaa453ac92385c8ff743aeef640af1b065914dffcc75d8a8e012078ff74d2ab`.
Bei Wiederholung ist ein neuer Ausgabepfad zu verwenden.

Zentrale Eingaben, SHA-256 jeweils über die unveränderten Dateibytes:

| Datei | SHA-256 |
| --- | --- |
| `mRemoteNG/Tree/Root/RootNodeInfo.cs` | `44b6a50efc705208b761d64b4c95f740d12dbc6e51cec0f00d3dcd334cb9de81` |
| `mRemoteNG/UI/Forms/FrmPassword.cs` | `8f5ab60a50b224be8d0f6560d996a25a545a7eb121d0d6f5fb58f5426da0f8f5` |
| `mRemoteNG/Config/Settings/Registry/OptRegistrySecurityPage.cs` | `d304df8cc16809a8a7e475ef4729b8b096c00afb5b237a97d630076ef7b3085f` |
| `mRemoteNG/Config/Serializers/ConnectionSerializers/Csv/CsvConnectionsSerializerMremotengFormat.cs` | `6d2aecae1bbb8c1a6511bebcb6c2d1e5ac294a653196c8cbfdbe7b97f39dd22d` |
| `mRemoteNG/Config/Settings/Store/SettingsStoreInitializer.cs` | `887d95c9b24a770297ea250dae2b83de151658bec5e544051a7823f62c862ba7` |
| `mRemoteNG/Security/KeyManagement/DpapiMasterKeyProvider.cs` | `c1e3a6b2740eb3c4a7cf60b43ee0706b965116944f4008aa940c57352ba1f82f` |
