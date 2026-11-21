# Ein Tool als Plugin ausliefern

## Ein Verzeichnis für einen JSON-Befehl

Lege im Suite-Repository `modules/repo-profil/tool.toml` an. Der Verzeichnisname wird zum Befehl.

```toml
engine = "appsec-analyzer==0.1.0a0"
args = ["repo-profile", "{repo}", "--json"]
```

Nach dem nächsten Suite-Release können Teams `appsec-cli repo-profil .` ausführen. Der Build übernimmt die Engine als pip-Abhängigkeit. Hilfe, Toolliste, Deaktivierung und JSON-Ausgabe funktionieren wie bei anderen Befehlen. Bei einem Engine-Update ändert das AppSec-Team den Versionspin im Manifest und veröffentlicht die Suite in einer neuen Version.

Nur `engine` ist Pflicht. Im Standardfall erhält das Programm den absoluten Repositorypfad und `--json`. Mit `args` kannst du diese Liste ersetzen. Ohne `{repo}` hat der Befehl kein Repository-Argument. Für eine Beschreibung gibt es `description`. Bei mehreren Console Scripts verwendet die CLI das gleichnamige Script des Pakets oder den explizit angegebenen Namen in `binary`. Die Engine liefert bei Exit 0 ein JSON-Objekt, das unverändert unter `data` erscheint.

## Python-Adapter für individuelle Übersetzungen

Für eigene Finding-Regeln, mehrere Operationen oder enginespezifische Exit-Codes gibt es den Paketgenerator.


Ein Plugin besitzt seinen Befehlsnamen, die fachlichen Argumente und das Schema seiner Ergebnisse. Der Generator legt ein unabhängig paketierbares Projekt an. Wähle den Einstieg entsprechend dem Tool:

```sh
appsec-cli tools new team-inventory --scenario data
appsec-cli tools new policy-check --scenario findings
appsec-cli tools new reports --scenario group
appsec-cli tools new score-wrapper --scenario external --engine appsec-security-score==0.3.3 --binary security-score
```

Beim externen Wrapper benennt `--engine` das Paket und `--binary` dessen Console Script. pip installiert die Engine beim Installieren des Plugins in dieselbe Umgebung. Der Beispielhandler erwartet ein Repository und ein JSON-Objekt auf stdout. Passe Argumentliste, erlaubte Rückgabecodes und Übersetzung des Toolformats an das native Programm an. Der offizielle Score-Adapter zeigt das für ein Tool, das auch bei unvollständiger Prüfung einen Bericht liefert.

Ein Nicht-Python-Tool kann sein ausführbares Programm als Resource in plattformspezifischen Wheels mitliefern. Der Adapter löst die Resource aus seinem installierten Paket auf und startet sie über `appsec_cli.external.invoke` mit Argumentliste, Zeit- und Ausgabelimit. Ein separater Dienst benötigt stattdessen einen passenden API-Adapter. Für Aufrufe ohne Netz und reproduzierbare Upgrades gehören Engine oder Engine-Client in die versionierten Abhängigkeiten des Adapters.

## Schnittstelle

Der Entry Point `team-inventory` in der Gruppe `appsec_cli.tools` zeigt auf den dekorierten Handler eines Pakets namens `appsec-plugin-team-inventory`. Für Gruppen registriert das Paket einen Entry Point pro Operation, z. B. `reports.summary` oder `reports.export`. So zeigt die Übersicht alle Aufrufpfade, bevor Plugin-Code importiert wird.

```python
from appsec_cli import Result, command
from pydantic import BaseModel

class Inventory(BaseModel):
    component: str

@command(data=Inventory)
def inspect(component: str) -> Result:
    """Report a selected component."""
    return Result(summary="Component inventoried.", data={"component": component})
```

`@command(findings=True)` erlaubt zusätzlich Findings. Jede Regel beginnt mit dem Befehlsnamen und einem Schrägstrich. Plugins können Diagnosecodes und den Laufstatus setzen. Wer eine eigene Textdarstellung benötigt, übergibt mit `render_data=` eine Funktion, die aus validierten Fachdaten eine Liste von Textzeilen erzeugt. Das öffentliche JSON-Schema bleibt davon unabhängig.

## Testen und verteilen

1. Passe den generierten Handler und seinen Test an. Trage Team, Quellrepository und Issue-Tracker in die Paketmetadaten ein. Pflege Änderungen an Befehlen und Datenverträgen im Changelog des Plugins.
2. Baue in einer vorbereiteten Python-Buildumgebung mit `python -m pip wheel --no-deps --no-build-isolation . -w dist`. Installiere das Wheel zum Ausprobieren mit `pipx inject appsec-cli dist/<wheel>.whl` und ergänze den Namen unter `[plugins].additional` in der Benutzerkonfiguration.
3. Prüfe `appsec-cli tools list --check`, `appsec-cli --format json tools describe NAME`, einen fachlichen Aufruf und einen Fehlerfall. Den generierten Modultest startest du mit dem Python der Umgebung, in der der Adapter installiert ist, über `python -m unittest discover -s tests`.
4. Für die Standard-Suite veröffentlicht das AppSec-Team das Adapter-Wheel und seine Engine-Abhängigkeiten im vereinbarten Index. In der Suite-`pyproject.toml` ergänzt es den festen Adapter-Pin unter `dependencies` und den öffentlichen Namen unter `tool.appsec-suite.bundle`. Der Core braucht dafür keine Änderung. Alle Teams erhalten dieses Tool beim nächsten Suite-Upgrade.

Die Engine kann dauerhaft in einem eigenen Repository bleiben. Bei einem Engine-Update veröffentlicht ihr zuerst die Engine, hebt im Adapter den Pin und die Adapterversion an, testet die Abbildung des nativen Ergebnisses und veröffentlicht anschließend die Suite mit neuem Adapter-Pin und neuer Suite-Version. Optionale, von einem Team selbst injizierte Erweiterungen lassen sich auf Indexinstallationen mit `pipx runpip appsec-cli install --upgrade appsec-plugin-NAME` aktualisieren. Ein entfernter offizieller Befehl wird auch dann ausgeblendet, wenn pip sein altes Wheel im Environment belässt.

Der Offline-Adapter für den Verifier führt das Berichtsschema aus dem Verifier-Commit `90fb9736af8911e0bb7e0d9b007328cfb86f9706` mit (Apache 2.0, Lizenz im Adapter). Bei einem Schemawechsel aktualisiert das AppSec-Team diese Datei und prüft die Extraktion der exportierten Felder mit vorhandenen Berichten.
