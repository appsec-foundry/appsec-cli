# appsec-cli

Eine gemeinsame CLI für die AppSec-Tools des Teams. Ein Suite-Release definiert in seinen Paketmetadaten, welche Adapter und Engine-Versionen Teams erhalten. Ein Adapter kann eine Python-Funktion aufrufen, ein mitgeliefertes Programm starten oder ein bestehendes Berichtsformat lesen. Der CLI-Kern übernimmt Hilfe, Ausgabe und Exit-Codes.

## Installation für Dev-Teams

Sobald das AppSec-Team die Release-Wheels im konfigurierten Paketindex bereitgestellt hat, genügen:

```sh
pipx install appsec-cli
appsec-cli
appsec-cli tools list --check
pipx upgrade appsec-cli
```

Für die **hier gebaute Version 0.1.0** kann das AppSec-Team ein lokales Wheelhouse bereitstellen. Der erste Befehl lädt auf einem Linux-x86_64-Rechner mit Python 3.10 die fixierten externen Wheels. Der zweite installiert die Suite vollständig aus den beiden lokalen Verzeichnissen.

```sh
python3 -m pip download --only-binary=:all: --require-hashes -r requirements-linux-py310.lock -d .wheelhouse
PIP_NO_INDEX=1 PIP_FIND_LINKS="$PWD/dist $PWD/.wheelhouse" pipx install appsec-cli
```

Installiere für spätere Upgrades über den Paketnamen und konfiguriere den Paketindex bzw. das Wheelhouse dauerhaft im Runner oder in pip. `pipx upgrade appsec-cli` zieht neu aufgenommene Plugins und die für das Release festgelegten Engines mit. Deaktivierungen bleiben erhalten. Geprüfte Plattform ist Linux mit Python 3.10 und Git.

## Vorhandene Befehle

| Aufruf | Ergebnis |
|---|---|
| `appsec-cli security-score .` | Score und Rating eines Repositorys. Für Änderungen stehen `--commit SHA` und `--staged` bereit. |
| `appsec-cli analyze-threats .` | Betrachtet den eingecheckten Stand von HEAD. Architektur, Bedrohungen, Belege, bestehende Maßnahmen und offene Fragen erscheinen im Bericht. |
| `appsec-cli analyze-threats --commit HEAD` | Vergleicht einen Commit mit seinem ersten Elterncommit und berücksichtigt unveränderten Kontext. |
| `appsec-cli analyze-threats --pr https://github.com/TEAM/REPO/pull/42` | Liest über GitHub die Merge-Basis und den Head des PR. Private Repositories benötigen freigegebenen Lesezugriff. |
| `appsec-cli appsec-analyzer repo-profile .` | Liefert das Repository-Inventar der paketierten Analyzer-Engine. |
| `appsec-cli appsec-analyzer export ASSESSMENT ZIEL --format sarif` | Lässt den Analyzer einen gespeicherten Assessment-Ordner als SARIF oder HTML exportieren. |
| `appsec-cli appsec-verifier export verification.yaml` | Validiert einen vorhandenen Verifier-Bericht und exportiert Finding-Identitäten, Verdicts und Confidence für die weitere Auswertung. |

`appsec-cli tools list --all` zeigt auch deaktivierte Tools. `tools describe NAME` erklärt die Argumente aller Befehle eines Tools. Die Terminalansicht orientiert sich am AppSec Verifier. Globale Optionen wie `--format`, `--output` und `--fail-on` stehen vor dem Toolnamen.

## Modellprofile

Claude Code (`claude`) ist der Standard. `--profile` und `--model` überschreiben `APPSEC_CLI_PROFILE` und `APPSEC_CLI_MODEL`. Die beiden CLI-Profile verwenden die separat angemeldete Anbieter-CLI. Die HTTP-Profile lassen sich ohne Anbieter-CLI verwenden.

| Profil | Laufzeit und Konfiguration |
|---|---|
| `claude` | Claude Code auf dem PATH mit gültiger Anmeldung |
| `codex-cli` | Codex CLI auf dem PATH mit gültiger Anmeldung |
| `anthropic-api` | Anthropic Messages API mit `ANTHROPIC_API_KEY` |
| `litellm` | HTTPS-Adresse des OpenAI-kompatiblen Gateways in `LITELLM_BASE_URL` (z. B. `https://gateway.example/v1`), `LITELLM_API_KEY` und ein Modellalias mit JSON-Schema-Unterstützung |

```sh
appsec-cli --format json analyze-threats --profile litellm --model team-review --commit HEAD
```

Die Analyse übermittelt einen begrenzten Quellkontext an den ausgewählten Modellhost. Sie liest Git-Blobs, priorisiert Änderungen und Architekturunterlagen und nennt ausgelassene Inhalte. Der Lauf erhält bei ausgelassenen Dateien oder offenen Fragen den Status `partial`. Standardgrenzen sind 100 Dateistände, 32 KiB pro Datei und 160.000 Bytes insgesamt. Jede gemeldete Bedrohung muss auf eine mitgelieferte Datei und Zeile verweisen.

## CI, Team-CLIs und Skills

Für CI kann ein vertrauenswürdiger Runner die Schwelle explizit setzen. Das Beispiel schreibt den Bericht auch dann, wenn Findings die Schwelle erreichen oder die Prüfung teilweise scheitert. Der Exit-Code des letzten Kommandos ist der Job-Status.

```sh
appsec-cli --format json --output report.json --fail-on high security-score .
```

Eine Team-CLI kann denselben Vertrag mit einer Argumentliste verwenden:

```python
import json
import subprocess
import sys

run = subprocess.run(
    ["appsec-cli", "--format", "json", "security-score", "."],
    capture_output=True, text=True,
)
if run.stdout and run.returncode in (0, 1, 3):
    report = json.loads(run.stdout)
    print(report["summary"])
if run.stderr:
    print(run.stderr, file=sys.stderr, end="")
sys.exit(run.returncode)
```

Für Fork-PRs kann CI mit `--config /runner/trusted/appsec.toml` Reporting-Einstellungen aus dem freigegebenen Zielstand verwenden. Plugin-Freigaben gehören in `$XDG_CONFIG_HOME/appsec-cli/config.toml` bzw. `~/.config/appsec-cli/config.toml`. Beispiel:

```toml
[plugins]
disabled = ["appsec-verifier"]
additional = ["team-inventory"]
```

Der Nutzungsskill entdeckt die tatsächlich aktivierten Befehle und liest deren Datenschema. Er liegt auch im Suite-Wheel unter `share/appsec-cli/skills/appsec-cli/`. [Nutzungsskill](skills/appsec-cli/SKILL.md) · [JSON-Vertrag und Exit-Codes](docs/result-schema.md)

## Für das AppSec-Team

Neue Plugins lassen sich als Datenbefehl, Finding-Check, Befehlsgruppe oder Wrapper für ein externes Programm anlegen. Der Generator schreibt ein eigenes Python-Paket mit Entry Point und Vertragstest. [Plugin erstellen, verteilen und aktualisieren](docs/writing-a-tool.md)

Die Release-Prüfung auf einem Linux-x86_64-Runner mit Python 3.10 und pipx verwendet die lokalen, vertrauenswürdigen Checkouts von appsec-tools und appsec-analyzer. Der Builder nutzt die angegebenen Commit-IDs, auch wenn das Arbeitsverzeichnis der Engine auf einem anderen Stand steht.

```sh
make release-check SCORE_REPO=/pfad/appsec-tools ANALYZER_REPO=/pfad/appsec-analyzer
```

Der Check prüft externe Wheel-Hashes und PyPI-Advisories, installiert die fixierten Abhängigkeiten, baut die Wheels und durchläuft Vertragstests sowie einen echten pipx-Upgrade-Test. Für einen lokalen Build in einer vorbereiteten Build-Umgebung genügt `python3 scripts/build_release.py --score /pfad/appsec-tools --analyzer /pfad/appsec-analyzer`. Der Ordner `dist/` enthält die acht Suite-, Adapter- und Engine-Wheels. Der Betreiber verteilt die Wheels über den Team-Index. [Implementierungsstand und offene Abnahmen](docs/implementation-plan.md)

Der HTML-Export des Analyzers braucht zusätzlich das Systemprogramm Pandoc. SARIF, Repository-Profil, Security-Score und der Offline-Export des Verifiers laufen mit den paketierten Python-Tools.
