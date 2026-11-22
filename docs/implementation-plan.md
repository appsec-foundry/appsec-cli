# Umsetzungsplan appsec-cli

Stand 21.11.2026 · Suite 0.1.0 ist lokal als Wheel-Satz gebaut. Installation, Upgrade mit `appsec-cli update`, Pluginwechsel und Aufrufe der paketierten Engines wurden unter Linux mit pipx geprüft. Der Einstieg steht im [README](../README.md). Die Phasen weiter unten dokumentieren die ursprünglichen Abnahmekriterien. Wo die Umsetzung davon abweicht, steht es direkt vor den Phasen.

Der pipx-Upgrade-Test hat die echte Score-Engine von 0.3.2 auf 0.3.3 aktualisiert und dabei eine Deaktivierung erhalten. Der Offline-Verifier hat einen vorhandenen Bericht mit 69 Annotationen verarbeitet. Eine Finding-Ausgabe wurde gegen das offizielle SARIF-2.1.0-Schema validiert. Bei den Offline-Installationstests wurden drei externe Python-Wheels aus den installierten, mit RECORD abgeglichenen Dateien rekonstruiert. Das Release-Lock verwendet die Hashes der Original-Wheels.

Jedes Tool ist ein Verzeichnis unter `tools/`. Für ein Tool mit JSON-Ausgabe reicht eine Datei `tools/<name>/tool.toml`. Ein Verzeichnis mit `pyproject.toml` ist ein Python-Adapter für eigene Ausgabeformate und Finding-Regeln; neue Adapter entstehen als Kopie von `tools/_template`. Der Build findet beide Arten, übernimmt Engine-Pin bzw. Adapterversion und registriert den Verzeichnisnamen als Befehl.

Die Release-Auswahl ergibt sich aus den Verzeichnissen unter `tools/` und steht in den Paketmetadaten der Suite. Der Kern liest Befehlsnamen ohne Plugin-Import und lädt den Handler erst für Aufruf oder Detailansicht. Im Terminal zeigt appsec-cli nur eine Kopf- und eine Ergebniszeile; den Inhalt dazwischen liefert das jeweilige Tool. Kapselt ein Tool eine Engine, erscheint im Terminal deren eigene Ausgabe ohne diesen Rahmen, und der Lauf endet mit ihrem Exit-Code. Farbe gibt es dort nur für Status und Severity, mit den Werten der Palette des AppSec Analyzer. Nur die Startseite, auf der kein Tool sein eigenes Logo zeigt, trägt das Logo der appsec-foundry-Tools in Schiefergrau. Die Adapter nutzen die paketierten Engines oder beim Verifier das Berichtsformat. Beim Threat-Review steuert der Adapter Quellauswahl und Analysevertrag und nutzt die Host-Transporte des Analyzers sowie HTTP für die API-Profile.

## Ziel

`appsec-cli` macht jedes aktivierte AppSec-Tool direkt als `appsec-cli <command>` verfügbar. Nur Tools mit mehreren eigenständigen Operationen brauchen Unterbefehle. Drei Gruppen nutzen die CLI:

- das AppSec-Team, das die Tools schreibt und pflegt,
- andere Teams, lokal und in CI-Pipelines,
- Skills und andere Automatisierung, die die CLI aufrufen und die JSON-Ausgabe lesen.

Das AppSec-Team ergänzt einen Befehl über ein neues Verzeichnis unter `tools/`. Die Kern-CLI bleibt dabei unverändert. Dev-Teams können denselben Befehl im Terminal, aus einer eigenen CLI oder in einer CI-Pipeline als Prozess aufrufen. Skills entdecken die installierten Befehle und lesen ihre Ergebnisse als JSON.

### Beispiel für die Nutzung

Die ersten beiden Befehle sind `security-score` und `analyze-threats`. Globale Optionen stehen vor dem Befehlsnamen, toolspezifische Argumente dahinter. Vorgesehene Aufrufe:

```sh
appsec-cli security-score .
appsec-cli --format json --fail-on high security-score . > report.json
appsec-cli --format json tools list
appsec-cli --format json tools describe analyze-threats
```

Der zweite Aufruf eignet sich auch für eine Team-CLI oder einen CI-Job. Der aufrufende Prozess übernimmt den Exit-Code und kann den Bericht auch bei Findings auswerten. Skills verwenden dieselbe Schnittstelle ohne Python-Import.

### Erste Integrationen

- **`security-score`** hat bereits ein eigenständiges CLI-Tool. Der Adapter nutzt dessen strukturierte Ausgabe und übernimmt Score und Rating bei Repository-Prüfungen bzw. die Sicherheitsrelevanz bei Änderungen in `data`. Findings und unvollständige Verarbeitung werden auf das gemeinsame Ergebnisschema abgebildet. Scanning und Scoring mit der Standard-Engine brauchen keinen Modellzugang. [Skill](https://github.com/appsec-foundry/appsec-skills/blob/main/skills/security-score/README.md) · [Tool](https://github.com/appsec-foundry/appsec-tools/tree/main/security-score)
- **`analyze-threats`** liefert direkt im Terminal eine kontextbezogene Bedrohungsanalyse für einen Pull Request, einen Commit oder ein ganzes Repository. CI und Skills können dasselbe Ergebnis als JSON lesen. Der bestehende Skill dient als fachliche Referenz. [Skill](https://github.com/appsec-foundry/appsec-skills/blob/main/skills/analyze-threats/README.md)

| Vorgesehener Aufruf | Umfang der Analyse |
|---|---|
| `appsec-cli analyze-threats --pr <URL>` | Änderungen des PR anhand von Vergleichsbasis und Head prüfen. Betroffene Aufrufer, Datenflüsse und bestehende Schutzmaßnahmen aus dem umgebenden Code einbeziehen. |
| `appsec-cli analyze-threats --commit <SHA>` | Die Änderung dieses Commits im lokalen Repository untersuchen. Ergebnis und Belege nennen den Commit und die verwendete Vergleichsbasis. |
| `appsec-cli analyze-threats .` | Den gesamten eingecheckten Repository-Stand an HEAD als Prüfgegenstand behandeln, einschließlich Komponenten, Schnittstellen, Datenflüssen und Vertrauensgrenzen. |

Ein vorhandenes Bedrohungsmodell, Architekturunterlagen oder Anforderungen ergänzen den jeweiligen Codekontext. Bei Änderungen beschreibt die Analyse, welche Bedrohungen neu entstehen, sich verändern oder durch bestehende Maßnahmen abgedeckt sind. Das Ergebnis enthält Umfang und Revision, priorisierte Bedrohungen mit Belegen, mögliche Auswirkungen und empfohlene Maßnahmen. Wesentliche offene Fragen und ausgelassene Bereiche bleiben sichtbar. Verhindert eine solche Lücke die Bewertung des angeforderten Umfangs, erhält der Lauf `partial`.

### Weitere Integrationen und Aktivierung

Auch `appsec-analyzer` und `appsec-verifier` erhalten eigene Plugin-Pakete. Als erste Analyzer-Befehle sind `appsec-cli appsec-analyzer repo-profile` für einen Repository-Überblick und `appsec-cli appsec-analyzer export` für vorhandene Assessments vorgesehen. Für den Verifier ist `appsec-cli appsec-verifier export` zum Offline-Export eines fertigen `verification.yaml` vorgesehen. Die lokalen Projekte deklarieren bereits gleichnamige eigenständige Programme. Jeder Adapter veröffentlicht die von ihm unterstützten Operationen und deren Argumente einzeln.

`appsec-cli` ist das Installationspaket für die Suite. Seine Release-Metadaten legen die mitgelieferten Plugin-Pakete und getesteten Versionen fest. Der Kern enthält ausschließlich den gemeinsamen Vertrag, die Discovery und Verwaltung. Neue Tools, auch aus separaten Repositories, registrieren sich über Entry Points. Das gilt ebenso für die ersten Tools und für spätere Ergänzungen.

Standardmäßig sind die offiziellen Plugins des installierten Releases aktiv. Ein Tool mit `enabled = false` in seinem Verzeichnis liefert der Release mit, es bleibt aber aus, bis ein Team es unter `[plugins].additional` einschaltet. Teams können jedes davon in der Benutzer- oder vertrauenswürdigen CI-Konfiguration deaktivieren. Beispiel:

```toml
[plugins]
disabled = ["appsec-verifier"]
```

Eine leere Liste aktiviert wieder alle offiziellen Plugins. Entfernt ein Team einen einzelnen Namen, aktiviert es nur dieses Tool wieder. Die Einstellung bleibt bei Upgrades erhalten. `tools list --all` zeigt auch deaktivierte Plugins samt Status. Die normale Hilfe und JSON-Liste zeigen die aktiven Tools. Vor Beschreibung, Unterbefehl, direktem Aufruf oder Ladeprüfung wertet der Kern dieselbe Auswahl aus. Der direkte Aufruf eines deaktivierten Tools endet vor dem Import mit Exit 2 und dem Hinweis auf `tools list --all`. Ein Projekt kann diese Auswahl nicht überschreiben. Die Kernbefehle für Hilfe, Liste und Schema bleiben immer erreichbar. Die Deaktivierung gilt für den öffentlichen Suite-Befehl; gemeinsam genutzte Bibliotheken können anderen aktiven Plugins weiterhin als Abhängigkeit dienen.

### Befehle entdecken

`appsec-cli` ohne Argumente zeigt das Logo, eine Zeile Einleitung aus der Beschreibung des Suite-Pakets und jeden Befehl mit Kurzbeschreibung und erstem Beispielaufruf, am Ende die nächsten Schritte. Ohne Farbe steht dort schlichter Text statt des Logos. `appsec-cli --help` ergänzt die globalen Optionen, `appsec-cli TOOL --help` zeigt alle Beispiele eines Tools. `appsec-cli tools list` zeigt Version und Status jedes Tools. Beschreibungen und Beispiele stehen im Verzeichnis des Tools; der Release-Build sammelt sie, sodass die CLI dafür kein Tool laden muss. Ein Tool mit genau einem Befehl erscheint einmal. Die Übersicht ist alphabetisch sortiert und funktioniert ohne Anmeldung oder Modellaufruf.

```text
appsec-cli 0.1.0
Security tools from your AppSec team
4 tools · terminal, CI and coding agents

Usage: appsec-cli [OPTIONS] TOOL [COMMAND] [ARGS]

Tools
  analyze-threats               Threat review of a repository, commit or PR.
    appsec-cli analyze-threats --commit HEAD
  appsec-analyzer export        Export a saved assessment, for example as SARIF or HTML.
    appsec-cli appsec-analyzer export --assessment ./assessment --output ./out
  appsec-analyzer repo-profile  Repository size, languages and build manifests.
    appsec-cli appsec-analyzer repo-profile .
  appsec-verifier export        Export results from completed verification reports.
  security-score                Score a repository or assess a change.
    appsec-cli security-score .

Next steps
  appsec-cli TOOL --help         Arguments, options and examples of a tool
  appsec-cli tools list          Installed tools, versions and status
  appsec-cli --format json TOOL  Result as JSON for scripts and CI
  appsec-cli update              Install the latest release
```

Bedienfehler enden mit Exit 2 und nennen auf stderr die Ursache und einen nächsten Schritt, etwa `Hint: Did you mean 'security-score'?` bei einem Tippfehler oder den Hinweis, eine globale Option vor den Toolnamen zu setzen.

`appsec-cli analyze-threats --help` erklärt die Eingaben und zeigt Beispiele. Skills erhalten mit `appsec-cli --format json tools list` dieselben Namen, Beschreibungen und Aufrufpfade in strukturierter Form.

### Modellprofile für analyze-threats

Claude Code ist der Standard (`claude`). Ein Modellprofil wählt die Laufzeit und deren Anmeldung. Das optionale `--model` wählt innerhalb des Profils ein Modell. Das Profil gilt für alle drei Prüfgegenstände. Beispiel: `appsec-cli --format json analyze-threats --profile codex-cli --commit HEAD`. Teams können das Profil für sich oder ihre CI konfigurieren; die ausdrückliche Profilwahl am Befehl hat Vorrang. Ohne Auswahl gilt `claude`. Das gescannte Projekt bestimmt weder Profil noch Zieladresse.

Für Version 1 sind `claude` (Standard), `codex-cli`, `anthropic-api` und `litellm` vereinbart. `litellm` nutzt einen vorhandenen LiteLLM Proxy über dessen OpenAI-kompatible HTTP-Schnittstelle. Betreiber konfigurieren Gateway-Adresse, Modellalias und Zugang in der Benutzer- oder Runner-Umgebung. Für den ausgewählten Alias wird die Unterstützung des Analyse-Schemas geprüft. Die Antwort durchläuft dieselbe lokale Validierung wie bei den anderen Profilen. Zur Abnahme gehören ein gültiges Analyseergebnis und eine verständliche Diagnose für einen Alias ohne Schema-Unterstützung. [LiteLLM Gateway](https://docs.litellm.ai/docs/simple_proxy) · [Strukturierte Antworten](https://docs.litellm.ai/docs/completion/json_mode)

Referenz ist die Profilauswahl in `appsec-verifier/appsec_verifier/agent/profiles.py`. Dort steht `claude` für Claude Code, `codex-cli` für Codex CLI, `copilot-cli` für GitHub Copilot CLI, `codex` für die OpenAI-API und `anthropic-api` für die Anthropic-API. Im Verifier ist die Profilangabe für explizit nichtinteraktive Läufe Pflicht. In der Suite kann das CI-Team das Profil einmal in der vertrauenswürdigen Runner-Konfiguration hinterlegen.

Die Analyse-Engine bestimmt Revision, Kontext und Bewertungsschema. Der gewählte Host verarbeitet den bereitgestellten Kontext und liefert eine strukturierte Antwort. Die Engine validiert sie für alle Profile gegen dasselbe Schema und hält Profil und Modell im Ergebnis fest. Ein fehlender Host oder eine fehlende Anmeldung ergeben eine Diagnose für das gewählte Profil. Ein Anbieterwechsel erfordert eine ausdrückliche Auswahl. Die Suite bringt die Adapter mit. CLI-Profile benötigen die jeweilige Anbieter-CLI und deren Anmeldung; ein direktes API-Profil braucht nur den konfigurierten API-Zugang.

## Getroffene Entscheidungen

| Thema | Entscheidung |
|---|---|
| Sprache | Python ab 3.10. Die CLI ist eine click-Gruppe; die Befehle der Tools erzeugt typer-slim aus den Signaturen der Handler. |
| Tool-Integration | Jedes Tool ist ein Python-Plugin und meldet sich über die entry-point-Gruppe `appsec_cli.tools` an. Tools in anderen Sprachen bekommen einen dünnen Python-Wrapper auf Basis des `ExternalTool`-Helpers. |
| Ablage | Jedes Tool ist ein Verzeichnis unter `tools/`: eine `tool.toml` für ein JSON-Tool ohne Code oder ein eigenständig baubarer Python-Adapter. Das Suite-Paket nimmt alle Verzeichnisse als Abhängigkeiten auf. Externe Programme behalten ihren eigenen Releasezyklus. |
| Installation und Updates | `pipx install appsec-cli` liefert alle offiziellen Befehle samt benötigten Tool-Paketen. `appsec-cli update` führt `pipx upgrade` aus, aktualisiert sie gemeinsam, installiert neu hinzugekommene Tools und zeigt die Änderungen. Danach aktualisiert es mit `pipx upgrade --include-injected` die per `pipx inject` ergänzten Team-Plugins; scheitert das, bleibt das Suite-Update gültig und `update` warnt. Einmal am Tag weist der erste Lauf im Terminal auf ein neueres Release im Team-Index hin. Der Release-Build verlangt für jedes geänderte Paket eine neue Version. |
| Engine-Quellen | Jedes Tool nennt in seinem Verzeichnis die Git-Quelle seiner Engine mit URL und vollständigem Commit-Hash. Der Build klont sie und checkt diesen Commit aus. Eine Engine von PyPI steht stattdessen mit Hash im Lockfile. Im Beispiel-Setup sind es die GitHub-Repos von appsec-foundry. `ENGINE_SOURCES` wählt je Engine einen anderen Git-Server, etwa ein internes GitLab, oder einen lokalen Checkout. Vorab muss nichts geklont sein. |
| Argumente | appsec-cli ist ein Wrapper. Alles nach dem Toolnamen geht unverändert an die Engine, `--help` zeigt deren Hilfe. Zurückgehalten werden nur Engine-Optionen, die das Ergebnis unlesbar machen, die Engine-Version des Release ersetzen, ein anderes Programm starten oder ein Geheimnis auswählen, und deren Abkürzungen. `analyze-threats` und `appsec-verifier` rufen keine Engine auf und behalten eigene Parameter. |
| Laden | Hilfe und `tools list` nutzen Entry-Point-Metadaten und die vom Release-Build gesammelten Beschreibungen und Beispiele. Erst Aufruf und `tools describe <tool>` laden das ausgewählte Tool. |
| Ergebnis | Gemeinsames Ergebnisschema v1 (siehe unten). Tools geben ein Ergebnisobjekt zurück und schreiben nicht selbst auf stdout. |
| Exit-Codes | Berechnet der Kern: 0 ok, 1 Findings ab Schwelle, 2 Bedienfehler, 3 Lauf fehlgeschlagen oder unvollständig |
| Ausgabe | Text für Menschen und JSON für Automatisierung unterstützen alle Befehle. SARIF exportiert Findings. Logs gehen auf stderr. Im Terminal rahmt appsec-cli die Ansicht des Tools nur ein und färbt nur Status und Severity; nur die Startseite zeigt ein Logo. |
| Config | TOML in mehreren Ebenen. Die Projekt-Config im Arbeitsverzeichnis darf nur Schwellen setzen und diese nur verschärfen. |
| KI-Tools | Host-Auswahl und Analysevertrag im zuständigen Adapter. Das Modell darf Alarm schlagen, aber nicht entwarnen. Antworten werden streng geprüft, eine ungültige Antwort ergibt `failed`. Endpoint und Key kommen nie aus dem gescannten Repo. |

## Entscheidungen und offene Abnahmen

| Thema | Stand in 0.1.0 |
|---|---|
| E1 / E2 | Pydantic 2 validiert den Vertrag. CLI und mitgelieferte Texte sind englisch. |
| E3 | Zugangsdaten kommen aus der Anbieteranmeldung oder der Runner-Umgebung. |
| E4 | Linux mit Python 3.12 getestet. macOS und WSL benötigen eine eigene Abnahme. |
| E5 | Claude Code, Codex CLI, Anthropic API und LiteLLM sind angebunden. Automatisierte Tests nutzen Host-Doubles. Die Freigabe mit realen Hostkonten steht aus. |
| E7 | CI kann eine Prüfkonfiguration aus dem vertrauenswürdigen Zielstand auswählen. Die Ausführung auf Fork-PRs entscheidet der jeweilige Runner-Betreiber. |
| E8 | Wheelhouse getestet. Der für Teams vorkonfigurierte Release-Index und der Veröffentlichungszeitpunkt sind offen. |
| Weitere Abnahmen | Anzeige von SARIF im Zielsystem und Online-Abgleich der Abhängigkeiten im Release-Runner. |

## Ergebnisschema v1

Gemeinsam sind nur vier Pflichtfelder: `schema_version`, `tool`, `status` und `summary`. Das fachliche Ergebnis legt der Befehl selbst fest. Unter `data` kann er beispielsweise einen Messwert, eine Liste inventarisierter Komponenten, einen Designvergleich oder offenen Klärungsbedarf liefern. Dazu deklariert er ein JSON-Schema. `findings` kann allein oder zusammen mit `data` auftreten. Ein neuer Ergebnistyp erfordert keine Änderung am Kern.

| Feld | Inhalt | Wer füllt es |
|---|---|---|
| `schema_version` | Ganzzahl, aktuell 1 | Kern |
| `tool` | Name des Tools | Kern |
| `status` | `ok`, `partial` oder `failed`, beschreibt nur den Lauf | Tool, bei Ausnahmen der Kern |
| `summary` | ein Satz für Menschen und Skills | Tool, sonst ein Standardtext vom Kern |
| `target` | was geprüft wurde, mit `kind` (`repository`, `pull_request`, `path`, `image` …) | Tool |
| `counts` | Findings pro Severity vor jedem Filtern, wird nur bei vorhandenem Feld `findings` erzeugt | Kern |
| `findings` | Optionale Liste. Eine leere Liste meldet null ermittelte Findings. Fehlt das Feld, liefert der Befehl für diesen Lauf keine Finding-Auswertung. | Tool |
| `diagnostics` | Fehler und Warnungen mit `level`, festem `code` und `message` | Tool und Kern |
| `data` | Fachliches Ergebnis als JSON-Wert gemäß dem Schema des Befehls | Tool |
| `run` | `cli_version`, `tool_version`, `started_at`, `duration_ms` | Kern |

Ein Finding hat die Pflichtfelder `rule` (mit Tool-Präfix, z. B. `pr-security-check/authn-change`), `severity` (`critical`, `high`, `medium`, `low`, `info`) und `title`. Optional sind:

- `confidence`: `high`, `medium` oder `low`
- `locations`: Liste von Fundstellen mit `kind` (`file`, `package`, `url`, `resource`, `repository`)
- `cwe`: Liste von CWE-IDs
- `remediation`: Hinweis zur Behebung
- `evidence`: Beleg, bei Secrets nur maskiert
- `fingerprint`: Standardwert vom Kern aus Regel und Fundstelle, ein Tool kann einen stabileren setzen

Beispiel für eine reine Score-Ausgabe im geplanten CLI-Format:

```json
{
  "schema_version": 1,
  "tool": "security-score",
  "status": "ok",
  "summary": "Repository score: 59/100 (Bad).",
  "data": {"score": 59, "rating": "Bad"}
}
```

Hier erhält CI den berechneten Wert auch bei Exit 0. Eine Mindestpunktzahl kann sie anhand von `data.score` prüfen. `--fail-on` bezieht sich auf die Severity gelieferter Findings. Ein Beispiel mit `data` und `findings` steht am Ende.

### Regeln für die Weiterentwicklung

- Wer das Format liest, ignoriert unbekannte Felder und unbekannte `kind`-Werte.
- Neue optionale Felder und neue `kind`-Werte ändern die Version nicht.
- Fällt ein Feld weg, wird es umbenannt oder ändert es seine Bedeutung, gibt es `schema_version: 2`. Die CLI kann dann eine Weile beide Versionen ausgeben (`--schema-version 1`).
- Beim Erzeugen ist das Modell streng. Liefert ein Tool ein unbekanntes Feld oder einen ungültigen Wert, schlägt sein Test fehl.

### Exit-Codes

| Situation | Exit-Code |
|---|---|
| `status` ist `failed` oder `partial` | 3 |
| `status` ist `ok` und mindestens ein Finding hat eine Severity ab `--fail-on` | 1 |
| `status` ist `ok`, sonst | 0 |
| falsche Optionen oder Argumente | 2 (Standard von Click) |

Für `--fail-on` gilt diese Reihenfolge: CLI-Option, `APPSEC_CLI_FAIL_ON`, Benutzer-Config oder `--config`, dann der Standard des Tools (bei KI-Tools `never`), dann der globale Standard `low`. Eine `.appsec-cli.toml` im Arbeitsverzeichnis darf das Ergebnis nur verschärfen. Einen lockereren Wert ignoriert der Kern und meldet `config_threshold_ignored`.

## Aufbau des Repos

| Ort | Inhalt |
|---|---|
| `pyproject.toml`, `setup.py`, `src/appsec_suite/` | Installationspaket und Version; der Build nimmt jedes Verzeichnis unter `tools/` auf |
| `core/src/appsec_cli/` | Discovery, Konfiguration, Terminal, Ergebnisvertrag, Format der `tool.toml` und Prozessaufrufe |
| `tools/` | Ein Verzeichnis pro Befehl: die vier Adapter des Beispiel-Setups und die Vorlage `_template` |
| `skills/appsec-cli/` | Mitgelieferter Nutzungsskill |
| `scripts/`, `tests/` | Build, Abhängigkeitsprüfung, Vertrags- und Installationstests |

## Schnittstelle für Tools

### Paketierung und Installation

Ein **Adapter** definiert den CLI-Befehl und übersetzt zwischen dem Tool und dem gemeinsamen Ausgabeformat. Er kann Teil eines bestehenden Python-Pakets sein oder als kleines eigenes Wheel veröffentlicht werden. Die CLI entdeckt die Entry Points der Pakete in ihrer Python-Umgebung. Ein Dev-Team kann deshalb einen eigenen Befehl ausliefern, ohne auf einen Release des CLI-Kerns zu warten. [Python Packaging – Entry Points](https://packaging.python.org/en/latest/specifications/entry-points/)

| Ausgangslage | Lieferung | Aufruf durch den Adapter |
|---|---|---|
| Python-Tool mit gepflegter Bibliotheksschnittstelle | Entry Point im Tool-Paket oder Adapter-Wheel mit deklarierter Abhängigkeit | Python-Funktion mit typisierten Argumenten |
| Bestehendes Kommando, z. B. `security-score`, Go-Binary oder Java-Launcher | Adapter im Tool-Paket oder als eigenes Wheel. Das Tool kommt aus seinem eigenen Release. | Installiertes Programm per Argumentliste starten, strukturierte Ausgabe, Fehler und Exit-Codes gemäß Tool-Vertrag übersetzen |
| Assistentengestütztes Tool wie `analyze-threats` | CLI-Adapter und benötigte lokale Analysekomponenten mit der Suite ausliefern. | Der CLI-Befehl führt die Analyse über die in E5 gewählte Engine aus. Ein Skill kann den Befehl aufrufen und das Ergebnis auswerten. |

Für `security-score` veröffentlicht das Team das vorhandene Python-Paket `appsec-security-score` als Wheel im gewählten Index. Jeder CLI-Release führt die getestete Version als exakte Laufzeitabhängigkeit. Dadurch installiert pipx auch das ausführbare Kommando in der Umgebung der CLI. Der Adapter löst dessen Pfad über das Skriptverzeichnis der laufenden Python-Umgebung auf und startet es mit JSON-Ausgabe. Dass `security-score` im globalen PATH liegt, ist dafür unerheblich. Die Scoring-Regeln pflegt weiterhin das Tool. Für Tools ohne JSON definiert der Adapter einen Parser für ein dokumentiertes Ausgabeformat und testet ihn gegen eine Referenzausgabe der unterstützten Version.

Für native Standardtools ohne Python-Paket kann der Herausgeber je unterstützter Plattform und Architektur ein Wheel mit Adapter und ausführbarer Datei bereitstellen, sofern die Lizenz die Weitergabe erlaubt. Der Adapter verwendet dann die Datei aus seinem installierten Paket. Separat verwaltete Programme kann ein Team über einen optionalen Adapter und einen konfigurierten Toolpfad anbinden. Für deren Updates ist der externe Paketmanager zuständig.

### Ablauf für Teams

| Zeitpunkt | Befehl | Wirkung |
|---|---|---|
| Erste Installation | `pipx install appsec-cli` | pipx installiert CLI und Standardtools aus dem konfigurierten Index in eine eigene Umgebung. |
| Erster Lauf | `appsec-cli security-score .` | Funktioniert für ein lokales Repository direkt nach der Installation. |
| Alle offiziellen Tools aktualisieren | `appsec-cli update` | Führt `pipx upgrade appsec-cli` aus. Installiert den neuen CLI-Release, die dafür freigegebenen Toolversionen und jedes neu ins Paket aufgenommene Tool und listet die Änderungen. |

Welche Tools offiziell dazugehören, ergibt sich aus den Verzeichnissen unter `tools/`; der Build schreibt sie in die Paketmetadaten von `appsec-cli`. Das gilt auch für Tools aus anderen Repositories. Für ein neues offizielles Tool legt das AppSec-Team ein Verzeichnis an. Engine und Adapter werden damit reguläre Abhängigkeiten des nächsten CLI-Release. Dev-Teams, CI und Skills folgen derselben Aktivierung. Separat ergänzte Team-Plugins werden in der vertrauenswürdigen Konfiguration über `[plugins].additional` ausdrücklich ausgewählt. Bei der Discovery kommen nur Einträge aus der aktuellen Release-Auswahl oder dieser zusätzlichen Auswahl in Betracht; `disabled` hat Vorrang. So taucht ein zurückgezogenes offizielles Plugin nach dem Upgrade auch dann nicht von selbst wieder auf, wenn sein Wheel noch installiert ist.

Der kurze Installationsbefehl setzt voraus, dass der Paketname im gewählten Index dem Team gehört und alle benötigten Pakete darüber auflösbar sind. Für einen internen Index wird der Zugriff einmalig auf Rechnern und Runnern eingerichtet. Benötigt `analyze-threats` eine lokale Engine, stellt die Standardinstallation diese bereit. Eine Anmeldung an einem externen Dienst kann weiterhin erforderlich sein. [pipx – Installation und Updates](https://pipx.pypa.io/stable/reference/cli.html)

CI verwendet eine feste CLI-Releaseversion und einen dazugehörigen geprüften Abhängigkeitsstand. Ein CI-Update erfolgt durch eine Änderung dieses Stands.

### Wartung der Plugins

| Bestandteil | Wer pflegt ihn? | Was wird veröffentlicht? |
|---|---|---|
| CLI-Kern und Suite-Paket | Das AppSec-Team pflegt den gemeinsamen Vertrag, die Aktivierungslogik und die Auswahl der Standardtools. | Ein Suite-Release mit den gemeinsam getesteten Plugin- und Toolversionen. |
| Externes Tool | Das zuständige Tool-Team pflegt Fachlogik, Regeln und native Ausgabe in seinem bestehenden Repository. | Ein eigener Tool-Release. Das AppSec-Team entscheidet, wann es diese Version ins Standardpaket übernimmt. |
| Separat installierbares Plugin | Das herausgebende Team pflegt Adapter, Abhängigkeiten, Dokumentation und Tests. README und Paketmetadaten nennen das Team und verlinken Repository und Issue-Tracker. | Ein versioniertes Wheel im vereinbarten Paketindex. Optionale Plugins können unabhängig von der CLI erscheinen. |

Beispiel `security-score`: Neue Bewertungsregeln erscheinen zuerst in `appsec-security-score`. Im CLI-Repository hebt ein PR die festgelegte Toolversion an. Die CI installiert die gebauten Pakete in einer frischen Umgebung und ruft `appsec-cli --format json security-score` mit einer Repository- und einer Änderungs-Fixture auf. Sie prüft Score bzw. Relevanz, JSON-Struktur und Exit-Code. Ändert sich ein erwarteter Score absichtlich, erläutert der PR die fachliche Änderung. Nach erfolgreicher Abnahme veröffentlicht das AppSec-Team den CLI-Release und nennt die neue Engine-Version im Changelog.

Für ein eigenständiges Plugin läuft derselbe Vertragstest in dessen Repository. Das Plugin deklariert die unterstützten CLI-Paketversionen und seine `ToolSpec.api_version`. Vor der Veröffentlichung prüft die Plugin-CI das gebaute Wheel mit der ältesten unterstützten und der aktuellen kompatiblen CLI-Version. Sie testet Discovery, Befehlsaufruf, fachliches Ergebnis und einen Fehlerfall. Änderungen an Befehlsnamen, Argumenten oder am `data`-Schema, die bestehende Nutzer betreffen, erhalten im Changelog ein Migrationsbeispiel für CI und Skills. Ein fehlerhafter Release wird durch eine neue Paketversion korrigiert.

### Registrierung

Jeder Entry Point verweist auf eine mit `@command` dekorierte Funktion. Das Paket `appsec-plugin-inventory` registriert z. B. `inventory` oder mehrere Operationen wie `inventory.list` und `inventory.export`. Der Kern liest diese Namen aus den installierten Wheel-Metadaten. `tools describe` erzeugt Parameter und Datenschema aus dem tatsächlich geladenen Handler. Neue Adapter entstehen als Kopie von `tools/_template`. [Vollständiges Beispiel und Paketierung](writing-a-tool.md)

## Ursprüngliche Phasen und Abnahmekriterien

Die Umsetzung weicht in fünf Punkten von den Phasen ab. Die Adapter deklarieren keine eigenen Argumente, sondern reichen alles an die Engine durch (siehe Getroffene Entscheidungen). Die Tools liegen unter `tools/` statt unter `plugins/` und `modules/`. Statt eines Generators gibt es die Vorlage `tools/_template`. Das Lazy Loading übernimmt eine click-Gruppe statt einer eigenen TyperGroup. Die Projekt-Config kann Schwellen nur verschärfen, damit gilt die Abnahme aus Phase 3 auch ohne `--config`.

### Phase 0: Projektgrundlage

- `git init`, `pyproject.toml` mit hatchling und src-Layout
- Abhängigkeiten: `typer`, `pydantic>=2`, `tomli` nur für Python < 3.11
- ruff, pytest, `.gitignore`, Gerüst für das README

Fertig, wenn `pip install -e .` durchläuft, `appsec-cli --version` eine Version ausgibt und `ruff check` und `pytest` grün sind.

### Phase 1: Ergebnismodell und Ausführungsrahmen

- Pydantic-Modelle für Schema v1, Severity und Status als Enums
- `@tool_command`, Berechnung der Exit-Codes, Fehlerbehandlung
- globale Optionen `--format`, `--output`, `--fail-on`, `-v`/`-q`, `--debug`, `--no-color`
- Ausgabe als `json` und `table`. Texte aus Tools werden ohne Rich-Markup und ohne Steuerzeichen ausgegeben, damit Dateinamen oder Modellantworten die Anzeige nicht verfälschen.
- `appsec-cli schema` gibt das JSON-Schema aus

Fertig, wenn reine Fachdaten, reine Findings und eine Kombination jeweils gegen das Schema validieren. Ein Test unterscheidet ein fehlendes Feld `findings` von einer leeren Liste, einer prüft die Ablehnung ungültiger `data` gemäß dem Tool-Schema. Jede Zeile der Exit-Code-Tabelle hat einen Test. Eine Ausnahme im Tool führt zu Exit 3 ohne Traceback auf stdout.

### Phase 2: Plugin-System

- Discovery über `importlib.metadata.entry_points(group="appsec_cli.tools")`
- Vorlage `plugins/_template/` mit einem Handler, einem Entry-Point-Beispiel und einem Test. Die Kurzanleitung zeigt den Weg von der Vorlage bis zum ersten Aufruf im Terminal.
- `LazyToolGroup` als eigene TyperGroup, die Tools aus den entry points auflistet und erst beim Aufruf importiert
- `appsec-cli tools list` liefert in JSON ein Objekt mit `schema_version: 1` und einer Liste `tools` mit Namen, Kurzbeschreibung, Aufrufpfaden und Ladestatus. Damit das ohne Plugin-Import funktioniert, erzeugt die Paketvorlage beim Bauen aus den Befehlsdefinitionen eine Katalogdatei und liefert sie als Paketmetadaten mit. Ein Entry Point ohne Katalog bleibt mit Namen und Verweis auf `tools describe <tool>` sichtbar. Ohne Import lautet der Ladestatus `unchecked`. Namenskonflikte zwischen Paketen und Kollisionen mit den Kernbefehlen `tools` und `schema` werden bereits bei der Discovery gemeldet. Eindeutige Befehle bleiben nutzbar.
- Die Auswahl erfolgt vor Import und Namensauflösung aus Release-Katalog, zusätzlicher Auswahl und Deaktivierungen. Der Vertragstest deaktiviert ein verschachteltes Test-Plugin und prüft Aufruf, Hilfe, Detailansicht, Completion, Ladeprüfung und JSON-Liste sowie die erneute Aktivierung.
- Beim Laden werden Name und `api_version` geprüft. Ein Import- oder Kompatibilitätsfehler des gewählten Tools ergibt Exit 3 mit Diagnose. `appsec-cli tools describe <tool>` liefert in JSON die Schnittstellenversion der Beschreibung, Befehlsnamen, Hilfe, Argumente, Optionen und das deklarierte `data`-Schema. Ein optionales `tools list --check` prüft alle registrierten Plugins und weist deren Ladefehler einzeln aus.

Fertig, wenn ein separat installiertes und ausgewähltes Test-Plugin ohne Änderung am Kern als `appsec-cli <name>` läuft und eine Test-Gruppe ihre Unterbefehle anbietet. In frischen Prozessen importieren globale Hilfe und Liste kein Tool. Die Beschreibung und der Aufruf laden nur das gewählte Tool. Ein kaputtes oder namensgleiches Plugin beeinträchtigt andere Befehle nicht. Ein Test liest die Liste als JSON, beschreibt einen Eintrag und führt ihn mit den dokumentierten Argumenten aus.

Der Pakettest vergleicht die Übersicht des installierten Wheels mit den tatsächlich registrierten Aufrufpfaden eines Einzelbefehls und einer Gruppe. Aufruf ohne Argumente und globale Hilfe enden mit Exit 0.

### Phase 3: Konfiguration

- Ebenen in dieser Reihenfolge: `~/.config/appsec-cli/config.toml` (bzw. unter `$XDG_CONFIG_HOME`), `.appsec-cli.toml` im Projekt, Umgebungsvariablen `APPSEC_CLI_*`, CLI-Optionen. Spätere Ebenen gewinnen.
- Die Aktivierung unter `[plugins]` wird ausschließlich aus der Benutzer- oder vertrauenswürdigen CI-Konfiguration gelesen. Ein entsprechender Schlüssel in der Projekt-Config ergibt `config_forbidden_key`.
- Abschnitte `[tools.<name>]`, geprüft gegen das `config_model` des Tools
- Die Projekt-Config darf nur Felder setzen, die als projekt-tauglich markiert sind, etwa Excludes und Schwellenwerte. Pfade zu Binaries, Endpoints und Zugangsdaten führen dort zu einem Fehler mit `code: config_forbidden_key`.
- Zugangsdaten nach E3, nie als CLI-Argument, in Logs und Ausgaben maskiert
- `--config <datei>` ersetzt die automatisch gefundene Projekt-Config und hat dieselben erlaubten Felder. Bei fremden PRs übergibt der CI-Job eine Konfiguration aus dem vertrauenswürdigen Zielstand. Fehlt die explizit gewählte Datei, bricht der Lauf ab.

Fertig, wenn die Reihenfolge der Ebenen getestet ist, ein verbotener Schlüssel den Lauf mit einer verständlichen Meldung abbricht und ein Fork-PR seine CI-Prüfung durch eigene Excludes oder Schwellenwerte nicht abschwächen kann.

### Phase 4: Bestehende Tools anbinden

- `ExternalTool(binary, min_version, version_args, version_pattern)`
- Mitgelieferte Tools über den Paketpfad bzw. das Skriptverzeichnis der CLI-Umgebung starten. Für separat verwaltete Tools den Pfad aus der Benutzer-Config oder den PATH verwenden.
- Start ohne Shell mit Argumenten als Liste, Timeout, Obergrenze für die gelesene Ausgabe, Übersetzung der Exit-Codes
- Jeder Adapter deklariert die unterstützten Operationen und Argumente. Updates des Tool-Pakets laufen über das Suite-Upgrade.
- Diagnose-Codes `binary_not_found`, `binary_version_unsupported`, `timeout`, `tool_failed`, `output_too_large`
- Erster Wrapper für das vorhandene `security-score`. Je ein Referenzlauf für Repository und Änderung prüft, dass der Adapter Score bzw. Relevanz und Findings aus der Tool-Ausgabe übernimmt.
- Für `analyze-threats` je einen PR, einen Commit und einen vollständigen Repository-Stand über die CLI prüfen. Mindestens ein Änderungsfall enthält eine relevante Schutzmaßnahme außerhalb des Diffs. Die Abnahme prüft deren Berücksichtigung, die tatsächlich bewerteten Revisionen und die Meldung unvollständiger Abdeckung. Der Repository-Fall enthält zusätzlich eine relevante Schnittstelle, die der jüngste Commit nicht berührt hat.
- Analyzer und Verifier anhand eines Repository-Profils bzw. eines vorhandenen Berichts als getrennte Plugins abnehmen. Jedes muss sich einzeln deaktivieren und wieder aktivieren lassen.
- In Phase 4 die gemeinsame Profilschnittstelle bereitstellen. Für jedes freigegebene Profil die Strukturvalidierung, fehlende Zugangsdaten und Timeouts testen. Vor Freigabe einen echten Analyseaufruf je Profil am selben kleinen Eingabebeispiel prüfen. Automatisierte Tests verwenden Host-Doubles.

Fertig, wenn Tests mit einem Fake-Skript fehlendes Binary, zu alte Version, Timeout, zu große Ausgabe und Argumente mit Shell-Sonderzeichen (`; touch pwned`, `$(id)`) abdecken, die aktivierten Integrationen mit ihren deklarierten Befehlen in `tools list` erscheinen und die Referenzfälle bestehen.

### Phase 5: Erste nutzbare Version für Dev-Teams und Skills

Braucht E8. Der Schnellstart zeigt die pipx-Standardinstallation, den direkten Aufruf von `security-score` und das gemeinsame Update aller offiziellen Tools.

- Ein Dev-Team ruft den Befehl aus einem anderen Arbeitsverzeichnis auf. Ein Beispiel für eine Team-CLI startet ihn mit einer Argumentliste, liest JSON von stdout und reicht seinen Exit-Code weiter.
- Ein CI-Beispiel setzt die gewünschte Schwelle, bewahrt den JSON-Bericht auch bei Exit 1 oder 3 auf und gibt den Exit-Code des Prüflaufs an den Job weiter.
- Der Skill „appsec-cli nutzen“ liest `appsec-cli --format json tools list`, beschreibt bei Bedarf das gewählte Tool mit `appsec-cli --format json tools describe <tool>` und ruft es mit `--format json` auf. Er liest den Laufstatus, interpretiert `data` gemäß dem deklarierten Schema und berücksichtigt vorhandene Findings, Counts und Diagnosen. Ein Test lässt ihn einen Score ohne Finding-Felder wiedergeben. Titel, Dateinamen und Modelltexte behandelt er als Daten. Bei Exit 2 erklärt er den Bedienfehler anhand von stderr.

Fertig, wenn eine frische pipx-Installation aus einem Testindex ohne separat installiertes `security-score` denselben lokalen Beispielbefehl im Terminal, aus der Team-CLI, im CI-Job und über den Skill ausführt. Der Upgrade-Test installiert Release A. Release B enthält eine neuere Scoring-Engine und ein zusätzliches offizielles Tool aus einem eigenen Paket. Nach genau einem `pipx upgrade appsec-cli` prüft der Test die tatsächlich gestartete Engine-Version und führt den neuen Befehl aus. Ein weiterer Upgrade-Fall prüft ein vom Team deaktiviertes und ein aus dem Release entferntes Plugin. Beide bleiben für normale Aufrufe inaktiv. Die fachliche Abnahme verwendet einen Lauf ohne Findings, einen mit Finding über der Schwelle und einen fehlgeschlagenen Lauf. CI und Skill unterscheiden alle drei Fälle.

### Phase 6: SARIF und Filter

- Export nach SARIF 2.1.0: `rule` wird `ruleId`, Fundstellen vom Typ `file` werden `physicalLocation`, andere Typen `logicalLocations`, `fingerprint` wird `partialFingerprints`
- Pro Finding wird `level` gesetzt: `critical` und `high` → `error`, `medium` → `warning`, `low` und `info` → `note`. Für GitHub erhält jede Sicherheitsregel in `tool.driver.rules` den höchsten Schweregrad ihrer Findings im ungefilterten Lauf als String in `properties.security-severity` (`"9.5"`, `"8.0"`, `"5.5"` oder `"3.0"`). Bei ausschließlich `info` entfällt das Feld.
- `--min-severity` und `--limit` filtern ausschließlich die Liste der Findings. Die Berechnung von `counts` und Exit-Code verwendet alle Findings. Für einen reinen Datenbefehl weist die CLI `--format sarif` als nicht unterstütztes Format mit Exit 2 aus. Unterstützte Formate stehen in `tools describe`.

Fertig, wenn die SARIF-Ausgabe gegen das offizielle SARIF-Schema validiert und im Zielsystem angezeigt wird. Ein Test deckt zwei Findings derselben Regel mit unterschiedlicher Severity ab. Ein weiterer prüft, dass Ausgabefilter den Exit-Code erhalten.

### Phase 7: Optionaler PR-Check

- Der PR-Check verwendet die in Phase 4 eingeführte Profilschnittstelle für strukturierte Modellantworten.
- Endpoint, Modell und Key nur aus Benutzer-Config oder Umgebung
- Prompts als Dateien im Tool-Paket mit Versionsnummer, die Version landet in `data`
- Der geprüfte Inhalt (Diff) wird abgegrenzt als Daten übergeben und nie in den System-Prompt eingebaut.
- Die Antwort wird strikt gegen das Schema geprüft: unbekannte Felder sind verboten, Werte kommen aus festen Listen. Eine ungültige Antwort, eine Ablehnung durch das Modell oder ein Timeout ergeben `failed` mit `llm_invalid_response`, `llm_refused` oder `llm_timeout`.
- Größenlimit für die Eingabe. Wird gekürzt, gibt es die Warnung `input_truncated` und `status: partial`.
- Optionaler PR-Check mit `default_fail_on = "never"`

Fertig, wenn Tests mit einem Fake-Client ungültiges JSON, unbekannte Felder, Ablehnung, Timeout und Kürzung abdecken, keiner dieser Fälle `ok` ergibt und ein manueller Lauf gegen den echten Anbieter einen PR bewertet. Für eine gültige Antwort ohne Findings erzeugt der PR-Check eine feste Zusammenfassung, die nur das Ausbleiben von Modellhinweisen meldet. Ein Skill-Test prüft dieselbe Aussage.

### Phase 8: Verteilung und Doku für Tool-Autoren

Braucht E8.

- Verteilung nach E8, Versionsnummer und Changelog
- `docs/writing-a-tool.md` mit der Vorlage `plugins/_template/`, einem Beispiel für die Pflege eines mitgelieferten Adapters und dem Ablauf für Test, Versionierung und Veröffentlichung eines eigenständigen Plugins
- `docs/result-schema.md` für alle, die die JSON-Ausgabe weiterverarbeiten
- Contract-Test: Für jedes registrierte Tool wird eine Beispielausgabe gegen das Ergebnisschema und sein `data`-Schema geprüft.

Fertig, wenn jemand aus dem Team ohne Hilfe ein drittes Tool nach der Anleitung hinzufügt und der Contract-Test es abdeckt.

## Risiken

- Lazy Loading hängt an einer eigenen click-Gruppe; Typer erzeugt nur die Befehle der Tools. click und typer-slim sind exakt gepinnt und durch Tests abgesichert.
- Nach dem Hinzufügen eines entry points muss das Paket neu installiert werden (`pip install -e .`). Das steht in der Anleitung für Tool-Autoren.
- KI-Tools kosten Geld und antworten nicht deterministisch. Automatische Tests laufen deshalb nur gegen einen Fake-Client, Tests gegen den echten Anbieter laufen manuell oder nur, wenn man sie ausdrücklich einschaltet.
- Ein eigenes Schema muss gepflegt werden. Contract-Test und Versionsregeln sollen verhindern, dass es unbemerkt auseinanderläuft.
- Python-Plugins teilen sich die Umgebung der CLI. Bei unvereinbaren Abhängigkeiten läuft das betroffene Tool als externes Programm in einer eigenen Umgebung. Nur sein dünner Wrapper wird als Plugin installiert.

## Beispielausgabe

```json
{
  "schema_version": 1,
  "tool": "pr-security-check",
  "status": "partial",
  "summary": "PR changes session handling; 2 of 14 files skipped due to size",
  "target": {"kind": "pull_request", "ref": "gitlab.example.com/shop/api!482", "commit": "9c1e2f7"},
  "counts": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
  "findings": [
    {
      "rule": "pr-security-check/authn-change",
      "severity": "medium",
      "confidence": "high",
      "title": "Session timeout raised from 15 to 240 minutes",
      "locations": [{"kind": "file", "path": "auth/session.py", "start_line": 40, "end_line": 42}],
      "cwe": ["CWE-613"],
      "remediation": "Set the timeout to 30 minutes or less, or document the exception",
      "fingerprint": "c7a1…"
    }
  ],
  "diagnostics": [
    {"level": "warning", "code": "input_truncated", "message": "2 files above the size limit were skipped"}
  ],
  "data": {"security_relevant": true, "categories": ["authentication"], "model": "<modell-id>", "prompt_version": "3"},
  "run": {"cli_version": "0.4.0", "tool_version": "1.2.0", "started_at": "2026-11-21T10:41:07Z", "duration_ms": 8312}
}
```

Weitere Arten von Fundstellen:

```json
{"kind": "package",    "purl": "pkg:pypi/requests@2.25.0", "manifest": "requirements.txt"}
{"kind": "url",        "url": "https://shop.example.com/login", "parameter": "next"}
{"kind": "resource",   "id": "arn:aws:s3:::backups-prod"}
{"kind": "repository", "ref": "gitlab.example.com/shop/api", "setting": "branch_protection"}
```
