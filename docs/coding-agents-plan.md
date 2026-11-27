# Umsetzungsplan: appsec-cli für Coding-Agenten

Stand 2026-11-27. **Status:** Alle Punkte sind umgesetzt (siehe [Umsetzung](#umsetzung)).

## Ziel

Coding-Agenten nutzen appsec-cli wie jede andere CLI, ohne eigenen Skill. Was ein Agent wissen muss, sagt die CLI selbst: auf der Startseite, in der Hilfe und im JSON-Ergebnis. Eine eigene Agentendarstellung (`--agent`-Modus, MCP-Server, `llms.txt`) gibt es nicht, denn sie wäre eine zweite Schnittstelle mit denselben Inhalten.

## Ausgangslage (geprüft)

- **Skill ohne Wirkung:** Die Suite installiert den Skill unter `<pipx-venv>/share/appsec-cli/skills/appsec-cli/`. Dort sucht weder Claude Code (`~/.claude/skills/`) noch Codex.
- **Was schon funktioniert:** Startseite und `--help` zeigen alle Tools mit Beispiel. Eine globale Option hinter dem Toolnamen endet mit Exit 2 und einem Hinweis, wie es richtig geht. Ohne Terminal gibt es keine Rückfragen und keinen Update-Hinweis. Der Fortschritt steht nur auf stderr.
- **`security-score` in der Sandbox:** `appsec-cli --format json security-score .` endet in der Sandbox von Claude Code mit Exit 3 („Cannot read selected source without following links“). Die Sandbox legt im Arbeitsverzeichnis Platzhalter für geschützte Dateien an (`.mcp.json`, `.gitconfig`, `.bashrc`, `.idea`, `.vscode` …). Das sind Gerätedateien, die sich nicht öffnen lassen. Die Engine nimmt nicht versionierte Dateien mit (`git ls-files --cached --others --exclude-standard` in `score_sources.py`), das Öffnen schlägt fehl, und der Lauf bricht ab. Derselbe Aufruf außerhalb der Sandbox ergibt `status: ok`. Der aktuelle Stand von appsec-tools (9703439) verhält sich gleich.
- **Exit 1 ohne Erklärung:** Bei Exit 1 steht im JSON `"status": "ok"`, und kein Feld nennt die Schwelle. Nur das Terminal zeigt „Threshold low reached (exit 1)“.
- **Modellaufrufe nicht erkennbar:** Die Beschreibungen auf der Startseite und in `tools list` sagen nicht, welches Tool Code an ein Modell schickt.
- **Versionen:** Es gibt noch kein `v*`-Tag. Die Versionsprüfung des Release-Builds greift also noch nicht, und Core und Adapter bleiben auf 0.1.0.

## Punkt 4: Skill streichen

Änderungen:

- `skills/appsec-cli/` löschen.
- `pyproject.toml`: den Abschnitt `[tool.setuptools.data-files]` entfernen.
- `tests/pipx_release.py`: `shutil.copytree(ROOT / "skills", target / "skills")` entfernen.
- README, Abschnitt „Team CLIs and coding agents“: Den Skill-Absatz ersetzt dieser Text:
  > Coding agents use appsec-cli like any other command-line tool: `appsec-cli --help` lists the commands, and `--format json` returns the result. To have an agent use it without being asked, add a line to the repository's `AGENTS.md` or `CLAUDE.md`, for example: *For security checks, use `appsec-cli`; run `appsec-cli --help` first.*
- README, Doku-Liste: den Eintrag „Usage skill“ entfernen; „skills“ wird zu „coding agents“.
- `docs/result-schema.md`, Zeilen 3 und 24: „skills“ wird zu „coding agents“.
- `docs/implementation-plan.md`: Die 15 Stellen kommen auf den neuen Stand: Agenten rufen die CLI direkt auf. Die Abnahme in Phase 5 prüft das über die CLI und nicht über einen Skill.

Prüfung: `make test` ist grün. `rg -i skill` findet nur noch Stellen, die bleiben sollen.

## Punkt 2: Exit 1 im JSON erklären

Änderungen:

- `core/src/appsec_cli/cli.py`, `finish`: Bei Exit-Code 1 hängt `finish` eine Diagnose an, nach demselben Muster wie `config_threshold_ignored`:
  `{"level": "info", "code": "threshold_reached", "message": "Threshold low reached by 3 findings (exit 1)."}`
  Die Zahl sind die Findings auf oder über der Schwelle, aus `counts`, also vor `--min-severity` und `--limit`. Bei einem Finding lautet die Meldung „by 1 finding“.
- `core/src/appsec_cli/ui.py`, `table`: Diese Diagnose nicht als Notiz zeigen, denn die Ergebniszeile sagt dasselbe.
- `docs/result-schema.md`: ein Satz zu `threshold_reached`.

Unverändert bleiben SARIF (es enthält keine Diagnosen) und die Schema-Version (eine neue Diagnose ändert kein Feld).

Tests in `tests/test_cli.py`:

- Exit 1: Die Diagnose ist da, mit Schwelle und Zahl, auch mit `--limit 0`.
- Exit 0, `--fail-on never` und Exit 3 bei erreichter Schwelle: keine Diagnose.
- Terminal: keine doppelte Notiz.

## Punkt 3: Beschreibungen schärfen

Änderungen:

- `tools/analyze-threats/pyproject.toml`, `description`: „Model-based threat review of a repository, commit or PR.“
- `tools/security-score/pyproject.toml`, `description`: „Score a repository or assess a change; no model calls.“ Das ist die Formulierung der Engine-Hilfe. „Locally“ wäre falsch, denn bei einer URL liest das Tool über HTTPS.
- `tools/analyze-threats/src/appsec_plugin_analyze_threats/commands.py`, Docstring des Handlers, ein neuer Satz: „Sends the selected source to the profile's model; a review can take up to 3 minutes.“
- `docs/writing-a-tool.md`, Abschnitt „Descriptions and examples“, eine neue Regel: „Say in the description whether the tool calls a model.“

Die Beispieltabelle im README bleibt, wie sie ist. Sie hat schon die Spalte „Model calls“.

Prüfung: `make test` ist grün. Die längste Zeile der Startseite ist nicht länger als heute (etwa 89 Zeichen). `appsec-cli --help`, `appsec-cli analyze-threats --help` und `appsec-cli --format json tools list` zeigen die neuen Texte.

## Punkt 1: Sandbox-Fehler in der Engine beheben

### 1a. appsec-tools (`../appsec-tools/security-score`)

- `scripts/score_sources.py`: Eine nicht versionierte Datei, die keine reguläre Datei ist (Gerätedatei, FIFO, Socket), überspringt die Engine, statt den Lauf abzubrechen. Das wird vor dem Öffnen mit `lstat` geprüft.
- Eine übersprungene Datei zählt nicht als Lücke in der Abdeckung, sonst stünde der Lauf auf `partial` und endete wieder mit Exit 3.
- Versionierte Dateien und Links behandelt die Engine so streng wie bisher.
- Bricht ein Lauf weiterhin ab, nennt die Meldung die Datei (Pfad bereinigt) und den tatsächlichen Grund statt „without following links“.
- Version 0.3.3 wird 0.3.4. pip installiert eine Engine nur neu, wenn sich ihre Version ändert.
- Tests im Framework von appsec-tools:
  - Eine nicht versionierte FIFO im Repository: Der Score läuft durch, und der Status ist nicht `partial`. Eine FIFO lässt sich ohne Root-Rechte anlegen, eine Gerätedatei nicht.
  - Ein Link: Der Lauf bricht weiterhin ab.
- Ein Commit auf `main` in appsec-tools, ohne Push.

### 1b. appsec-cli

- `tools/security-score/pyproject.toml`: `appsec-security-score==0.3.4`, `[tool.appsec-cli.source] commit` auf den neuen Commit.
- Der neue Pin bringt auch 9703439 mit, ab dem die Engine Python 3.12 oder neuer verlangt. Deshalb:
  - `pyproject.toml` (Suite): `requires-python = ">=3.12"`.
  - README: Badge „Python 3.12+“, in der Tabelle „Security Score 0.3.4“.
- Prüfung:
  - `make release-check ENGINE_SOURCES="appsec-security-score=PFAD"` mit einem lokalen Checkout von appsec-tools ist grün.
  - In der Sandbox liefert `appsec-cli --format json security-score .` den Status `ok`.
- `make install` ohne `ENGINE_SOURCES` funktioniert erst, wenn der Commit in appsec-tools auf GitHub liegt.
- Eine bestehende pipx-Installation auf Python 3.10 muss danach mit 3.12 neu aufgesetzt werden.

## Reihenfolge und Commits

4 → 2 → 3 → 1a → 1b. Jeder Punkt wird ein eigener Commit auf `main`, nach grünem `make test`, im Stil der bisherigen Nachrichten. Gepusht wird nichts.

## Verworfen

| Idee | Grund |
| --- | --- |
| `appsec-cli skill install` | Eine CLI braucht keinen Skill. Für die Auffindbarkeit reicht eine Zeile in `AGENTS.md` oder `CLAUDE.md`. |
| Abschnitt zu den Exit-Codes in `--help` | Ein Agent liest das JSON, nicht zwingend die Hilfe. README und `result-schema.md` beschreiben die Codes schon. Punkt 2 deckt das ab. |
| „agents“ unter „Next steps“ | Bringt nichts. Der JSON-Weg steht dort schon. |
| maschinenlesbares Feld `model_calls` | Die Beschreibung und die Hilfe reichen, ein neues Feld wäre zusätzliche Schnittstelle. |
| Workaround im security-score-Adapter | Der Adapter reicht die Engine durch und deutet sie nicht um. Beim direkten Aufruf von `security-score` hülfe er ohnehin nicht. |
| `--agent`-Modus, MCP-Server, `llms.txt` | Wären eine zweite Darstellung derselben Inhalte, die gepflegt werden müsste. |

## Punkt 5: Hilfe der Wrapper-Tools zeigt den JSON-Weg

Ausgangslage (geprüft): Die Hilfe von `security-score` und `appsec-analyzer repo-profile` zeigt die Option `--json` der Engine. `appsec-cli security-score . --json` liefert im Terminal das eigene JSON der Engine mit anderen Feldern (`overall`, `subscores`, `checks` …), ohne `status`, `summary` und `counts`, und endet mit dem Exit-Code der Engine (hier 2). Dass `--format json` vor dem Toolnamen das gemeinsame Ergebnis liefert, steht in dieser Hilfe nicht.

Änderungen:

- `core/src/appsec_cli/cli.py`, `Forwarding.format_options`: Nach „Arguments and options go to the engine unchanged …“ kommt ein Satz, der die Optionen erklärt und kein Ergebnis verspricht:
  > With --format json before the tool name, appsec-cli returns its common result; output options of the engine print the engine's own format.
- Der Satz erscheint bei allen Wrapper-Befehlen. Ob ein Befehl JSON kann, entscheidet erst sein Handler. `requirement-harvester login` lehnt `--format json` ab, dort bleibt der Satz ungenau. Das ist vertretbar: Der Harvester ist standardmäßig aus und für das AppSec-Team gedacht, und ein Versuch endet mit einer klaren Fehlermeldung. Ein Kennzeichen im Plugin-Interface nur für diesen Satz wäre zu viel.
- Das `--json` der Engine bleibt im Terminal erlaubt (Durchreichen).
- Die Textansicht von `tools describe` (`ui.py`) bleibt, wie sie ist.

Test in `tests/test_cli.py` (`test_wrapper_help_is_the_engine_help`): Die Hilfe enthält den Satz. Danach prüfe ich von Hand mit der gebauten CLI `appsec-cli security-score --help` und `appsec-cli appsec-analyzer repo-profile --help`.

## Punkt 6: Beispielzeile für AGENTS.md schärfen

Die Zeile liegt dauerhaft im Kontext des Agenten und ist die einzige Stelle, die ihm vor dem ersten Aufruf die Regel zum Datenfluss mitgibt. Bisher sagt sie nur „run `appsec-cli --help` first“. Sie wirkt nur, wenn ein Team sie übernimmt, und ersetzt Punkt 5 deshalb nicht.

Änderung: README, Abschnitt „Team CLIs and coding agents“. Statt der bisherigen Beispielzeile:

> Security checks: use `appsec-cli` (see `appsec-cli --help`) and call tools as `appsec-cli --format json TOOL …`. Model-based tools send source code to a model; run them only when the user asks for one.

„run them only when the user asks for one“ statt „ask before“, damit der Agent nicht noch einmal fragt, wenn der Nutzer das Tool gerade ausdrücklich verlangt hat. Ohne „read `status` and `summary`“, weil das JSON sich selbst erklärt.

## Reihenfolge der Nachträge

5 → 6, je ein Commit auf `main` nach grünem `make test`, ohne Push.

## Umsetzung

| Punkt | Commit |
| --- | --- |
| 4. Skill streichen | appsec-cli `fe74c98` |
| 2. `threshold_reached` | appsec-cli `fc07804` |
| 3. Beschreibungen | appsec-cli `ab06348` |
| 1a. Engine | appsec-tools `bb7345c` |
| 1b. Pin, Python 3.12 | appsec-cli `a4b6a9d` |
| 5. Hilfe der Wrapper-Tools | appsec-cli `0e71d14` |
| 6. Beispielzeilen für AGENTS.md | appsec-cli `9af1ef7` |

Abweichungen vom Plan:

- 1a überspringt Sonderdateien nur in einem Git-Checkout. Außerhalb von Git bleibt die bestehende Regel der Engine (`test_symlinks_and_fifo_fail_closed`).
- 1a verwendet den Grund „excluded or unsupported“, weil jeder andere Grund den Lauf unvollständig macht.
- Der Test zu 1a simuliert die Sandbox per Mock, denn Git listet eine echte FIFO nicht.
- 2 hängt die Diagnose nur bei `--format json` an. `ui.table` musste nicht geändert werden.
- Für den Fall Exit 3 hat das Test-Plugin in `tests/plugin_fixture.py` den Schalter `--partial` bekommen.
- Der Packaging-Test von appsec-tools lief mit dem Python 3.12 aus `.venv` von appsec-cli, weil dem System-Python 3.12 `distutils` fehlt.
- `docs/implementation-plan.md` ist nachgezogen: Python 3.12, Hinweis auf `--format json` in der Hilfe der Wrapper, `threshold_reached`, Modellaufrufe in der Kurzbeschreibung.

Noch offen:

- Push von appsec-tools `bb7345c`. Bis dahin funktionieren `make install` und `make test` nur mit `ENGINE_SOURCES="appsec-security-score=PFAD"` und einem lokalen Checkout von appsec-tools.
- Bestehende pipx-Installationen auf Python 3.10 müssen mit 3.12 neu aufgesetzt werden.
- Die Bilder der Startseite (`docs/images/start-page*.png`) zeigen noch die alten Beschreibungen.
