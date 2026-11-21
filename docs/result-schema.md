# JSON für CI und Skills

`appsec-cli schema` gibt das gemeinsame JSON Schema v1 aus. `appsec-cli --format json tools describe NAME` liefert unter `definitions` Parameter, Ausgabeformate und das zu jedem Befehlsweg gehörende `data_schema`. Die Discovery mit `tools list` funktioniert ohne Modellanmeldung.

Jedes Laufergebnis hat `schema_version`, `tool`, `status` und `summary`. Je nach Befehl kommen `target`, `run`, `data`, `findings`, `counts` und `diagnostics` hinzu. Ein kompatibler Leser prüft die Version, liest bekannte Felder und toleriert Erweiterungen. Hier liefert ein Inventar ausschließlich Fachdaten:

```json
{"schema_version":1,"tool":"team-inventory","status":"ok","summary":"Inventory complete.","data":{"components":12}}
```

`data` kann ein beliebiger JSON-Wert sein. Eine leere Finding-Liste steht für null ermittelte Findings. Ohne dieses Feld macht der Befehl keine Finding-Aussage. Findings enthalten mindestens `rule`, `title` und `severity`. Bei einer abgeschlossenen Ausführung enthält `run` CLI-, Plugin- und Toolversion, Startzeit und Dauer. Für einen reinen Adapter bezeichnet die Toolversion die Adapterversion.

| Exit | Bedeutung |
|---|---|
| 0 | Lauf erfolgreich, Finding-Schwelle nicht erreicht |
| 1 | Lauf erfolgreich, Schwelle erreicht |
| 2 | Bedienfehler, Erklärung auf stderr |
| 3 | Lauf unvollständig oder fehlgeschlagen, siehe `status` und `diagnostics` |
| 130 | Benutzerabbruch |

`--min-severity` und `--limit` ändern die dargestellte Finding-Liste. Counts und Exit-Code beruhen auf allen Findings. `--fail-on never` lässt Laufzeitfehler und unvollständige Prüfungen weiterhin mit 3 enden. Für Finding-Befehle steht auch `--format sarif` bereit. Ein abgeschnittener Bericht oder eine fehlende JSON-Ausgabe ist ein Fehler des Aufrufs.
