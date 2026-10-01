# Richtlinien für Beiträge

[English version](CONTRIBUTING.md)

Danke, dass du zu ZenitiumDNS beitragen möchtest! Beiträge verbessern das Projekt und helfen allen, die es nutzen. Bitte lies die folgenden Richtlinien, bevor du Code, Dokumentation oder andere Inhalte einreichst.

## Lizenz
- Das Projekt steht unter der GNU General Public License v3 (GPLv3).
- Beiträge werden unter der GPLv3 in das Projekt aufgenommen. So können alle den Code zu denselben Bedingungen frei nutzen, verändern und weitergeben.

## Beiträge einreichen
Mit dem Einreichen eines Beitrags bestätigst du:
- Du bist der ursprüngliche Urheber der Arbeit oder berechtigt, sie einzureichen.
- Du bist damit einverstanden, dass dein Beitrag als Teil des Projekts unter der GPLv3 lizenziert wird.

## Richtlinien
- Vorhandene Urheberrechts- und Lizenzhinweise in bestehenden Quelldateien bleiben unverändert.
- Die Solution muss vor dem Einreichen fehlerfrei bauen.
- Neue oder geänderte Texte der Weboberfläche werden auf Deutsch geschrieben und brauchen eine englische Übersetzung in `src/ZenitiumDns.Core/www/lang/en.json`; `python3 tools/i18n.py check` muss durchlaufen. Texte auf dem Server verwenden `Lang.T("Deutsch", "English")`, Meldungen, die gespeichert und später angezeigt werden, `Lang.L("Deutsch", "English")`.
- Quelldateien enthalten außer dem Urheberrechts- und Lizenzkopf keine Kommentare.
- Web-Dateien werden lesbar geschrieben; Debian-Paket und Container-Image verkleinern sie mit `tools/WebMinifier`.
