# Contribution guidelines

[Deutsche Version](CONTRIBUTING.de.md)

Thank you for wanting to contribute to ZenitiumDNS! Contributions improve the project and help everyone who uses it. Please read the following guidelines before submitting code, documentation or other content.

## License
- The project is licensed under the GNU General Public License v3 (GPLv3).
- Contributions are accepted into the project under the GPLv3. This way everyone can freely use, modify and distribute the code under the same terms.

## Submitting contributions
By submitting a contribution you confirm:
- You are the original author of the work or are entitled to submit it.
- You agree that your contribution is licensed under the GPLv3 as part of the project.

## Guidelines
- Existing copyright and license notices in existing source files remain unchanged.
- The solution must build without errors before submitting.
- New or changed texts in the web interface are written in German and need an English translation in `src/ZenitiumDns.Core/www/lang/en.json`; `python3 tools/i18n.py check` must pass. Server-side texts use `Lang.T("German", "English")`, or `Lang.L("German", "English")` for messages that are stored and shown later.
- Source files contain no comments apart from the copyright and license header.
- Web files are written readable; the Debian package and the container image minify them with `tools/WebMinifier`.
