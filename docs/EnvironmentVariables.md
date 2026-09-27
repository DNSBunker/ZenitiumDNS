# Umgebungsvariablen von ZenitiumDNS

ZenitiumDNS unterstützt die folgenden Umgebungsvariablen. Ihre Werte werden bei jedem Start direkt aus der Umgebung gelesen.

Hinweis: Änderungen an diesen Variablen werden erst nach einem Neustart des DNS-Servers wirksam. Beim Debian-Paket lassen sie sich in der Datei `/etc/default/zenitiumdns` setzen.

| Umgebungsvariable                                 | Typ     | Beschreibung                                                                                                                             |
| ------------------------------------------------- | ------- | -----------------------------------------------------------------------------------------------------------------------------------------|
| DNS_SERVER_WEB_SERVICE_WWW_FOLDER_PATH            | String  | Pfad zu dem Ordner, der als www-Stammordner des Webdienstes verwendet wird. Ist die Variable nicht gesetzt oder existiert der Ordner nicht, wird der Standardordner verwendet. |
| DNS_SERVER_UPDATE_CHECK_URL                       | String  | Adresse der GitHub-API für das neueste Release, gegen das die Update-Prüfung vergleicht. Standard ist `https://api.github.com/repos/DNSBunker/ZenitiumDNS-DE/releases/latest`. Ein leerer Wert schaltet die Update-Prüfung ab. Erwartet wird das Antwortformat der GitHub-Releases-API mit Tags der Form `v15.5.1-3`. |
| DNS_SERVER_ADMIN_PASSWORD_FILE                    | String  | Pfad zu einer Datei mit dem Passwort des Benutzers `admin` im Klartext. Wird nur beim allerersten Start ausgewertet, wenn noch keine Benutzerkonfiguration existiert. Das Debian-Paket nutzt diese Variable für das zufällige Erstpasswort. |
| DNS_SERVER_BUNDLED_APPS_PATH                      | String  | Ordner mit mitgelieferten DNS-Apps als ZIP-Dateien. Standard ist `/usr/share/zenitiumdns/apps`. Beim Start werden fehlende Apps deaktiviert installiert und vorhandene aktualisiert, wenn sich ihre ZIP-Datei geändert hat. Die Konfiguration einer App bleibt dabei erhalten. |
