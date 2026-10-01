# ZenitiumDNS environment variables

[Deutsche Version](EnvironmentVariables.de.md)

ZenitiumDNS supports the following environment variables. Their values are read directly from the environment on every start.

Note: Changes to these variables only take effect after the DNS server is restarted. With the Debian package they can be set in the file `/etc/default/zenitiumdns`.

| Environment variable                              | Type    | Description                                                                                                                              |
| ------------------------------------------------- | ------- | -----------------------------------------------------------------------------------------------------------------------------------------|
| DNS_SERVER_WEB_SERVICE_WWW_FOLDER_PATH            | String  | Path to the folder used as the www root folder of the web service. If the variable is not set or the folder does not exist, the default folder is used. |
| DNS_SERVER_UPDATE_CHECK_URL                       | String  | Address of the GitHub API for the latest release that the update check compares against. The default is `https://api.github.com/repos/DNSBunker/ZenitiumDNS/releases/latest`. An empty value turns the update check off. The response format of the GitHub releases API with tags of the form `v15.5.1-3` is expected. |
| DNS_SERVER_ADMIN_PASSWORD_FILE                    | String  | Path to a file containing the password of the user `admin` in plain text. Only evaluated on the very first start, when no user configuration exists yet. The Debian package and the container image use this variable for the random initial password. If the file lies directly in the configuration folder, the server deletes it once the password of `admin` no longer matches or the user `admin` was deleted or renamed. |
| DNS_SERVER_BUNDLED_APPS_PATH                      | String  | Folder with bundled DNS apps as ZIP files. The default is `/usr/share/zenitiumdns/apps`. On start, missing apps are installed disabled and existing ones are updated if their ZIP file has changed. The configuration of an app is preserved. |
