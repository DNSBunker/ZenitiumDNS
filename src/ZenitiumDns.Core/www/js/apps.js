/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)
Copyright (C) 2026  xRuffKez

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

var appConfigState = null;

var APP_CONFIG_LABELS = {
    enableBlocking: "Blockieren aktiviert",
    blockingAnswerTtl: "TTL der Blockierantwort (Sekunden)",
    blockListUrlUpdateIntervalHours: "Aktualisierung der Listen (Stunden)",
    blockListUrlUpdateIntervalMinutes: "Aktualisierung der Listen (zusätzliche Minuten)",
    localEndPointGroupMap: "Gruppe je lokalem Endpunkt",
    networkGroupMap: "Gruppe je Client-Netz",
    groups: "Gruppen",
    name: "Name",
    allowTxtBlockingReport: "Blockiergrund per TXT-Abfrage abrufbar",
    blockAsNxDomain: "Als NXDOMAIN blockieren",
    blockingAddresses: "Blockieradressen",
    allowed: "Erlaubte Domains",
    blocked: "Blockierte Domains",
    allowListUrls: "URLs von Allowlisten",
    blockListUrls: "URLs von Blocklisten",
    allowedRegex: "Erlaubte Domains (regulärer Ausdruck)",
    blockedRegex: "Blockierte Domains (regulärer Ausdruck)",
    regexAllowListUrls: "URLs von Regex-Allowlisten",
    regexBlockListUrls: "URLs von Regex-Blocklisten",
    adblockListUrls: "URLs von Adblock-Listen",
    url: "URL",
    appPreference: "Reihenfolge (kleiner wird zuerst ausgeführt)",
    enableForwarding: "Weiterleitung aktiviert",
    proxyServers: "Proxyserver",
    type: "Typ",
    proxyAddress: "Proxy-Adresse",
    proxyPort: "Proxy-Port",
    proxyUsername: "Benutzername",
    proxyPassword: "Passwort",
    forwarders: "Forwarder",
    proxy: "Proxy",
    dnssecValidation: "DNSSEC-Validierung",
    forwarderProtocol: "Protokoll",
    forwarderAddresses: "Adressen",
    forwardings: "Weiterleitungen",
    domains: "Domains",
    adguardUpstreams: "AdGuard-Upstreams",
    configFile: "Konfigurationsdatei",
    enableDns64: "DNS64 aktiviert",
    dns64PrefixMap: "DNS64-Präfix je IPv4-Netz",
    excludedIpv6: "Ausgenommene IPv6-Netze",
    enableProtection: "Schutz aktiviert",
    bypassNetworks: "Ausgenommene Client-Netze",
    privateNetworks: "Private Netze",
    privateDomains: "Private Domains",
    dropMalformedRequests: "Fehlerhafte Anfragen verwerfen",
    allowedNetworks: "Erlaubte Client-Netze",
    blockedNetworks: "Blockierte Client-Netze",
    allowedLocalEndPoints: "Erlaubte lokale Endpunkte",
    blockedQuestions: "Blockierte Anfragen",
    blockZone: "Ganze Zone blockieren",
    maxQueueSize: "Maximale Warteschlange",
    enableEdnsLogging: "EDNS-Daten mitschreiben",
    file: "Datei",
    path: "Pfad",
    enabled: "Aktiviert",
    http: "HTTP",
    endpoint: "Endpunkt",
    headers: "HTTP-Header",
    syslog: "Syslog",
    address: "Adresse",
    port: "Port",
    protocol: "Protokoll",
    enableLogging: "Protokollierung aktiviert",
    maxLogDays: "Aufbewahrung in Tagen (0 = unbegrenzt)",
    maxLogRecords: "Maximale Einträge (0 = unbegrenzt)",
    databaseName: "Datenbankname",
    connectionString: "Verbindungszeichenfolge",
    enableVacuum: "Datenbank regelmäßig verdichten (VACUUM)",
    useInMemoryDb: "Datenbank nur im Arbeitsspeicher",
    sqliteDbPath: "Pfad der SQLite-Datei"
};

function refreshApps() {
    var divViewAppsLoader = $("#divViewAppsLoader");
    var divViewApps = $("#divViewApps");

    divViewApps.hide();
    divViewAppsLoader.show();

    HTTPRequest({
        url: "api/apps/list",
        token: sessionData.token,
        success: function (responseJSON) {
            var apps = responseJSON.response.apps;
            var tableHtmlRows = "";

            for (var i = 0; i < apps.length; i++) {
                tableHtmlRows += getAppRowHtml(apps[i]);
            }

            $("#tableAppsBody").html(tableHtmlRows);
            updateAppsFooterCount();

            divViewAppsLoader.hide();
            divViewApps.show();
        },
        error: function () {
            divViewAppsLoader.hide();
            divViewApps.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divViewAppsLoader
    });
}

function getAppRowId(appName) {
    return btoa(appName).replace(/=/g, "");
}

function getAppRowHtml(app) {
    var name = app.name;
    var version = app.version;

    var dnsAppsTable = null;

    if (app.dnsApps.length > 0) {
        dnsAppsTable = "<table class=\"table\" style=\"margin-bottom: 10px; background: transparent;\"><thead><th>Klassenpfad</th><th>Beschreibung</th></thead><tbody>";

        for (var j = 0; j < app.dnsApps.length; j++) {
            var labels = "";
            var description = null;

            if (app.dnsApps[j].isAppRecordRequestHandler) {
                labels += "<span class=\"label label-info\" style=\"margin-right: 4px;\">APP-Eintrag</span>";
                description = "<p>" + htmlEncode(app.dnsApps[j].description).replace(/\n/g, "<br />") + "</p>" + (app.dnsApps[j].recordDataTemplate == null ? "" : "<div><b>Vorlage für die Daten</b><pre>" + htmlEncode(app.dnsApps[j].recordDataTemplate) + "</pre></div>");
            }

            if (app.dnsApps[j].isRequestController)
                labels += "<span class=\"label label-info\" style=\"margin-right: 4px;\">Zugriffskontrolle</span>";

            if (app.dnsApps[j].isAuthoritativeRequestHandler)
                labels += "<span class=\"label label-info\" style=\"margin-right: 4px;\">Lokale Antworten</span>";

            if (app.dnsApps[j].isRequestBlockingHandler)
                labels += "<span class=\"label label-info\" style=\"margin-right: 4px;\">Blockierung</span>";

            if (app.dnsApps[j].isQueryLogger)
                labels += "<span class=\"label label-info\" style=\"margin-right: 4px;\">Abfrage-Protokollierung</span>";

            if (app.dnsApps[j].isQueryLogs)
                labels += "<span class=\"label label-info\" style=\"margin-right: 4px;\">Abfrageprotokoll</span>";

            if (app.dnsApps[j].isPostProcessor)
                labels += "<span class=\"label label-info\" style=\"margin-right: 4px;\">Nachbearbeitung</span>";

            if (labels == "")
                labels = "<span class=\"label label-info\" style=\"margin-right: 4px;\">Allgemein</span>";

            if (description == null)
                description = htmlEncode(app.dnsApps[j].description).replace(/\n/g, "<br />");

            dnsAppsTable += "<tr><td>" + htmlEncode(app.dnsApps[j].classPath) + "</br>" + labels + "</td><td>" + description + "</td></tr>";
        }

        dnsAppsTable += "</tbody></table>"
    }

    var id = getAppRowId(name);
    var tableHtmlRow = "<tr id=\"trApp" + id + "\"><td><div><span style=\"font-weight: bold; font-size: 16px;\">" + htmlEncode(getAppDisplayName(name)) + "</span>" + (getAppDisplayName(name) == name ? "" : " <span class=\"text-muted\" style=\"font-size: 12px;\">" + htmlEncode(name) + "</span>") + "<br /><span class=\"label label-primary\">Version " + htmlEncode(version) + "</span>" + (app.enabled ? " <span class=\"label label-success\">Aktiv</span>" : " <span class=\"label label-default\">Deaktiviert</span>") + "</div>";

    if (app.description != null)
        tableHtmlRow += "<div style=\"margin-top: 10px;\">" + htmlEncode(app.description).replace(/\n/g, "<br />") + "</div>";

    if (dnsAppsTable != null) {
        tableHtmlRow += "<div style=\"margin-top: 10px;\"><a href=\"#" + id + "\" class=\"collapsed\" data-toggle=\"collapse\" aria-expanded=\"false\" aria-controls=\"" + id + "\">Details <span class=\"glyphicon glyphicon-chevron-down\" style=\"font-size: 10px;\" aria-hidden=\"true\"></span></a>";
        tableHtmlRow += "<div id=\"" + id + "\" class=\"collapse\" aria-expanded=\"false\">";
        tableHtmlRow += dnsAppsTable;
        tableHtmlRow += "</div></div>";
    }

    tableHtmlRow += "</td>";
    tableHtmlRow += "<td><button type=\"button\" data-id=\"" + id + "\" class=\"btn " + (app.enabled ? "btn-default" : "btn-primary") + "\" style=\"font-size: 12px; padding: 2px 0px; width: 108px; margin-bottom: 6px; display: block;\" data-name=\"" + htmlEncode(name) + "\" onclick=\"setAppEnabled(this, $(this).attr('data-name'), " + (app.enabled ? "false" : "true") + ");\" data-loading-text=\"Bitte warten...\">" + (app.enabled ? "Deaktivieren" : "Aktivieren") + "</button>";
    tableHtmlRow += "<button type=\"button\" class=\"btn btn-default\" style=\"font-size: 12px; padding: 2px 0px; width: 108px; margin-bottom: 6px; display: block;\" data-name=\"" + htmlEncode(name) + "\" onclick=\"showAppConfigModal(this, $(this).attr('data-name'));\" data-loading-text=\"Lade...\">Konfigurieren</button></td></tr>";

    return tableHtmlRow;
}

function setAppEnabled(objBtn, appName, enabled) {
    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/apps/" + (enabled ? "enable" : "disable") + "?name=" + encodeURIComponent(appName),
        token: sessionData.token,
        success: function (responseJSON) {
            $("#trApp" + btn.attr("data-id")).replaceWith(getAppRowHtml(responseJSON.response.updatedApp));

            showAlert("success", enabled ? "App aktiviert" : "App deaktiviert", "Die App '" + appName + "' wurde " + (enabled ? "aktiviert." : "deaktiviert."));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function updateAppsFooterCount() {
    var totalApps = $("#tableApps >tbody >tr").length;
    if (totalApps > 0)
        $("#tableAppsFooter").html("<tr><td colspan=\"2\"><b>Apps gesamt: " + totalApps + "</b></td></tr>");
    else
        $("#tableAppsFooter").html("<tr><td colspan=\"2\" align=\"center\">Keine Apps vorhanden</td></tr>");
}

function getAppConfigLabel(key) {
    if (APP_CONFIG_LABELS.hasOwnProperty(key))
        return APP_CONFIG_LABELS[key];

    var words = String(key).replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/[_-]+/g, " ").trim();
    if (words.length === 0)
        return String(key);

    return words.charAt(0).toUpperCase() + words.slice(1);
}

function isAppConfigPlainObject(value) {
    return (value !== null) && (typeof value === "object") && !Array.isArray(value);
}

function isAppConfigMap(key, value) {
    if (!isAppConfigPlainObject(value))
        return false;

    if (/Map$/.test(key) || (key === "headers"))
        return true;

    var keys = Object.keys(value);
    for (var i = 0; i < keys.length; i++) {
        if (/[.:\/\s]/.test(keys[i]))
            return true;
    }

    return false;
}

function isAppConfigPrimitiveArray(value) {
    for (var i = 0; i < value.length; i++) {
        if ((value[i] !== null) && (typeof value[i] === "object"))
            return false;
    }

    return true;
}

function getAppConfigTemplate(value) {
    if (Array.isArray(value))
        return [];

    if (isAppConfigPlainObject(value)) {
        var template = {};
        var keys = Object.keys(value);

        for (var i = 0; i < keys.length; i++)
            template[keys[i]] = getAppConfigTemplate(value[keys[i]]);

        return template;
    }

    switch (typeof value) {
        case "boolean":
            return false;

        case "number":
            return 0;

        case "string":
            return "";

        default:
            return null;
    }
}

function markAppConfigError(input, message) {
    input.closest(".app-config-field").addClass("has-error");
    input.attr("data-error", message);
    appConfigState.errors[appConfigState.errorId(input)] = message;
}

function clearAppConfigError(input) {
    input.closest(".app-config-field").removeClass("has-error");
    input.removeAttr("data-error");
    delete appConfigState.errors[appConfigState.errorId(input)];
}

function createAppConfigField(label, key) {
    var field = $("<div class=\"app-config-field\"></div>");
    var labelElement = $("<label class=\"app-config-label\"></label>").text(label);

    if (key !== null)
        labelElement.append($("<span class=\"app-config-key\"></span>").text(key));

    field.append(labelElement);
    return field;
}

function renderAppConfigPrimitiveInput(parent, key, value, onChange) {
    var input;

    if (typeof value === "boolean") {
        input = $("<input type=\"checkbox\">").prop("checked", value);
        input.on("change", function () {
            onChange($(this).prop("checked"));
        });

        return input;
    }

    if (typeof value === "number") {
        input = $("<input type=\"number\" step=\"any\" class=\"form-control\">").val(value);
        input.on("input", function () {
            var text = $(this).val().trim();
            var number = Number(text);

            if ((text === "") || !isFinite(number)) {
                markAppConfigError($(this), "Bitte eine Zahl eingeben.");
            }
            else {
                clearAppConfigError($(this));
                onChange(number);
            }
        });

        return input;
    }

    var nullable = (value === null);
    var isSecret = /password|secret|token/i.test(String(key));

    input = $("<input class=\"form-control\" spellcheck=\"false\">").attr("type", isSecret ? "password" : "text").val(value === null ? "" : value);

    if (nullable)
        input.attr("placeholder", "leer");

    input.on("input", function () {
        var text = $(this).val();
        onChange((nullable && (text === "")) ? null : text);
    });

    return input;
}

function renderAppConfigPrimitiveList(parent, key, value) {
    var numeric = (value.length > 0);

    for (var i = 0; i < value.length; i++) {
        if (typeof value[i] !== "number") {
            numeric = false;
            break;
        }
    }

    var textarea = $("<textarea class=\"form-control\" spellcheck=\"false\"></textarea>");
    textarea.attr("rows", Math.min(Math.max(value.length + 1, 3), 12));
    textarea.val(value.map(function (item) { return item === null ? "" : String(item); }).join("\n"));

    textarea.on("input", function () {
        var lines = $(this).val().split("\n").map(function (line) { return line.trim(); }).filter(function (line) { return line.length > 0; });

        if (numeric) {
            var numbers = [];

            for (var j = 0; j < lines.length; j++) {
                var number = Number(lines[j]);
                if (!isFinite(number)) {
                    markAppConfigError($(this), "Jede Zeile muss eine Zahl sein.");
                    return;
                }

                numbers.push(number);
            }

            clearAppConfigError($(this));
            parent[key] = numbers;
        }
        else {
            parent[key] = lines;
        }
    });

    return textarea;
}

function renderAppConfigMap(parent, key, container) {
    var map = parent[key];
    var entries = Object.keys(map).map(function (entryKey) { return { key: entryKey, value: map[entryKey] }; });
    var nullable = false;

    for (var i = 0; i < entries.length; i++) {
        if (entries[i].value === null)
            nullable = true;
    }

    var table = $("<table class=\"table table-condensed app-config-map\"><thead><tr><th>Schlüssel</th><th>Wert</th><th></th></tr></thead><tbody></tbody></table>");
    var tbody = table.find("tbody");

    function commit() {
        var result = {};

        for (var j = 0; j < entries.length; j++) {
            if (entries[j].key.length > 0)
                result[entries[j].key] = entries[j].value;
        }

        parent[key] = result;
    }

    function addRow(entry) {
        var row = $("<tr></tr>");
        var keyInput = $("<input type=\"text\" class=\"form-control\" spellcheck=\"false\">").val(entry.key);
        var valueInput;

        keyInput.on("input", function () {
            entry.key = $(this).val().trim();
            commit();
        });

        if ((entry.value !== null) && (typeof entry.value === "object")) {
            valueInput = $("<textarea class=\"form-control\" rows=\"2\" spellcheck=\"false\"></textarea>").val(JSON.stringify(entry.value));
            valueInput.on("input", function () {
                try {
                    entry.value = JSON.parse($(this).val());
                    clearAppConfigError($(this));
                    commit();
                }
                catch (e) {
                    markAppConfigError($(this), "Bitte gültiges JSON eingeben.");
                }
            });
        }
        else {
            valueInput = $("<input type=\"text\" class=\"form-control\" spellcheck=\"false\">").val(entry.value === null ? "" : entry.value);

            if (nullable)
                valueInput.attr("placeholder", "leer");

            valueInput.on("input", function () {
                var text = $(this).val();

                if (typeof entry.value === "number") {
                    var number = Number(text);
                    if ((text.trim() === "") || !isFinite(number)) {
                        markAppConfigError($(this), "Bitte eine Zahl eingeben.");
                        return;
                    }

                    clearAppConfigError($(this));
                    entry.value = number;
                }
                else {
                    entry.value = (nullable && (text === "")) ? null : text;
                }

                commit();
            });
        }

        var removeButton = $("<button type=\"button\" class=\"btn btn-default btn-xs\">Entfernen</button>");
        removeButton.on("click", function () {
            entries.splice(entries.indexOf(entry), 1);
            row.find("input, textarea").each(function () { clearAppConfigError($(this)); });
            row.remove();
            commit();
        });

        row.append($("<td class=\"app-config-field\"></td>").append(keyInput));
        row.append($("<td class=\"app-config-field\"></td>").append(valueInput));
        row.append($("<td></td>").append(removeButton));
        tbody.append(row);
    }

    for (var k = 0; k < entries.length; k++)
        addRow(entries[k]);

    var addButton = $("<button type=\"button\" class=\"btn btn-default btn-xs\">Zeile hinzufügen</button>");
    addButton.on("click", function () {
        var entry = { key: "", value: nullable ? null : "" };
        entries.push(entry);
        addRow(entry);
    });

    container.append(table);
    container.append(addButton);
}

function renderAppConfigObjectList(parent, key, container) {
    var list = parent[key];
    var template = null;

    for (var i = 0; i < list.length; i++) {
        if (isAppConfigPlainObject(list[i])) {
            template = getAppConfigTemplate(list[i]);
            break;
        }
    }

    var items = $("<div class=\"app-config-items\"></div>");

    function render() {
        items.find("input, textarea").each(function () { clearAppConfigError($(this)); });
        items.empty();

        for (var j = 0; j < list.length; j++)
            items.append(renderItem(j));
    }

    function renderItem(index) {
        var item = list[index];
        var card = $("<div class=\"app-config-item\"></div>");
        var head = $("<div class=\"app-config-item-head\"></div>");
        var title = getAppConfigLabel(key) + " " + (index + 1);

        if (isAppConfigPlainObject(item) && (typeof item.name === "string") && (item.name.length > 0))
            title = item.name;

        head.append($("<span class=\"app-config-item-title\"></span>").text(title));

        var removeButton = $("<button type=\"button\" class=\"btn btn-default btn-xs\">Entfernen</button>");
        removeButton.on("click", function () {
            list.splice(index, 1);
            render();
        });

        head.append(removeButton);
        card.append(head);

        if (isAppConfigPlainObject(item)) {
            renderAppConfigObject(item, card);
        }
        else {
            var holder = { value: item };
            var field = createAppConfigField("Wert", null);
            field.append(renderAppConfigPrimitiveInput(holder, "value", item, function (newValue) { list[index] = newValue; }));
            card.append(field);
        }

        return card;
    }

    render();
    container.append(items);

    var addButton = $("<button type=\"button\" class=\"btn btn-default btn-xs\">Eintrag hinzufügen</button>");
    addButton.on("click", function () {
        list.push(template === null ? "" : JSON.parse(JSON.stringify(template)));
        render();
    });

    container.append(addButton);
}

function renderAppConfigProperty(parent, key, container) {
    var value = parent[key];
    var field = createAppConfigField(getAppConfigLabel(key), key);

    if (Array.isArray(value)) {
        if (isAppConfigPrimitiveArray(value)) {
            field.append(renderAppConfigPrimitiveList(parent, key, value));
            field.append($("<div class=\"app-config-hint\"></div>").text("Ein Eintrag pro Zeile."));
        }
        else {
            field.addClass("app-config-group");
            renderAppConfigObjectList(parent, key, field);
        }
    }
    else if (isAppConfigMap(key, value)) {
        field.addClass("app-config-group");
        renderAppConfigMap(parent, key, field);
    }
    else if (isAppConfigPlainObject(value)) {
        field.addClass("app-config-group");
        renderAppConfigObject(value, field);
    }
    else if (typeof value === "boolean") {
        field.empty();
        field.addClass("app-config-check");

        var label = $("<label></label>");
        label.append(renderAppConfigPrimitiveInput(parent, key, value, function (newValue) { parent[key] = newValue; }));
        label.append(document.createTextNode(" " + getAppConfigLabel(key)));
        label.append($("<span class=\"app-config-key\"></span>").text(key));
        field.append(label);
    }
    else {
        field.append(renderAppConfigPrimitiveInput(parent, key, value, function (newValue) { parent[key] = newValue; }));
    }

    container.append(field);
}

function renderAppConfigObject(obj, container) {
    var keys = Object.keys(obj);

    for (var i = 0; i < keys.length; i++)
        renderAppConfigProperty(obj, keys[i], container);
}

function renderAppConfigForm() {
    var form = $("#divAppConfigForm");
    form.empty();

    appConfigState.errors = {};

    if (!isAppConfigPlainObject(appConfigState.model)) {
        form.append($("<p class=\"app-config-empty\"></p>").text("Diese Konfiguration lässt sich nur im JSON-Modus bearbeiten."));
        return;
    }

    if (Object.keys(appConfigState.model).length === 0) {
        form.append($("<p class=\"app-config-empty\"></p>").text("Die App hat keine Einstellungen."));
        return;
    }

    renderAppConfigObject(appConfigState.model, form);
}

function parseAppConfigText(text) {
    if (text == null)
        return { ok: true, value: {} };

    text = String(text).replace(/^﻿/, "");

    if (text.trim().length === 0)
        return { ok: true, value: {} };

    try {
        return { ok: true, value: JSON.parse(text) };
    }
    catch (e) {
        return { ok: false, error: e.message };
    }
}

function setAppConfigMode(mode) {
    var divAppConfigAlert = $("#divAppConfigAlert");

    if (mode === appConfigState.mode)
        return true;

    if (mode === "json") {
        if (Object.keys(appConfigState.errors).length > 0) {
            showAlert("warning", "Ungültige Eingabe", "Bitte zuerst die markierten Felder korrigieren.", divAppConfigAlert);
            return false;
        }

        $("#txtAppConfig").val(JSON.stringify(appConfigState.model, null, 2));
        $("#divAppConfigForm").hide();
        $("#divAppConfigJson").show();
    }
    else {
        var parsed = parseAppConfigText($("#txtAppConfig").val());
        if (!parsed.ok) {
            showAlert("warning", "Ungültiges JSON", "Das Formular lässt sich erst öffnen, wenn das JSON gültig ist: " + parsed.error, divAppConfigAlert);
            return false;
        }

        appConfigState.model = parsed.value;
        renderAppConfigForm();

        $("#divAppConfigJson").hide();
        $("#divAppConfigForm").show();
    }

    divAppConfigAlert.html("");
    appConfigState.mode = mode;

    $("#btnAppConfigModeForm").toggleClass("active", mode === "form").attr("aria-pressed", mode === "form");
    $("#btnAppConfigModeJson").toggleClass("active", mode === "json").attr("aria-pressed", mode === "json");

    return true;
}

function showAppConfigModal(objBtn, appName) {
    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/apps/config/get?name=" + encodeURIComponent(appName),
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");

            var parsed = parseAppConfigText(responseJSON.response.config);
            var errorCounter = 0;

            appConfigState = {
                name: appName,
                mode: null,
                model: parsed.ok ? parsed.value : null,
                errors: {},
                errorId: function (input) {
                    var id = input.attr("data-error-id");
                    if (id == null) {
                        id = "e" + (++errorCounter);
                        input.attr("data-error-id", id);
                    }

                    return id;
                }
            };

            $("#divAppConfigAlert").html("");
            $("#lblAppConfigName").text(getAppDisplayName(appName));
            $("#txtAppConfig").val(responseJSON.response.config == null ? "" : String(responseJSON.response.config).replace(/^﻿/, ""));
            $("#btnAppConfig").button("reset");

            if (parsed.ok && isAppConfigPlainObject(parsed.value)) {
                appConfigState.mode = "json";
                setAppConfigMode("form");
            }
            else {
                appConfigState.mode = "form";
                setAppConfigMode("json");

                if (!parsed.ok)
                    showAlert("warning", "Kein gültiges JSON", "Die Konfiguration ist kein gültiges JSON und lässt sich nur im JSON-Modus bearbeiten: " + parsed.error, $("#divAppConfigAlert"));
            }

            $("#modalAppConfig").modal("show");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function saveAppConfig() {
    var divAppConfigAlert = $("#divAppConfigAlert");
    var config;

    if (appConfigState.mode === "form") {
        var errorIds = Object.keys(appConfigState.errors);
        if (errorIds.length > 0) {
            showAlert("warning", "Ungültige Eingabe", appConfigState.errors[errorIds[0]] + " Die betroffenen Felder sind markiert.", divAppConfigAlert);
            $("#divAppConfigForm .has-error input, #divAppConfigForm .has-error textarea").first().trigger("focus");
            return;
        }

        config = JSON.stringify(appConfigState.model, null, 2);
    }
    else {
        config = $("#txtAppConfig").val();

        var parsed = parseAppConfigText(config);
        if (!parsed.ok) {
            showAlert("warning", "Ungültiges JSON", "Die Konfiguration wurde nicht gespeichert: " + parsed.error, divAppConfigAlert);
            $("#txtAppConfig").trigger("focus");
            return;
        }
    }

    var appName = appConfigState.name;
    var btn = $("#btnAppConfig");
    btn.button("loading");

    HTTPRequest({
        url: "api/apps/config/set?name=" + encodeURIComponent(appName),
        token: sessionData.token,
        method: "POST",
        data: "config=" + encodeURIComponent(config),
        processData: false,
        success: function (responseJSON) {
            $("#modalAppConfig").modal("hide");

            showAlert("success", "Konfiguration gespeichert", "Die Konfiguration der App '" + appName + "' wurde gespeichert und neu geladen.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalAppConfig").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divAppConfigAlert
    });
}
