/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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

            if (apps.length > 0)
                $("#tableAppsFooter").html("<tr><td colspan=\"3\"><b>Apps gesamt: " + apps.length + "</b></td></tr>");
            else
                $("#tableAppsFooter").html("<tr><td colspan=\"3\" align=\"center\">Keine Apps installiert</td></tr>");

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
    var updateVersion = app.updateVersion;
    var updateUrl = app.updateUrl;
    var updateAvailable = app.updateAvailable;

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
    var tableHtmlRow = "<tr id=\"trApp" + id + "\"><td><div><span style=\"font-weight: bold; font-size: 16px;\">" + htmlEncode(name) + "</span><br /><span id=\"trAppVersion" + id + "\" class=\"label label-primary\">Version " + htmlEncode(version) + "</span> <span id=\"trAppUpdateVersion" + id + "\" class=\"label label-warning\" style=\"" + (updateAvailable ? "" : "display: none;") + "\">Update " + htmlEncode(updateVersion) + "</span>" + (app.enabled ? "" : " <span class=\"label label-default\">Deaktiviert</span>") + "</div>";

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
    tableHtmlRow += "<button type=\"button\" class=\"btn btn-default\" style=\"font-size: 12px; padding: 2px 0px; width: 108px; margin-bottom: 6px; display: block;\" data-name=\"" + htmlEncode(name) + "\" onclick=\"showAppConfigModal(this, $(this).attr('data-name'));\" data-loading-text=\"Lade...\">Konfiguration</button>";
    tableHtmlRow += "<button type=\"button\" class=\"btn btn-warning\" style=\"font-size: 12px; padding: 2px 0px; width: 108px; margin-bottom: 6px; display: block;\" data-name=\"" + htmlEncode(name) + "\" onclick=\"showUpdateAppModal($(this).attr('data-name'));\">Aktualisieren</button>";
    tableHtmlRow += "<button id=\"btnAppsStoreUpdate" + id + "\" type=\"button\" data-id=\"" + id + "\" class=\"btn btn-warning\" style=\"font-size: 12px; padding: 2px 0px; width: 108px; margin-bottom: 6px; " + (updateAvailable ? "" : "display: none;") + "\" data-name=\"" + htmlEncode(name) + "\" data-url=\"" + htmlEncode(updateUrl) + "\" onclick=\"updateStoreApp(this, $(this).attr('data-name'), $(this).attr('data-url'), false);\" data-loading-text=\"Aktualisiere...\">Store-Update</button>";
    tableHtmlRow += "<button type=\"button\" data-id=\"" + id + "\" class=\"btn btn-danger\" style=\"font-size: 12px; padding: 2px 0px; width: 108px; margin-bottom: 6px; display: block;\" data-name=\"" + htmlEncode(name) + "\" onclick=\"uninstallApp(this, $(this).attr('data-name'));\" data-loading-text=\"Entferne...\">Deinstallieren</button></td></tr>";

    return tableHtmlRow
}

function showStoreAppsModal() {
    var divStoreAppsAlert = $("#divStoreAppsAlert");
    var divStoreAppsLoader = $("#divStoreAppsLoader");
    var divStoreApps = $("#divStoreApps");

    divStoreAppsLoader.show();
    divStoreApps.hide();
    $("#modalStoreApps").modal("show");

    HTTPRequest({
        url: "api/apps/listStoreApps",
        token: sessionData.token,
        success: function (responseJSON) {
            var storeApps = responseJSON.response.storeApps;
            var tableHtmlRows = "";

            for (var i = 0; i < storeApps.length; i++) {
                var id = Math.floor(Math.random() * 10000);
                var name = storeApps[i].name;
                var version = storeApps[i].version;
                var description = storeApps[i].description;
                var url = storeApps[i].url;
                var size = storeApps[i].size;
                var installed = storeApps[i].installed;
                var installedVersion = storeApps[i].installedVersion;
                var updateAvailable = installed ? storeApps[i].updateAvailable : false;

                var displayVersion = installed ? installedVersion : version;
                description = htmlEncode(description).replace(/\n/g, "<br />");

                tableHtmlRows += "<tr id=\"trStoreApp" + id + "\"><td><div style=\"margin-bottom: 14px;\"><span style=\"font-weight: bold; font-size: 16px;\">" + htmlEncode(name) + "</span><br /><span id=\"spanStoreAppDisplayVersion" + id + "\" class=\"label label-primary\">Version " + htmlEncode(displayVersion) + "</span> <span id=\"spanStoreAppUpdateVersion" + id + "\" class=\"label label-warning\" style=\"" + (updateAvailable ? "" : "display: none;") + "\">Update " + htmlEncode(version) + "</span></div>";
                tableHtmlRows += "<div style=\"margin-bottom: 10px;\">" + description + "</div><div><b>App-Datei</b>: " + htmlEncode(url) + "<br /><b>Größe</b>: " + htmlEncode(size) + "</div></td><td>";
                tableHtmlRows += "<button id=\"btnStoreAppInstall" + id + "\" type=\"button\" data-id=\"" + id + "\" class=\"btn btn-primary\" style=\"font-size: 12px; padding: 2px 0px; width: 80px; margin-bottom: 6px; " + (installed ? "display: none;" : "") + "\" data-name=\"" + htmlEncode(name) + "\" data-url=\"" + htmlEncode(url) + "\" onclick=\"installStoreApp(this, $(this).attr('data-name'), $(this).attr('data-url'));\" data-loading-text=\"Installiere...\">Installieren</button>";
                tableHtmlRows += "<button id=\"btnStoreAppUpdate" + id + "\" type=\"button\" data-id=\"" + id + "\" class=\"btn btn-warning\" style=\"font-size: 12px; padding: 2px 0px; width: 80px; margin-bottom: 6px; " + (updateAvailable ? "" : "display: none;") + "\" data-name=\"" + htmlEncode(name) + "\" data-url=\"" + htmlEncode(url) + "\" onclick=\"updateStoreApp(this, $(this).attr('data-name'), $(this).attr('data-url'), true);\" data-loading-text=\"Aktualisiere...\">Aktualisieren</button>";
                tableHtmlRows += "<button id=\"btnStoreAppUninstall" + id + "\" type=\"button\" data-id=\"" + id + "\" class=\"btn btn-danger\" style=\"font-size: 12px; padding: 2px 0px; width: 80px; margin-bottom: 6px; " + (installed ? "" : "display: none;") + "\" data-name=\"" + htmlEncode(name) + "\" onclick=\"uninstallStoreApp(this, $(this).attr('data-name'));\" data-loading-text=\"Entferne...\">Deinstallieren</button>";
                tableHtmlRows += "</td></tr>";
            }

            $("#tableStoreAppsBody").html(tableHtmlRows);

            if (storeApps.length > 0)
                $("#tableStoreAppsFooter").html("<tr><td colspan=\"3\"><b>Apps gesamt: " + storeApps.length + "</b></td></tr>");
            else
                $("#tableStoreAppsFooter").html("<tr><td colspan=\"3\" align=\"center\">Keine Apps installiert</td></tr>");

            divStoreAppsLoader.hide();
            divStoreApps.show();
        },
        error: function () {
            divStoreAppsLoader.hide();
            divStoreApps.show();
        },
        invalidToken: function () {
            $("#modalStoreApps").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divStoreAppsAlert,
        objLoaderPlaceholder: divStoreAppsLoader
    });
}

function showInstallAppModal() {
    $("#divInstallAppAlert").html("");
    $("#txtInstallApp").val("");
    $("#fileAppZip").val("");
    $("#btnInstallApp").button("reset");

    $("#modalInstallApp").modal("show");

    setTimeout(function () {
        $("#txtInstallApp").trigger("focus");
    }, 1000);
}

function showUpdateAppModal(appName) {
    $("#divUpdateAppAlert").html("");
    $("#txtUpdateApp").val(appName);
    $("#fileUpdateAppZip").val("");
    $("#btnUpdateApp").button("reset");

    $("#modalUpdateApp").modal("show");
}

function installStoreApp(objBtn, appName, url) {
    var divStoreAppsAlert = $("#divStoreAppsAlert");

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/apps/downloadAndInstall?name=" + encodeURIComponent(appName) + "&url=" + encodeURIComponent(url),
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");
            btn.hide();

            var id = btn.attr("data-id");
            $("#btnStoreAppUninstall" + id).show();

            var tableHtmlRow = getAppRowHtml(responseJSON.response.installedApp);
            $("#tableAppsBody").prepend(tableHtmlRow);
            updateAppsFooterCount();

            showAlert("success", "App installiert", "Die App '" + appName + "' wurde aus dem App-Store installiert.", divStoreAppsAlert);
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalStoreApps").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divStoreAppsAlert
    });
}

function updateStoreApp(objBtn, appName, url, isModal) {
    var divStoreAppsAlert;

    if (isModal)
        divStoreAppsAlert = $("#divStoreAppsAlert");

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/apps/downloadAndUpdate?name=" + encodeURIComponent(appName) + "&url=" + encodeURIComponent(url),
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");
            btn.hide();

            if (isModal) {
                var id = btn.attr("data-id");
                $("#spanStoreAppUpdateVersion" + id).hide();
                $("#spanStoreAppDisplayVersion" + id).text($("#spanStoreAppUpdateVersion" + id).text().replace(/Update/g, "Version"));
            }

            var tableHtmlRow = getAppRowHtml(responseJSON.response.updatedApp);
            var id = getAppRowId(responseJSON.response.updatedApp.name);
            $("#trApp" + id).replaceWith(tableHtmlRow);

            showAlert("success", "App aktualisiert", "Die App '" + appName + "' wurde aus dem App-Store aktualisiert.", divStoreAppsAlert);
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalStoreApps").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divStoreAppsAlert
    });
}

function uninstallStoreApp(objBtn, appName) {
    if (!confirm("App '" + appName + "' wirklich deinstallieren?"))
        return;

    var divStoreAppsAlert = $("#divStoreAppsAlert");
    var btn = $(objBtn);

    btn.button("loading");

    HTTPRequest({
        url: "api/apps/uninstall?name=" + encodeURIComponent(appName),
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");
            btn.hide();

            var id = btn.attr("data-id");
            $("#btnStoreAppInstall" + id).show();
            $("#btnStoreAppUpdate" + id).hide();
            $("#spanStoreAppVersion" + id).attr("class", "label label-primary");

            var id = getAppRowId(appName);
            $("#trApp" + id).remove();
            updateAppsFooterCount();

            showAlert("success", "App deinstalliert", "Die App '" + appName + "' wurde deinstalliert.", divStoreAppsAlert);
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalStoreApps").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divStoreAppsAlert
    });
}

function installApp() {
    var divInstallAppAlert = $("#divInstallAppAlert");
    var appName = $("#txtInstallApp").val();

    if ((appName === null) || (appName === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte einen Namen für die App eingeben.", divInstallAppAlert);
        $("#txtInstallApp").trigger("focus");
        return;
    }

    var fileAppZip = $("#fileAppZip");

    if (fileAppZip[0].files.length === 0) {
        showAlert("warning", "Angabe fehlt", "Bitte die App-Datei (ZIP) auswählen.", divInstallAppAlert);
        fileAppZip.trigger("focus");
        return;
    }

    var formData = new FormData();
    formData.append("fileAppZip", $("#fileAppZip")[0].files[0]);

    var btn = $("#btnInstallApp");
    btn.button("loading");

    HTTPRequest({
        url: "api/apps/install?name=" + encodeURIComponent(appName),
        token: sessionData.token,
        method: "POST",
        data: formData,
        contentType: false,
        processData: false,
        success: function (responseJSON) {
            $("#modalInstallApp").modal("hide");

            var tableHtmlRow = getAppRowHtml(responseJSON.response.installedApp);
            $("#tableAppsBody").prepend(tableHtmlRow);
            updateAppsFooterCount();

            showAlert("success", "App installiert", "Die App '" + appName + "' wurde installiert.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalInstallApp").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divInstallAppAlert
    });
}

function updateApp() {
    var divUpdateAppAlert = $("#divUpdateAppAlert");
    var appName = $("#txtUpdateApp").val();
    var fileAppZip = $("#fileUpdateAppZip");

    if (fileAppZip[0].files.length === 0) {
        showAlert("warning", "Angabe fehlt", "Bitte die App-Datei (ZIP) auswählen.", divUpdateAppAlert);
        fileAppZip.trigger("focus");
        return;
    }

    var formData = new FormData();
    formData.append("fileAppZip", $("#fileUpdateAppZip")[0].files[0]);

    var btn = $("#btnUpdateApp");
    btn.button("loading");

    HTTPRequest({
        url: "api/apps/update?name=" + encodeURIComponent(appName),
        token: sessionData.token,
        method: "POST",
        data: formData,
        contentType: false,
        processData: false,
        success: function (responseJSON) {
            $("#modalUpdateApp").modal("hide");

            var tableHtmlRow = getAppRowHtml(responseJSON.response.updatedApp);
            var id = getAppRowId(responseJSON.response.updatedApp.name);
            $("#trApp" + id).replaceWith(tableHtmlRow);

            showAlert("success", "App aktualisiert", "Die App '" + appName + "' wurde aktualisiert.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalUpdateApp").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divUpdateAppAlert
    });
}

function uninstallApp(objBtn, appName) {
    if (!confirm("App '" + appName + "' wirklich deinstallieren?"))
        return;

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/apps/uninstall?name=" + encodeURIComponent(appName),
        token: sessionData.token,
        success: function (responseJSON) {
            var id = btn.attr("data-id");
            $("#trApp" + id).remove();
            updateAppsFooterCount();

            showAlert("success", "App deinstalliert", "Die App '" + appName + "' wurde deinstalliert.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
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
        $("#tableAppsFooter").html("<tr><td colspan=\"3\"><b>Apps gesamt: " + totalApps + "</b></td></tr>");
    else
        $("#tableAppsFooter").html("<tr><td colspan=\"3\" align=\"center\">Keine App gefunden</td></tr>");
}

function showAppConfigModal(objBtn, appName) {
    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/apps/config/get?name=" + encodeURIComponent(appName),
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");

            $("#divAppConfigAlert").html("");

            $("#lblAppConfigName").text(appName);
            $("#txtAppConfig").val(responseJSON.response.config);

            $("#btnAppConfig").button("reset");

            $("#modalAppConfig").modal("show");

            setTimeout(function () {
                $("#txtAppConfig").trigger("focus");
            }, 1000);
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

    var appName = $("#lblAppConfigName").text();
    var config = $("#txtAppConfig").val();

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
