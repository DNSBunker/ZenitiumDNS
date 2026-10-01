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

function htmlEncode(value) {
    return $('<div/>').text(value).html().replace(/"/g, "&quot;");
}

function jsArg(value) {
    return htmlEncode(JSON.stringify(value == null ? null : String(value)));
}

function htmlDecode(value) {
    return $('<div/>').html(value).text();
}

var serverConnection = { lost: false, attempts: 0, retryAt: 0, timer: null, tick: null };

function isServerConnectionFailure(jqXHR, textStatus) {
    if (textStatus === "abort")
        return false;

    return (jqXHR.status === 0) || (jqXHR.status === 502) || (jqXHR.status === 503) || (jqXHR.status === 504);
}

function getConnectionBanner() {
    var banner = $("#divConnectionBanner");

    if (banner.length === 0) {
        banner = $("<div id=\"divConnectionBanner\" class=\"connection-banner\" role=\"status\" aria-live=\"polite\" style=\"display: none;\"><span class=\"connection-banner-icon fa\" aria-hidden=\"true\"></span><span class=\"connection-banner-text\"></span><button type=\"button\" class=\"btn btn-default btn-xs connection-banner-retry\"></button></div>");
        banner.find(".connection-banner-retry").on("click", function () {
            reconnectToServerNow();
        });
        $("body").append(banner);
    }

    return banner;
}

function showConnectionBanner(state) {
    var banner = getConnectionBanner();
    var icon = banner.find(".connection-banner-icon");
    var text = banner.find(".connection-banner-text");
    var retry = banner.find(".connection-banner-retry");

    banner.removeClass("connection-banner-lost connection-banner-ok");
    icon.removeClass("fa-plug fa-check fa-refresh fa-spin");

    switch (state) {
        case "lost":
            banner.addClass("connection-banner-lost");
            icon.addClass("fa-plug");
            text.text(tr("Verbindung zum Server unterbrochen. Neuer Versuch in {0} s …", Math.max(1, Math.ceil((serverConnection.retryAt - Date.now()) / 1000))));
            retry.text(tr("Jetzt versuchen")).show();
            break;

        case "connecting":
            banner.addClass("connection-banner-lost");
            icon.addClass("fa-refresh fa-spin");
            text.text(tr("Verbindung wird wiederhergestellt …"));
            retry.hide();
            break;

        case "updated":
            banner.addClass("connection-banner-ok");
            icon.addClass("fa-refresh fa-spin");
            text.text(tr("Der Server wurde aktualisiert. Die Seite wird neu geladen …"));
            retry.hide();
            break;

        default:
            banner.addClass("connection-banner-ok");
            icon.addClass("fa-check");
            text.text(tr("Verbindung wiederhergestellt."));
            retry.hide();
            break;
    }

    banner.show();
}

function hideConnectionBanner() {
    $("#divConnectionBanner").fadeOut(300);
}

function onServerConnectionLost() {
    if (serverConnection.lost)
        return;

    serverConnection.lost = true;
    serverConnection.attempts = 0;
    scheduleServerReconnect();
}

function scheduleServerReconnect() {
    var delays = [1000, 2000, 3000, 5000];
    var delay = delays[Math.min(serverConnection.attempts, delays.length - 1)];

    serverConnection.attempts++;
    serverConnection.retryAt = Date.now() + delay;

    clearTimeout(serverConnection.timer);
    clearInterval(serverConnection.tick);

    showConnectionBanner("lost");

    serverConnection.tick = setInterval(function () {
        if (serverConnection.lost && (serverConnection.retryAt > Date.now()))
            showConnectionBanner("lost");
    }, 1000);

    serverConnection.timer = setTimeout(reconnectToServerNow, delay);
}

function reconnectToServerNow() {
    clearTimeout(serverConnection.timer);
    clearInterval(serverConnection.tick);
    showConnectionBanner("connecting");

    $.ajax({
        type: "GET",
        url: "api/status",
        dataType: "json",
        cache: false,
        timeout: 5000,
        success: function () {
            onServerConnectionRestored();
        },
        error: function () {
            scheduleServerReconnect();
        }
    });
}

function onServerConnectionRestored() {
    if ((typeof sessionData === "undefined") || (sessionData == null)) {
        serverConnection.lost = false;
        showConnectionBanner("ok");
        setTimeout(hideConnectionBanner, 2500);
        return;
    }

    $.ajax({
        type: "GET",
        url: "api/user/session/get",
        headers: { "Authorization": "Bearer " + sessionData.token },
        dataType: "json",
        cache: false,
        timeout: 5000,
        success: function (responseJSON) {
            serverConnection.lost = false;

            if (responseJSON.status === "invalid-token") {
                hideConnectionBanner();
                showPageLogin();
                return;
            }

            var info = responseJSON.info;

            if ((info != null) && (sessionData.info != null) && (info.version !== sessionData.info.version)) {
                showConnectionBanner("updated");
                setTimeout(function () { window.location.reload(); }, 1500);
                return;
            }

            showConnectionBanner("ok");
            setTimeout(hideConnectionBanner, 2500);

            if (typeof onServerReconnected === "function")
                onServerReconnected();
        },
        error: function () {
            scheduleServerReconnect();
        }
    });
}

function HTTPRequest(url, method, data, isTextResponse, success, error, invalidToken, twoFactorAuthRequired, objAlertPlaceholder, objLoaderPlaceholder, processData, contentType, dontHideAlert, showInnerError, token) {
    var finalUrl;

    if ((url != null) && (url.url != null))
        finalUrl = arguments[0].url;
    else
        finalUrl = url;

    if (method == null)
        method = arguments[0].method;

    if (method == null)
        method = "GET";

    if (data == null) {
        if (arguments[0].data == null)
            data = "";
        else
            data = arguments[0].data;
    }

    if (isTextResponse == null)
        isTextResponse = arguments[0].isTextResponse;

    if (isTextResponse == null)
        isTextResponse = false;

    var dataType = isTextResponse ? null : "json";

    if (success == null)
        success = arguments[0].success;

    var async = success != null;

    if (error == null)
        error = arguments[0].error;

    if (invalidToken == null)
        invalidToken = arguments[0].invalidToken;

    if (twoFactorAuthRequired == null)
        twoFactorAuthRequired = arguments[0].twoFactorAuthRequired;

    if (objAlertPlaceholder == null)
        objAlertPlaceholder = arguments[0].objAlertPlaceholder;

    if (objLoaderPlaceholder == null)
        objLoaderPlaceholder = arguments[0].objLoaderPlaceholder;

    if (objLoaderPlaceholder != null)
        objLoaderPlaceholder.html("<div class='loader-block' role='status' aria-label='" + tr("Wird geladen") + "'><span class='spinner'></span></div>");

    if (processData == null)
        processData = arguments[0].processData;

    if (contentType == null)
        contentType = arguments[0].contentType;

    if (dontHideAlert == null)
        dontHideAlert = arguments[0].dontHideAlert;

    if ((dontHideAlert == null) || !dontHideAlert)
        hideAlert(objAlertPlaceholder);

    if (showInnerError == null)
        showInnerError = arguments[0].showInnerError;

    if (showInnerError == null)
        showInnerError = false;

    var headers = {};

    if (token == null)
        token = arguments[0].token;

    if (token != null)
        headers = { "Authorization": "Bearer " + token };

    var successFlag = false;

    $.ajax({
        type: method,
        url: finalUrl,
        headers: headers,
        data: data,
        dataType: dataType,
        async: async,
        cache: false,
        processData: processData,
        contentType: contentType,
        success: function (response, status, jqXHR) {
            if (objLoaderPlaceholder != null)
                objLoaderPlaceholder.html("");

            if (isTextResponse) {
                if (success == null)
                    successFlag = true;
                else
                    success(response);
            }
            else {
                switch (response.status) {
                    case "ok":
                        if (success == null)
                            successFlag = true;
                        else
                            success(response);

                        break;

                    case "invalid-token":
                        if (invalidToken != null)
                            invalidToken();
                        else {
                            showAlert("danger", tr("Fehler"), response.errorMessage + (showInnerError && (response.innerErrorMessage != null) ? " " + response.innerErrorMessage : ""), objAlertPlaceholder);

                            if (error != null)
                                error();
                            else
                                window.location = "/";
                        }
                        break;

                    case "2fa-required":
                        if (twoFactorAuthRequired != null) {
                            twoFactorAuthRequired();
                        }
                        else {
                            showAlert("danger", tr("Fehler"), response.errorMessage + (showInnerError && (response.innerErrorMessage != null) ? " " + response.innerErrorMessage : ""), objAlertPlaceholder);

                            if (error != null)
                                error();
                        }

                        break;

                    case "error":
                        showAlert("danger", tr("Fehler"), response.errorMessage + (showInnerError && (response.innerErrorMessage != null) ? " " + response.innerErrorMessage : ""), objAlertPlaceholder);

                        if (error != null)
                            error();

                        break;

                    default:
                        showAlert("danger", tr("Ungültige Antwort"), tr("Der Server lieferte einen ungültigen Status: {0}", response.status), objAlertPlaceholder);

                        if (error != null)
                            error();

                        break;
                }
            }
        },
        error: function (jqXHR, textStatus, errorThrown) {
            if (objLoaderPlaceholder != null)
                objLoaderPlaceholder.html("");

            if (error != null)
                error();

            if (isServerConnectionFailure(jqXHR, textStatus)) {
                onServerConnectionLost();
                return;
            }

            showAlert("danger", tr("Fehler"), textStatus + " - " + errorThrown, objAlertPlaceholder);
        }
    });

    return successFlag;
}

function showAlert(type, title, message, objAlertPlaceholder) {
    var alertHTML = "<div class=\"alert alert-" + type + "\">\
    <button type=\"button\" class=\"close\" data-dismiss=\"alert\">&times;</button>\
    <strong>" + title + "</strong>&nbsp;" + htmlEncode(message) + "\
    </div>";

    if (objAlertPlaceholder == null)
        objAlertPlaceholder = $(".AlertPlaceholder");

    objAlertPlaceholder.html(alertHTML);

    if (type == "success") {
        setTimeout(function () {
            hideAlert(objAlertPlaceholder);
        }, 5000);
    }
}

function hideAlert(objAlertPlaceholder) {
    if (objAlertPlaceholder == null)
        objAlertPlaceholder = $(".AlertPlaceholder");

    objAlertPlaceholder.html("");
}

function sortTable(tableId, n) {
    var table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
    table = document.getElementById(tableId);
    switching = true;
    dir = "asc";
    while (switching) {
        switching = false;
        rows = table.rows;
        for (i = 0; i < (rows.length - 1); i++) {
            shouldSwitch = false;
            x = rows[i].getElementsByTagName("TD")[n];
            y = rows[i + 1].getElementsByTagName("TD")[n];
            if (dir == "asc") {
                if (x.innerText.toLowerCase() > y.innerText.toLowerCase()) {
                    shouldSwitch = true;
                    break;
                }
            } else if (dir == "desc") {
                if (x.innerText.toLowerCase() < y.innerText.toLowerCase()) {
                    shouldSwitch = true;
                    break;
                }
            }
        }
        if (shouldSwitch) {
            rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
            switching = true;
            switchcount++;
        } else {
            if (switchcount == 0 && dir == "asc") {
                dir = "desc";
                switching = true;
            }
        }
    }
}

function serializeTableData(table, columns, objAlertPlaceholder) {
    var data = table.find('input:text, :input[type="number"], input:checkbox, input:hidden, select');
    var output = "";

    for (var i = 0; i < data.length; i += columns) {
        if (i > 0)
            output += "|";

        for (var j = 0; j < columns; j++) {
            if (j > 0)
                output += "|";

            var cell = $(data[i + j]);

            var cellValue;

            if (cell.attr("type") == "checkbox") {
                cellValue = cell.prop("checked").toString();
            }
            else {
                cellValue = cell.val();

                var optional = (cell.attr("data-optional") === "true");

                if ((cellValue === "") && !optional) {
                    showAlert("warning", tr("Angabe fehlt"), tr("Bitte im markierten Feld einen gültigen Wert eingeben."), objAlertPlaceholder);
                    cell.focus();
                    return false;
                }

                if (cellValue.includes("|")) {
                    showAlert("warning", tr("Ungültiges Zeichen"), tr("Bitte das Zeichen '|' aus dem markierten Feld entfernen."), objAlertPlaceholder);
                    cell.focus();
                    return false;
                }
            }

            output += htmlDecode(cellValue);
        }
    }

    return output;
}

function cleanTextList(text) {
    text = text.replace(/\n/g, ",");

    while (text.indexOf(",,") !== -1) {
        text = text.replace(/,,/g, ",");
    }

    if (text.startsWith(","))
        text = text.substr(1);

    if (text.endsWith(","))
        text = text.substr(0, text.length - 1);

    return text;
}

function getCookie(name) {
    name = name + "=";
    var cookieParts = document.cookie.split(';');

    for (var i = 0; i < cookieParts.length; i++) {
        var c = cookieParts[i].trimStart();

        if (c.indexOf(name) == 0)
            return c.substring(name.length, c.length);
    }

    return null;
}

function setCookie(name, value, maxAge) {
    document.cookie = name + "=" + value + ";Max-Age=" + maxAge + ";path=/";
}

var APP_DISPLAY_NAMES = {
    "AdvancedBlockingApp": tr("Erweiterte Blockierung"),
    "AdvancedForwardingApp": tr("Erweiterte Weiterleitung"),
    "Dns64App": "DNS64",
    "DnsRebindingProtectionApp": tr("Schutz vor DNS-Rebinding"),
    "DropRequestsApp": tr("Anfragen verwerfen"),
    "LogExporterApp": tr("Protokoll-Export"),
    "NxDomainApp": tr("NXDOMAIN-Blockierung"),
    "QueryLogsMySqlApp": tr("Anfrageprotokoll (MySQL/MariaDB)"),
    "QueryLogsPostgreSqlApp": tr("Anfrageprotokoll (PostgreSQL)"),
    "QueryLogsSqliteApp": tr("Anfrageprotokoll (SQLite)"),
    "QueryLogsSqlServerApp": tr("Anfrageprotokoll (SQL Server)")
};

function getAppDisplayName(name) {
    if (Object.prototype.hasOwnProperty.call(APP_DISPLAY_NAMES, name))
        return APP_DISPLAY_NAMES[name];

    return name;
}
