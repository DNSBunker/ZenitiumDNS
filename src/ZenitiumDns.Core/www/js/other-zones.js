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

function flushDnsCache(objBtn) {
    if (!confirm(tr("Den gesamten Cache leeren? Alle Antworten müssen danach neu aufgelöst werden.")))
        return;

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/cache/flush",
        token: sessionData.token,
        success: function (responseJSON) {
            $("#lstCachedZones").html("<div class=\"zone zone-action\"><a href=\"#\" onclick=\"refreshCachedZonesList(); return false;\"><span class=\"fa fa-refresh fa-fw\" aria-hidden=\"true\"></span>" + tr("Aktualisieren") + "</a></div>");
            $("#txtCachedZoneViewerTitle").text("<ROOT>");
            $("#btnDeleteCachedZone").hide();
            $("#preCachedZoneViewerBody").hide();

            btn.button("reset");
            showAlert("success", tr("Geleert"), tr("Der Cache wurde geleert."));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            showPageLogin();
        }
    });
}

function deleteCachedZone() {
    var domain = $("#txtCachedZoneViewerTitle").text();

    if (!confirm(tr("Zwischengespeicherte Daten für '{0}' löschen?", domain)))
        return;

    var btn = $("#btnDeleteCachedZone");
    btn.button("loading");

    HTTPRequest({
        url: "api/cache/delete?domain=" + encodeURIComponent(domain),
        token: sessionData.token,
        success: function (responseJSON) {
            refreshCachedZonesList(getParentDomain(domain), "up");

            btn.button("reset");
            showAlert("success", tr("Gelöscht"), tr("Die zwischengespeicherten Daten für '{0}' wurde gelöscht.", domain));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            showPageLogin();
        }
    });
}

function getParentDomain(domain) {

    if ((domain != null) && (domain != "")) {
        var parentDomain;
        var i = domain.indexOf(".");

        if (i == -1)
            parentDomain = "";
        else
            parentDomain = domain.substr(i + 1);

        return parentDomain;
    }

    return null;
}

function refreshCachedZonesList(domain, direction) {
    if (domain == null) {
        domain = $("#txtCachedZoneViewerTitle").text();

        if ((domain == null) || (domain == "<ROOT>"))
            domain = "";
    }

    domain = domain.toLowerCase();

    var lstCachedZones = $("#lstCachedZones");
    var divCachedZoneViewer = $("#divCachedZoneViewer");
    var preCachedZoneViewerBody = $("#preCachedZoneViewerBody");

    divCachedZoneViewer.hide();
    preCachedZoneViewerBody.hide();

    HTTPRequest({
        url: "api/cache/list?domain=" + encodeURIComponent(domain) + ((direction == null) ? "" : "&direction=" + direction),
        token: sessionData.token,
        success: function (responseJSON) {
            var newDomain = responseJSON.response.domain;
            var zones = responseJSON.response.zones;

            var list = "<div class=\"zone zone-action\"><a href=\"#\" onclick=\"refreshCachedZonesList(" + jsArg(newDomain) + "); return false;\"><span class=\"fa fa-refresh fa-fw\" aria-hidden=\"true\"></span>" + tr("Aktualisieren") + "</a></div>";

            var parentDomain = getParentDomain(newDomain);

            if (parentDomain != null)
                list += "<div class=\"zone zone-action\"><a href=\"#\" onclick=\"refreshCachedZonesList(" + jsArg(parentDomain) + ", 'up'); return false;\"><span class=\"fa fa-level-up fa-fw\" aria-hidden=\"true\"></span>" + tr("Eine Ebene höher") + "</a></div>";

            for (var i = 0; i < zones.length; i++) {
                var zoneName = htmlEncode(zones[i]);

                list += "<div class=\"zone\"><a href=\"#\" onclick=\"refreshCachedZonesList(" + jsArg(zones[i]) + "); return false;\">" + zoneName + "</a></div>";
            }

            lstCachedZones.html(list);

            if (newDomain == "") {
                $("#txtCachedZoneViewerTitle").text("<ROOT>");
                $("#btnDeleteCachedZone").hide();
            }
            else {
                if (responseJSON.response.domainIdn == null)
                    $("#txtCachedZoneViewerTitle").text(newDomain);
                else
                    $("#txtCachedZoneViewerTitle").text(responseJSON.response.domainIdn);

                $("#btnDeleteCachedZone").show();
            }

            if (responseJSON.response.records.length > 0) {
                renderDnsRecordsView(preCachedZoneViewerBody, responseJSON.response.records);
                preCachedZoneViewerBody.show();
            }

            divCachedZoneViewer.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        error: function () {
            lstCachedZones.html("<div class=\"zone zone-action\"><a href=\"#\" onclick=\"refreshCachedZonesList(" + jsArg(domain) + "); return false;\"><span class=\"fa fa-refresh fa-fw\" aria-hidden=\"true\"></span>" + tr("Aktualisieren") + "</a></div>");

            divCachedZoneViewer.show();
        },
        objLoaderPlaceholder: lstCachedZones
    });
}

function allowZone() {
    var domain = $("#txtAllowZone").val();

    if ((domain === null) || (domain === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte die zu erlaubende Domain eingeben."));
        $("#txtAllowZone").trigger("focus");
        return;
    }

    var btn = $("#btnAllowZone");
    btn.button("loading");

    HTTPRequest({
        url: "api/allowed/add?domain=" + encodeURIComponent(domain),
        token: sessionData.token,
        success: function (responseJSON) {
            refreshAllowedZonesList(domain, null, true);

            $("#txtAllowZone").val("");
            btn.button("reset");

            showAlert("success", tr("Erlaubt"), tr("Domain '{0}' wird nicht mehr blockiert.", domain));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            showPageLogin();
        }
    });
}

function deleteAllowedZone() {
    var domain = $("#txtAllowedZoneViewerTitle").text();

    if (!confirm(tr("Freigabe für '{0}' entfernen?", domain)))
        return;

    var btn = $("#btnDeleteAllowedZone");
    btn.button("loading");

    HTTPRequest({
        url: "api/allowed/delete?domain=" + encodeURIComponent(domain),
        token: sessionData.token,
        success: function (responseJSON) {
            refreshAllowedZonesList(getParentDomain(domain), "up", true);

            btn.button("reset");
            showAlert("success", tr("Gelöscht"), tr("Domain '{0}' ist nicht mehr erlaubt.", domain));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            showPageLogin();
        }
    });
}

function flushAllowedZone() {
    if (!confirm(tr("Alle erlaubten Domains löschen?")))
        return;

    var btn = $("#btnFlushAllowedZone");
    btn.button("loading");

    HTTPRequest({
        url: "api/allowed/flush",
        token: sessionData.token,
        success: function (responseJSON) {
            $("#lstAllowedZones").html("<div class=\"zone zone-action\"><a href=\"#\" onclick=\"refreshAllowedZonesList(); return false;\"><span class=\"fa fa-refresh fa-fw\" aria-hidden=\"true\"></span>" + tr("Aktualisieren") + "</a></div>");
            $("#txtAllowedZoneViewerTitle").text("<ROOT>");
            $("#btnDeleteAllowedZone").hide();
            $("#preAllowedZoneViewerBody").hide();

            btn.button("reset");
            showAlert("success", tr("Geleert"), tr("Alle erlaubten Domains wurden gelöscht."));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            showPageLogin();
        }
    });
}

function refreshAllowedZonesList(domain, direction, fromPrimary) {
    if (domain == null) {
        domain = $("#txtAllowedZoneViewerTitle").text();

        if ((domain == null) || (domain == "<ROOT>"))
            domain = "";
    }

    domain = domain.toLowerCase();

    var lstAllowedZones = $("#lstAllowedZones");
    var divAllowedZoneViewer = $("#divAllowedZoneViewer");
    var preAllowedZoneViewerBody = $("#preAllowedZoneViewerBody");

    divAllowedZoneViewer.hide();
    preAllowedZoneViewerBody.hide();

    HTTPRequest({
        url: "api/allowed/list?domain=" + encodeURIComponent(domain) + ((direction == null) ? "" : "&direction=" + direction),
        token: sessionData.token,
        success: function (responseJSON) {
            var newDomain = responseJSON.response.domain;
            var zones = responseJSON.response.zones;

            var list = "<div class=\"zone zone-action\"><a href=\"#\" onclick=\"refreshAllowedZonesList(" + jsArg(newDomain) + "); return false;\"><span class=\"fa fa-refresh fa-fw\" aria-hidden=\"true\"></span>" + tr("Aktualisieren") + "</a></div>";

            var parentDomain = getParentDomain(newDomain);

            if (parentDomain != null)
                list += "<div class=\"zone zone-action\"><a href=\"#\" onclick=\"refreshAllowedZonesList(" + jsArg(parentDomain) + ", 'up'); return false;\"><span class=\"fa fa-level-up fa-fw\" aria-hidden=\"true\"></span>" + tr("Eine Ebene höher") + "</a></div>";

            for (var i = 0; i < zones.length; i++) {
                var zoneName = htmlEncode(zones[i]);

                list += "<div class=\"zone\"><a href=\"#\" onclick=\"refreshAllowedZonesList(" + jsArg(zones[i]) + "); return false;\">" + zoneName + "</a></div>";
            }

            lstAllowedZones.html(list);

            if (newDomain == "") {
                $("#txtAllowedZoneViewerTitle").text("<ROOT>");
            }
            else {
                if (responseJSON.response.domainIdn == null)
                    $("#txtAllowedZoneViewerTitle").text(newDomain);
                else
                    $("#txtAllowedZoneViewerTitle").text(responseJSON.response.domainIdn);
            }

            if (responseJSON.response.records.length > 0) {
                renderDnsRecordsView(preAllowedZoneViewerBody, responseJSON.response.records);
                preAllowedZoneViewerBody.show();

                $("#btnDeleteAllowedZone").show();
            }
            else {
                $("#btnDeleteAllowedZone").hide();
            }

            divAllowedZoneViewer.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        error: function () {
            lstAllowedZones.html("<div class=\"zone zone-action\"><a href=\"#\" onclick=\"refreshAllowedZonesList(" + jsArg(domain) + "); return false;\"><span class=\"fa fa-refresh fa-fw\" aria-hidden=\"true\"></span>" + tr("Aktualisieren") + "</a></div>");

            divAllowedZoneViewer.show();
        },
        objLoaderPlaceholder: lstAllowedZones
    });
}

function blockZone() {
    var domain = $("#txtBlockZone").val();

    if ((domain === null) || (domain === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte die zu blockierende Domain eingeben."));
        $("#txtBlockZone").trigger("focus");
        return;
    }

    var btn = $("#btnBlockZone");
    btn.button("loading");

    HTTPRequest({
        url: "api/blocked/add?domain=" + encodeURIComponent(domain),
        token: sessionData.token,
        success: function (responseJSON) {
            refreshBlockedZonesList(domain, null, true);

            $("#txtBlockZone").val("");
            btn.button("reset");

            showAlert("success", tr("Blockiert"), tr("Domain '{0}' wird jetzt blockiert.", domain));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            showPageLogin();
        }
    });
}

function deleteBlockedZone() {
    var domain = $("#txtBlockedZoneViewerTitle").text();

    if (!confirm(tr("Blockierung für '{0}' aufheben?", domain)))
        return;

    var btn = $("#btnDeleteBlockedZone");
    btn.button("loading");

    HTTPRequest({
        url: "api/blocked/delete?domain=" + encodeURIComponent(domain),
        token: sessionData.token,
        success: function (responseJSON) {
            refreshBlockedZonesList(getParentDomain(domain), "up", true);

            btn.button("reset");
            showAlert("success", tr("Gelöscht"), tr("Die Blockierung für '{0}' wurde gelöscht.", domain));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            showPageLogin();
        }
    });
}

function flushBlockedZone() {
    if (!confirm(tr("Alle blockierten Domains löschen?")))
        return;

    var btn = $("#btnFlushBlockedZone");
    btn.button("loading");

    HTTPRequest({
        url: "api/blocked/flush",
        token: sessionData.token,
        success: function (responseJSON) {
            $("#lstBlockedZones").html("<div class=\"zone zone-action\"><a href=\"#\" onclick=\"refreshBlockedZonesList(); return false;\"><span class=\"fa fa-refresh fa-fw\" aria-hidden=\"true\"></span>" + tr("Aktualisieren") + "</a></div>");
            $("#txtBlockedZoneViewerTitle").text("<ROOT>");
            $("#btnDeleteBlockedZone").hide();
            $("#preBlockedZoneViewerBody").hide();

            btn.button("reset");
            showAlert("success", tr("Geleert"), tr("Alle blockierten Domains wurden gelöscht."));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            showPageLogin();
        }
    });
}

function refreshBlockedZonesList(domain, direction, fromPrimary) {
    if (domain == null) {
        domain = $("#txtBlockedZoneViewerTitle").text();

        if ((domain == null) || (domain == "<ROOT>"))
            domain = "";
    }

    domain = domain.toLowerCase();

    var lstBlockedZones = $("#lstBlockedZones");
    var divBlockedZoneViewer = $("#divBlockedZoneViewer");
    var preBlockedZoneViewerBody = $("#preBlockedZoneViewerBody");

    divBlockedZoneViewer.hide();
    preBlockedZoneViewerBody.hide();

    HTTPRequest({
        url: "api/blocked/list?domain=" + encodeURIComponent(domain) + ((direction == null) ? "" : "&direction=" + direction),
        token: sessionData.token,
        success: function (responseJSON) {
            var newDomain = responseJSON.response.domain;
            var zones = responseJSON.response.zones;

            var list = "<div class=\"zone zone-action\"><a href=\"#\" onclick=\"refreshBlockedZonesList(" + jsArg(newDomain) + "); return false;\"><span class=\"fa fa-refresh fa-fw\" aria-hidden=\"true\"></span>" + tr("Aktualisieren") + "</a></div>";

            var parentDomain = getParentDomain(newDomain);

            if (parentDomain != null)
                list += "<div class=\"zone zone-action\"><a href=\"#\" onclick=\"refreshBlockedZonesList(" + jsArg(parentDomain) + ", 'up'); return false;\"><span class=\"fa fa-level-up fa-fw\" aria-hidden=\"true\"></span>" + tr("Eine Ebene höher") + "</a></div>";

            for (var i = 0; i < zones.length; i++) {
                var zoneName = htmlEncode(zones[i]);

                list += "<div class=\"zone\"><a href=\"#\" onclick=\"refreshBlockedZonesList(" + jsArg(zones[i]) + "); return false;\">" + zoneName + "</a></div>";
            }

            lstBlockedZones.html(list);

            if (newDomain == "") {
                $("#txtBlockedZoneViewerTitle").text("<ROOT>");
            }
            else {
                if (responseJSON.response.domainIdn == null)
                    $("#txtBlockedZoneViewerTitle").text(newDomain);
                else
                    $("#txtBlockedZoneViewerTitle").text(responseJSON.response.domainIdn);
            }

            if (responseJSON.response.records.length > 0) {
                renderDnsRecordsView(preBlockedZoneViewerBody, responseJSON.response.records);
                preBlockedZoneViewerBody.show();

                $("#btnDeleteBlockedZone").show();
            }
            else {
                $("#btnDeleteBlockedZone").hide();
            }

            divBlockedZoneViewer.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        error: function () {
            lstBlockedZones.html("<div class=\"zone zone-action\"><a href=\"#\" onclick=\"refreshBlockedZonesList(" + jsArg(domain) + "); return false;\"><span class=\"fa fa-refresh fa-fw\" aria-hidden=\"true\"></span>" + tr("Aktualisieren") + "</a></div>");

            divBlockedZoneViewer.show();
        },
        objLoaderPlaceholder: lstBlockedZones
    });
}

function resetImportAllowedZonesModal() {
    $("#divImportAllowedZonesAlert").html("");
    $("#txtImportAllowedZones").val("");

    setTimeout(function () {
        $("#txtImportAllowedZones").trigger("focus");
    }, 1000);
}

function importAllowedZones() {
    var divImportAllowedZonesAlert = $("#divImportAllowedZonesAlert");
    var allowedZones = cleanTextList($("#txtImportAllowedZones").val());

    if ((allowedZones.length === 0) || (allowedZones === ",")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte die zu importierenden Domains eingeben."), divImportAllowedZonesAlert);
        $("#txtImportAllowedZones").trigger("focus");
        return;
    }

    var btn = $("#btnImportAllowedZones");
    btn.button("loading");

    HTTPRequest({
        url: "api/allowed/import",
        token: sessionData.token,
        method: "POST",
        data: "allowedZones=" + encodeURIComponent(allowedZones),
        processData: false,
        success: function (responseJSON) {
            $("#modalImportAllowedZones").modal("hide");
            btn.button("reset");

            showAlert("success", tr("Importiert"), tr("Die Domains wurden zu den erlaubten Domains hinzugefügt."));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            showPageLogin();
        },
        objAlertPlaceholder: divImportAllowedZonesAlert
    });
}

function exportAllowedZones(objBtn) {
    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/user/createSingleUseToken",
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");

            window.open("api/allowed/export?token=" + responseJSON.response.token, "_blank");

            showAlert("success", tr("Exportiert"), tr("Die erlaubten Domains wurden exportiert."));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            showPageLogin();
        }
    });
}

function resetImportBlockedZonesModal() {
    $("#divImportBlockedZonesAlert").html("");
    $("#txtImportBlockedZones").val("");

    setTimeout(function () {
        $("#txtImportBlockedZones").trigger("focus");
    }, 1000);
}

function importBlockedZones() {
    var divImportBlockedZonesAlert = $("#divImportBlockedZonesAlert");
    var blockedZones = cleanTextList($("#txtImportBlockedZones").val());

    if ((blockedZones.length === 0) || (blockedZones === ",")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte die zu importierenden Domains eingeben."), divImportBlockedZonesAlert);
        $("#txtImportBlockedZones").trigger("focus");
        return;
    }

    var btn = $("#btnImportBlockedZones");
    btn.button("loading");

    HTTPRequest({
        url: "api/blocked/import",
        token: sessionData.token,
        method: "POST",
        data: "blockedZones=" + encodeURIComponent(blockedZones),
        processData: false,
        success: function (responseJSON) {
            $("#modalImportBlockedZones").modal("hide");
            btn.button("reset");

            showAlert("success", tr("Importiert"), tr("Die Domains wurden zu den blockierten Domains hinzugefügt."));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            showPageLogin();
        },
        objAlertPlaceholder: divImportBlockedZonesAlert
    });
}

function exportBlockedZones(objBtn) {
    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/user/createSingleUseToken",
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");

            window.open("api/blocked/export?token=" + responseJSON.response.token, "_blank");

            showAlert("success", tr("Exportiert"), tr("Die blockierten Domains wurden exportiert."));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            showPageLogin();
        }
    });
}

function allowDomain(objMenuItem, btnName, alertPlaceholderName) {
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var domain = mnuItem.attr("data-domain");

    var btn = $("#" + btnName + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<span class='spinner spinner-sm' role='status' aria-label='" + tr("Wird geladen") + "'></span>");

    var alertPlaceholder;
    if (alertPlaceholderName != null)
        alertPlaceholder = $("#" + alertPlaceholderName);

    HTTPRequest({
        url: "api/blocked/delete?domain=" + encodeURIComponent(domain),
        token: sessionData.token,
        success: function (responseJSON) {
            HTTPRequest({
                url: "api/allowed/add?domain=" + encodeURIComponent(domain),
                token: sessionData.token,
                success: function (responseJSON) {
                    btn.prop("disabled", false);
                    btn.html(originalBtnHtml);

                    showAlert("success", tr("Erlaubt"), tr("Domain '{0}' wird nicht mehr blockiert.", domain), alertPlaceholder);
                },
                error: function () {
                    btn.prop("disabled", false);
                    btn.html(originalBtnHtml);
                },
                invalidToken: function () {
                    showPageLogin();
                },
                objAlertPlaceholder: alertPlaceholder
            });
        },
        error: function () {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);
        },
        invalidToken: function () {
            showPageLogin();
        },
        objAlertPlaceholder: alertPlaceholder
    });
}

function blockDomain(objMenuItem, btnName, alertPlaceholderName) {
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var domain = mnuItem.attr("data-domain");

    var btn = $("#" + btnName + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<span class='spinner spinner-sm' role='status' aria-label='" + tr("Wird geladen") + "'></span>");

    var alertPlaceholder;
    if (alertPlaceholderName != null)
        alertPlaceholder = $("#" + alertPlaceholderName);

    HTTPRequest({
        url: "api/allowed/delete?domain=" + encodeURIComponent(domain),
        token: sessionData.token,
        success: function (responseJSON) {
            HTTPRequest({
                url: "api/blocked/add?domain=" + encodeURIComponent(domain),
                token: sessionData.token,
                success: function (responseJSON) {
                    btn.prop("disabled", false);
                    btn.html(originalBtnHtml);

                    showAlert("success", tr("Blockiert"), tr("Domain '{0}' wird jetzt blockiert.", domain), alertPlaceholder);
                },
                error: function () {
                    btn.prop("disabled", false);
                    btn.html(originalBtnHtml);
                },
                invalidToken: function () {
                    showPageLogin();
                },
                objAlertPlaceholder: alertPlaceholder
            });
        },
        error: function () {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);
        },
        invalidToken: function () {
            showPageLogin();
        },
        objAlertPlaceholder: alertPlaceholder
    });
}
