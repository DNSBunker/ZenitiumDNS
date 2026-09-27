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

var editZoneInfo;
var editZoneRecords;
var editZoneFilteredRecords;

$(function () {
    $("#chkAddZoneInitializeForwarder").on("click", updateAddZoneFormInitializeForwarder);

    $("input[type=radio][name=rdAddZoneForwarderProtocol]").on("change", function () {
        var protocol = $('input[name=rdAddZoneForwarderProtocol]:checked').val();
        switch (protocol) {
            case "Udp":
            case "Tcp":
                $("#txtAddZoneForwarder").attr("placeholder", "8.8.8.8 oder [2620:fe::10]")
                break;

            case "Tls":
            case "Quic":
                $("#txtAddZoneForwarder").attr("placeholder", "dns.quad9.net (9.9.9.9:853)")
                break;

            case "Https":
                $("#txtAddZoneForwarder").attr("placeholder", "https://cloudflare-dns.com/dns-query (1.1.1.1)")
                break;
        }
    });

    $("input[type=radio][name=rdAddZoneForwarderProxyType]").on("change", function () {
        var proxyType = $('input[name=rdAddZoneForwarderProxyType]:checked').val();
        var disabled = (proxyType === "NoProxy") || (proxyType === "DefaultProxy");

        $("#txtAddZoneForwarderProxyAddress").prop("disabled", disabled);
        $("#txtAddZoneForwarderProxyPort").prop("disabled", disabled);
        $("#txtAddZoneForwarderProxyUsername").prop("disabled", disabled);
        $("#txtAddZoneForwarderProxyPassword").prop("disabled", disabled);
    });

    $("input[type=radio][name=rdQueryAccess]").on("change", function () {
        $("#txtQueryAccessNetworkACL").prop("disabled", $("input[name=rdQueryAccess]:checked").val() !== "UseSpecifiedNetworkACL");
    });

    $("#chkZonesTableCheckAll").on("click", function () {
        var checked = $("#chkZonesTableCheckAll").prop("checked");
        var checkboxes = $("#tableZonesBody").find("input:checkbox");

        for (var i = 0; i < checkboxes.length; i++)
            $(checkboxes[i]).prop("checked", checked);
    });

    $("#txtEditZoneFilterName").on("input", function () {
        editZoneFilteredRecords = null;
    });

    $("#txtEditZoneFilterType").on("input", function () {
        editZoneFilteredRecords = null;
    });

    $("input[type=radio][name=rdImportZoneType]").on("change", function () {
        var rdImportZoneType = $("input[name=rdImportZoneType]:checked").val();
        switch (rdImportZoneType) {
            case "File":
                $("#divImportZoneFile").show();
                $("#divImportZoneTextEditor").hide();
                break;

            case "Text":
                $("#divImportZoneFile").hide();
                $("#divImportZoneTextEditor").show();
                break;
        }
    });

    $("#chkAddEditRecordDataTxtSplitText").on("click", function () {
        var splitText = $("#chkAddEditRecordDataTxtSplitText").prop("checked");
        if (!splitText) {
            var text = $("#txtAddEditRecordDataTxt").val();
            text = text.replace(/\n/g, "");
            $("#txtAddEditRecordDataTxt").val(text);
        }
    });

    $("input[type=radio][name=rdAddEditRecordDataForwarderProtocol]").on("change", updateAddEditFormForwarderPlaceholder);

    $("input[type=radio][name=rdAddEditRecordDataForwarderProxyType]").on("change", updateAddEditFormForwarderProxyType);

    $("#optAddEditRecordDataAppName").on("change", function () {
        if (appsList == null)
            return;

        var appName = $("#optAddEditRecordDataAppName").val();
        var optClassPaths = "<option></option>";

        for (var i = 0; i < appsList.length; i++) {
            if (appsList[i].name == appName) {
                for (var j = 0; j < appsList[i].dnsApps.length; j++) {
                    if (appsList[i].dnsApps[j].isAppRecordRequestHandler)
                        optClassPaths += "<option>" + appsList[i].dnsApps[j].classPath + "</option>";
                }

                break;
            }
        }

        $("#optAddEditRecordDataClassPath").html(optClassPaths);
        $("#txtAddEditRecordDataData").val("");
    });

    $("#optAddEditRecordDataClassPath").on("change", function () {
        if (appsList == null)
            return;

        var appName = $("#optAddEditRecordDataAppName").val();
        var classPath = $("#optAddEditRecordDataClassPath").val();

        for (var i = 0; i < appsList.length; i++) {
            if (appsList[i].name == appName) {
                for (var j = 0; j < appsList[i].dnsApps.length; j++) {
                    if (appsList[i].dnsApps[j].classPath == classPath) {
                        $("#txtAddEditRecordDataData").val(appsList[i].dnsApps[j].recordDataTemplate);
                        return;
                    }
                }
            }
        }

        $("#txtAddEditRecordDataData").val("");
    });

    $("#optZonesPerPage").on("change", function () {
        localStorage.setItem("optZonesPerPage", $("#optZonesPerPage").val());
    });

    var optZonesPerPage = localStorage.getItem("optZonesPerPage");
    if (optZonesPerPage != null)
        $("#optZonesPerPage").val(optZonesPerPage);

    $("#optEditZoneRecordsPerPage").on("change", function () {
        localStorage.setItem("optEditZoneRecordsPerPage", $("#optEditZoneRecordsPerPage").val());
    });

    var optEditZoneRecordsPerPage = localStorage.getItem("optEditZoneRecordsPerPage");
    if (optEditZoneRecordsPerPage != null)
        $("#optEditZoneRecordsPerPage").val(optEditZoneRecordsPerPage);
});

function getPaginationHtml(pageNumber, totalPages, onClickFunction) {
    var paginationHtml = "";

    if (pageNumber > 1) {
        paginationHtml += "<li><a href=\"#\" aria-label=\"Erste Seite\" onClick=\"" + onClickFunction + "(1); return false;\"><span aria-hidden=\"true\">&laquo;</span></a></li>";
        paginationHtml += "<li><a href=\"#\" aria-label=\"Vorherige Seite\" onClick=\"" + onClickFunction + "(" + (pageNumber - 1) + "); return false;\"><span aria-hidden=\"true\">&lsaquo;</span></a></li>";
    }

    var pageStart = pageNumber - 5;
    if (pageStart < 1)
        pageStart = 1;

    var pageEnd = pageStart + 9;
    if (pageEnd > totalPages) {
        var endDiff = pageEnd - totalPages;
        pageEnd = totalPages;

        pageStart -= endDiff;
        if (pageStart < 1)
            pageStart = 1;
    }

    for (var i = pageStart; i <= pageEnd; i++) {
        if (i == pageNumber)
            paginationHtml += "<li class=\"active\"><a href=\"#\" onClick=\"" + onClickFunction + "(" + i + "); return false;\">" + i + "</a></li>";
        else
            paginationHtml += "<li><a href=\"#\" onClick=\"" + onClickFunction + "(" + i + "); return false;\">" + i + "</a></li>";
    }

    if (pageNumber < totalPages) {
        paginationHtml += "<li><a href=\"#\" aria-label=\"Nächste Seite\" onClick=\"" + onClickFunction + "(" + (pageNumber + 1) + "); return false;\"><span aria-hidden=\"true\">&rsaquo;</span></a></li>";
        paginationHtml += "<li><a href=\"#\" aria-label=\"Letzte Seite\" onClick=\"" + onClickFunction + "(-1); return false;\"><span aria-hidden=\"true\">&raquo;</span></a></li>";
    }

    return paginationHtml;
}

function refreshZonesPage(pageNumber) {
    refreshZones(false, pageNumber);
}

function refreshZones(checkDisplay, pageNumber) {
    if (checkDisplay == null)
        checkDisplay = false;

    var divViewZones = $("#divViewZones");

    if (checkDisplay) {
        if (divViewZones.css("display") === "none")
            return;

        if (($("#tableZonesBody").html().length > 0) && !$("#resolverTabPaneZones").hasClass("active"))
            return;
    }

    var filterName = $("#txtZonesFilterName").val();

    if (pageNumber == null) {
        pageNumber = $("#txtZonesPageNumber").val();
        if (pageNumber == "")
            pageNumber = 1;
    }

    var zonesPerPage = Number($("#optZonesPerPage").val());
    if (zonesPerPage < 1)
        zonesPerPage = 10;

    var divViewZonesLoader = $("#divViewZonesLoader");
    var divEditZone = $("#divEditZone");

    divViewZones.hide();
    divEditZone.hide();
    divViewZonesLoader.show();

    HTTPRequest({
        url: "api/zones/list?filterName=" + encodeURIComponent(filterName) + "&filterType=Forwarder&pageNumber=" + pageNumber + "&zonesPerPage=" + zonesPerPage,
        token: sessionData.token,
        success: function (responseJSON) {
            var zones = responseJSON.response.zones;
            var firstRowNumber = ((responseJSON.response.pageNumber - 1) * zonesPerPage) + 1;
            var lastRowNumber = firstRowNumber + (zones.length - 1);
            var tableHtmlRows = "";

            for (var i = 0; i < zones.length; i++) {
                var id = Math.floor(Math.random() * 10000);
                var name = zones[i].name;

                if (name === "")
                    name = ".";

                var status;

                if (zones[i].disabled)
                    status = "<span id=\"tdZoneStatus" + id + "\" class=\"label label-default\">Deaktiviert</span>";
                else
                    status = "<span id=\"tdZoneStatus" + id + "\" class=\"label label-success\">Aktiv</span>";

                var lastModified = zones[i].lastModified;
                if (lastModified == null)
                    lastModified = "&nbsp;";
                else
                    lastModified = moment(lastModified).local().format("DD.MM.YYYY HH:mm");

                tableHtmlRows += "<tr id=\"trZone" + id + "\"><td><input type=\"checkbox\" data-zone=\"" + htmlEncode(name) + "\"" + (zones[i].nameIdn == null ? "" : " data-zone-idn=\"" + htmlEncode(zones[i].nameIdn) + "\"") + " /></td>";
                tableHtmlRows += "<td>" + (firstRowNumber + i) + "</td>";

                if (zones[i].nameIdn == null)
                    tableHtmlRows += "<td style=\"word-break: break-word; max-width: 480px;\"><a href=\"#\" style=\"font-weight: bold;\" onclick=\"showEditZone(" + jsArg(name) + "); return false;\">" + htmlEncode(name === "." ? "<root>" : name) + "</a></td>";
                else
                    tableHtmlRows += "<td style=\"word-break: break-word; max-width: 480px;\"><a href=\"#\" style=\"font-weight: bold;\" onclick=\"showEditZone(" + jsArg(name) + "); return false;\">" + htmlEncode(zones[i].nameIdn + " (" + name + ")") + "</a></td>";

                tableHtmlRows += "<td>" + status + "</td>";
                tableHtmlRows += "<td>" + lastModified + "</td>";

                tableHtmlRows += "<td align=\"right\"><div class=\"dropdown\"><a href=\"#\" id=\"btnZoneRowOption" + id + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
                tableHtmlRows += "<li><a href=\"#\" onclick=\"showEditZone(" + jsArg(name) + "); return false;\">Einträge bearbeiten</a></li>";
                tableHtmlRows += "<li><a href=\"#\" onclick=\"showEditZoneFileModal(" + jsArg(name) + "); return false;\">Zonendatei bearbeiten</a></li>";
                tableHtmlRows += "<li id=\"mnuEnableZone" + id + "\"" + (zones[i].disabled ? "" : " style=\"display: none;\"") + "><a href=\"#\" data-id=\"" + id + "\" data-zone=\"" + htmlEncode(name) + "\" onclick=\"enableZoneMenu(this); return false;\">Aktivieren</a></li>";
                tableHtmlRows += "<li id=\"mnuDisableZone" + id + "\"" + (!zones[i].disabled ? "" : " style=\"display: none;\"") + "><a href=\"#\" data-id=\"" + id + "\" data-zone=\"" + htmlEncode(name) + "\" onclick=\"disableZoneMenu(this); return false;\">Deaktivieren</a></li>";
                tableHtmlRows += "<li><a href=\"#\" onclick=\"$('#btnSaveZoneOptions').attr('data-zones-row-id', " + id + "); showZoneOptionsModal(" + jsArg(name) + "); return false;\">Zonenoptionen</a></li>";
                tableHtmlRows += "<li><a href=\"#\" onclick=\"showZonePermissionsModal(" + jsArg(name) + "); return false;\">Berechtigungen</a></li>";
                tableHtmlRows += "<li role=\"separator\" class=\"divider\"></li>";
                tableHtmlRows += "<li><a href=\"#\" onclick=\"showImportZoneModal(" + jsArg(name) + "); return false;\">Einträge importieren</a></li>";
                tableHtmlRows += "<li><a href=\"#\" onclick=\"exportZone(" + jsArg(name) + "); return false;\">Zone exportieren</a></li>";
                tableHtmlRows += "<li><a href=\"#\" onclick=\"showCloneZoneModal(" + jsArg(name) + "); return false;\">Zone klonen</a></li>";
                tableHtmlRows += "<li role=\"separator\" class=\"divider\"></li>";
                tableHtmlRows += "<li><a href=\"#\" data-id=\"" + id + "\" data-zone=\"" + htmlEncode(name) + "\" onclick=\"deleteZoneMenu(this); return false;\">Zone löschen</a></li>";
                tableHtmlRows += "</ul></div></td></tr>";
            }

            if (zones.length == 0)
                tableHtmlRows = "<tr><td colspan=\"6\" align=\"center\">Noch keine Weiterleitungszonen angelegt</td></tr>";

            var paginationHtml = getPaginationHtml(responseJSON.response.pageNumber, responseJSON.response.totalPages, "refreshZonesPage");
            var statusHtml;

            if (zones.length > 0)
                statusHtml = firstRowNumber + "–" + lastRowNumber + " von " + responseJSON.response.totalZones + " Zonen (Seite " + responseJSON.response.pageNumber + " von " + responseJSON.response.totalPages + ")";
            else
                statusHtml = "0 Zonen";

            $("#txtZonesPageNumber").val(responseJSON.response.pageNumber);
            $("#chkZonesTableCheckAll").prop("checked", false);
            $("#tableZonesBody").html(tableHtmlRows);

            $("#tableZonesTopStatus").html(statusHtml);
            $("#tableZonesTopPagination").html(paginationHtml);

            $("#tableZonesFooterStatus").html(statusHtml);
            $("#tableZonesFooterPagination").html(paginationHtml);

            divViewZonesLoader.hide();
            divViewZones.show();

            $("#txtZonesFilterName").focus();
        },
        error: function () {
            divViewZonesLoader.hide();
            divViewZones.show();
        },
        invalidToken: function () {
            divViewZonesLoader.hide();
            showPageLogin();
        },
        objLoaderPlaceholder: divViewZonesLoader
    });
}

function enableZoneMenu(objMenuItem) {
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var zone = mnuItem.attr("data-zone");

    var btn = $("#btnZoneRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<span class='spinner spinner-sm' role='status' aria-label='Wird geladen'></span>");

    HTTPRequest({
        url: "api/zones/enable?zone=" + encodeURIComponent(zone),
        token: sessionData.token,
        success: function (responseJSON) {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);

            $("#mnuEnableZone" + id).hide();
            $("#mnuDisableZone" + id).show();
            $("#tdZoneStatus" + id).attr("class", "label label-success");
            $("#tdZoneStatus" + id).html("Aktiv");

            showAlert("success", "Zone aktiviert", "Zone '" + zone + "' ist aktiv.");
        },
        error: function () {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function enableZone(objBtn) {
    var zone = $("#titleEditZone").attr("data-zone");

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/zones/enable?zone=" + encodeURIComponent(zone),
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");

            $("#btnEnableZoneEditZone").hide();
            $("#btnDisableZoneEditZone").show();
            $("#titleEditZoneStatus").attr("class", "label label-success");
            $("#titleEditZoneStatus").html("Aktiv");

            showAlert("success", "Zone aktiviert", "Zone '" + zone + "' ist aktiv.");
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

function disableZoneMenu(objMenuItem) {
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var zone = mnuItem.attr("data-zone");

    if (!confirm("Zone '" + zone + "' deaktivieren?"))
        return;

    var btn = $("#btnZoneRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<span class='spinner spinner-sm' role='status' aria-label='Wird geladen'></span>");

    HTTPRequest({
        url: "api/zones/disable?zone=" + encodeURIComponent(zone),
        token: sessionData.token,
        success: function (responseJSON) {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);

            $("#mnuEnableZone" + id).show();
            $("#mnuDisableZone" + id).hide();
            $("#tdZoneStatus" + id).attr("class", "label label-default");
            $("#tdZoneStatus" + id).html("Deaktiviert");

            showAlert("success", "Zone deaktiviert", "Zone '" + zone + "' ist deaktiviert.");
        },
        error: function () {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function disableZone(objBtn) {
    var zone = $("#titleEditZone").attr("data-zone");

    if (!confirm("Zone '" + zone + "' deaktivieren?"))
        return;

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/zones/disable?zone=" + encodeURIComponent(zone),
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");

            $("#btnEnableZoneEditZone").show();
            $("#btnDisableZoneEditZone").hide();
            $("#titleEditZoneStatus").attr("class", "label label-default");
            $("#titleEditZoneStatus").html("Deaktiviert");

            showAlert("success", "Zone deaktiviert", "Zone '" + zone + "' ist deaktiviert.");
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

function deleteSelectedZones(objBtn) {
    var checkboxes = $("#tableZonesBody").find("input:checkbox");
    var zones;
    var zonesList;

    for (var i = 0; i < checkboxes.length; i++) {
        var checkbox = $(checkboxes[i]);

        if (checkbox.prop("checked")) {
            var zone = checkbox.attr("data-zone");
            var zoneIdn = checkbox.attr("data-zone-idn");

            if (zones == null)
                zones = zone;
            else
                zones += "," + zone;

            var zoneName;

            if (zoneIdn == null)
                zoneName = zone;
            else
                zoneName = zoneIdn + " (" + zone + ")";

            if (zonesList == null)
                zonesList = zoneName;
            else
                zonesList += "\n" + zoneName;
        }
    }

    if (zones == null) {
        alert("Bitte mindestens eine Zone zum Löschen auswählen.");
        return;
    }

    if (!confirm("Folgende Zonen samt allen Einträgen endgültig löschen?\n\n" + zonesList))
        return;

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/zones/delete?zones=" + encodeURIComponent(zones),
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");
            refreshZones();

            var failCount = Object.keys(responseJSON.response.failed).length;
            if (failCount == 0)
                showAlert("success", "Zonen gelöscht", "Die ausgewählten Zonen wurden gelöscht.");
            else
                showAlert("warning", "Löschen fehlgeschlagen", "Insgesamt " + failCount + " von " + (responseJSON.response.deleted.length + failCount) + " ausgewählten Zonen konnten nicht gelöscht werden. Details stehen im Serverprotokoll.");
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

function deleteZoneMenu(objMenuItem) {
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var zone = mnuItem.attr("data-zone");

    if (!confirm("Zone '" + zone + "' samt allen Einträgen endgültig löschen?"))
        return;

    var btn = $("#btnZoneRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<span class='spinner spinner-sm' role='status' aria-label='Wird geladen'></span>");

    HTTPRequest({
        url: "api/zones/delete?zone=" + encodeURIComponent(zone),
        token: sessionData.token,
        success: function (responseJSON) {
            refreshZones();

            showAlert("success", "Zone gelöscht", "Zone '" + zone + "' wurde gelöscht.");
        },
        error: function () {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function deleteZone(objBtn) {
    var zone = $("#titleEditZone").attr("data-zone");

    if (!confirm("Zone '" + zone + "' samt allen Einträgen endgültig löschen?"))
        return;

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/zones/delete?zone=" + encodeURIComponent(zone),
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");
            refreshZones();

            showAlert("success", "Zone gelöscht", "Zone '" + zone + "' wurde gelöscht.");
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

function showEditZoneFileModal(zone) {
    var divEditZoneFileAlert = $("#divEditZoneFileAlert");
    var divEditZoneFileLoader = $("#divEditZoneFileLoader");
    var divEditZoneFile = $("#divEditZoneFile");

    $("#lblEditZoneFileName").text(zone);

    divEditZoneFileLoader.show();
    divEditZoneFile.hide();

    $("#btnEditZoneFile").button("reset");

    $("#modalEditZoneFile").modal("show");

    HTTPRequest({
        url: "api/zones/export?zone=" + encodeURIComponent(zone),
        token: sessionData.token,
        isTextResponse: true,
        success: function (response) {
            divEditZoneFileLoader.hide();

            if (response.status != null)
                response = JSON.stringify(response, null, 2);

            $("#txtEditZoneFileText").val(response);
            divEditZoneFile.show();
        },
        error: function () {
            divEditZoneFileLoader.hide();
        },
        invalidToken: function () {
            $("#modalEditZoneFile").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divEditZoneFileAlert,
        objLoaderPlaceholder: divEditZoneFileLoader
    });
}

function saveEditZoneFile() {
    var divEditZoneFileAlert = $("#divEditZoneFileAlert");

    var zone = $("#lblEditZoneFileName").text();
    var formData = $("#txtEditZoneFileText").val();;

    var btn = $("#btnEditZoneFile");
    btn.button("loading");

    HTTPRequest({
        url: "api/zones/import?zone=" + encodeURIComponent(zone) + "&overwriteZone=true",
        token: sessionData.token,
        method: "POST",
        data: formData,
        contentType: "text/plain",
        processData: false,
        success: function (responseJSON) {
            $("#modalEditZoneFile").modal("hide");

            if ($("#divEditZone").is(":visible"))
                showEditZone(zone);

            showAlert("success", "Zone gespeichert", "Die Zonendatei wurde gespeichert.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalEditZoneFile").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divEditZoneFileAlert
    });
}

function showImportZoneModal(zone) {
    $("#lblImportZoneName").text(zone);
    $("#divImportZoneAlert").html("");

    $("#rdImportZoneTypeFile").prop("checked", true);
    $("#chkImportZoneOverwrite").prop("checked", true);
    $("#chkImportZoneOverwriteZone").prop("checked", false);

    $("#divImportZoneFile").show();
    $("#fileImportZone").val("");

    $("#divImportZoneTextEditor").hide();
    $("#txtImportZoneText").val("");

    $("#btnImportZone").button("reset");

    $("#modalImportZone").modal("show");

    setTimeout(function () {
        $("#txtImportZoneText").trigger("focus");
    }, 1000);
}

function importZone() {
    var divImportZoneAlert = $("#divImportZoneAlert");

    var zone = $("#lblImportZoneName").text();
    var importType = $("input[name=rdImportZoneType]:checked").val();
    var overwrite = $("#chkImportZoneOverwrite").prop("checked");
    var overwriteZone = $("#chkImportZoneOverwriteZone").prop("checked");

    var formData;
    var contentType;

    switch (importType) {
        case "File":
            var fileImportZone = $("#fileImportZone");

            if (fileImportZone[0].files.length === 0) {
                showAlert("warning", "Angabe fehlt", "Bitte eine Zonendatei auswählen.", divImportZoneAlert);
                fileImportZone.trigger("focus");
                return;
            }

            formData = new FormData();
            formData.append("fileImportZone", fileImportZone[0].files[0]);
            contentType = false;
            break;

        default:
            formData = $("#txtImportZoneText").val();
            contentType = "text/plain";
            break;
    }

    var btn = $("#btnImportZone");
    btn.button("loading");

    HTTPRequest({
        url: "api/zones/import?zone=" + encodeURIComponent(zone) + "&overwrite=" + overwrite + "&overwriteZone=" + overwriteZone,
        token: sessionData.token,
        method: "POST",
        data: formData,
        contentType: contentType,
        processData: false,
        success: function (responseJSON) {
            $("#modalImportZone").modal("hide");

            if ($("#divEditZone").is(":visible"))
                showEditZone(zone);

            showAlert("success", "Importiert", "Die Einträge wurden importiert.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalImportZone").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divImportZoneAlert
    });
}

function exportZone(zone) {
    HTTPRequest({
        url: "api/user/createSingleUseToken",
        token: sessionData.token,
        success: function (responseJSON) {
            window.open("api/zones/export?token=" + responseJSON.response.token + "&zone=" + encodeURIComponent(zone), "_blank");

            showAlert("success", "Exportiert", "Die Zone wurde exportiert.");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function showCloneZoneModal(sourceZone) {
    $("#lblCloneZoneZoneName").text(sourceZone === "." ? "<root>" : sourceZone);

    $("#divCloneZoneAlert").html("");
    $("#txtCloneZoneSourceZoneName").val(sourceZone);
    $("#txtCloneZoneZoneName").val("");

    $("#modalCloneZone").modal("show");

    setTimeout(function () {
        $("#txtCloneZoneZoneName").trigger("focus");
    }, 1000);
}

function cloneZone(objBtn) {
    var divCloneZoneAlert = $("#divCloneZoneAlert");

    var sourceZone = $("#txtCloneZoneSourceZoneName").val();

    var zone = $("#txtCloneZoneZoneName").val();
    if ((zone == null) || (zone === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte die Domain der neuen Zone eingeben.", divCloneZoneAlert);
        $("#txtCloneZoneZoneName").trigger("focus");
        return;
    }

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/zones/clone?zone=" + encodeURIComponent(zone) + "&sourceZone=" + encodeURIComponent(sourceZone),
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");
            $("#modalCloneZone").modal("hide");

            if ($("#divEditZone").is(":hidden"))
                refreshZones();

            showAlert("success", "Zone geklont", "Die Zone wurde geklont.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalCloneZone").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divCloneZoneAlert
    });
}

function showZoneOptionsModal(zone) {
    var divZoneOptionsAlert = $("#divZoneOptionsAlert");
    var divZoneOptionsLoader = $("#divZoneOptionsLoader");
    var divZoneOptions = $("#divZoneOptions");

    $("#lblZoneOptionsZoneName").text(zone === "." ? "<root>" : zone);
    $("#lblZoneOptionsZoneName").attr("data-zone", zone);
    divZoneOptionsLoader.show();
    divZoneOptions.hide();

    $("#modalZoneOptions").modal("show");

    HTTPRequest({
        url: "api/zones/options/get?zone=" + encodeURIComponent(zone),
        token: sessionData.token,
        success: function (responseJSON) {
            var queryAccess = responseJSON.response.queryAccess;

            switch (queryAccess) {
                case "Deny":
                case "AllowOnlyPrivateNetworks":
                case "UseSpecifiedNetworkACL":
                    $("#rdQueryAccess" + queryAccess).prop("checked", true);
                    break;

                default:
                    $("#rdQueryAccessAllow").prop("checked", true);
                    break;
            }

            $("#txtQueryAccessNetworkACL").val(getArrayAsString(responseJSON.response.queryAccessNetworkACL));
            $("#txtQueryAccessNetworkACL").prop("disabled", queryAccess !== "UseSpecifiedNetworkACL");

            divZoneOptionsLoader.hide();
            divZoneOptions.show();
        },
        error: function () {
            divZoneOptionsLoader.hide();
        },
        invalidToken: function () {
            $("#modalZoneOptions").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divZoneOptionsAlert,
        objLoaderPlaceholder: divZoneOptionsLoader
    });
}

function saveZoneOptions() {
    var divZoneOptionsAlert = $("#divZoneOptionsAlert");
    var divZoneOptionsLoader = $("#divZoneOptionsLoader");
    var zone = $("#lblZoneOptionsZoneName").attr("data-zone");

    var queryAccess = $("input[name=rdQueryAccess]:checked").val();

    var queryAccessNetworkACL = cleanTextList($("#txtQueryAccessNetworkACL").val());
    if ((queryAccessNetworkACL.length === 0) || (queryAccessNetworkACL === ","))
        queryAccessNetworkACL = false;
    else
        $("#txtQueryAccessNetworkACL").val(queryAccessNetworkACL.replace(/,/g, "\n"));

    if ((queryAccess === "UseSpecifiedNetworkACL") && (queryAccessNetworkACL === false)) {
        showAlert("warning", "Angabe fehlt", "Bitte mindestens einen Eintrag für die Zugriffsliste angeben.", divZoneOptionsAlert);
        $("#txtQueryAccessNetworkACL").trigger("focus");
        return;
    }

    var btn = $("#btnSaveZoneOptions");
    btn.button("loading");

    HTTPRequest({
        url: "api/zones/options/set?zone=" + encodeURIComponent(zone) + "&queryAccess=" + queryAccess + "&queryAccessNetworkACL=" + encodeURIComponent(queryAccessNetworkACL),
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");
            $("#modalZoneOptions").modal("hide");

            showAlert("success", "Gespeichert", "Die Zonenoptionen wurden übernommen.");
        },
        error: function () {
            btn.button("reset");
            divZoneOptionsLoader.hide();
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalZoneOptions").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divZoneOptionsAlert
    });
}

function showZonePermissionsModal(zone) {
    var divEditPermissionsAlert = $("#divEditPermissionsAlert");
    var divEditPermissionsLoader = $("#divEditPermissionsLoader");
    var divEditPermissionsViewer = $("#divEditPermissionsViewer");

    $("#lblEditPermissionsName").text("Weiterleitungszonen / " + (zone === "." ? "<root>" : zone));
    $("#tbodyEditPermissionsUser").html("");
    $("#tbodyEditPermissionsGroup").html("");

    divEditPermissionsLoader.show();
    divEditPermissionsViewer.hide();

    var btnEditPermissionsSave = $("#btnEditPermissionsSave");
    btnEditPermissionsSave.attr("onclick", "saveZonePermissions(this); return false;");
    btnEditPermissionsSave.show();

    var modalEditPermissions = $("#modalEditPermissions");
    modalEditPermissions.modal("show");

    HTTPRequest({
        url: "api/zones/permissions/get?zone=" + encodeURIComponent(zone) + "&includeUsersAndGroups=true",
        token: sessionData.token,
        success: function (responseJSON) {
            $("#lblEditPermissionsName").text(getPermissionSectionLabel(responseJSON.response.section) + " / " + (responseJSON.response.subItem == "." ? "<root>" : responseJSON.response.subItem));

            for (var i = 0; i < responseJSON.response.userPermissions.length; i++) {
                addEditPermissionUserRow(i, responseJSON.response.userPermissions[i].username, responseJSON.response.userPermissions[i].canView, responseJSON.response.userPermissions[i].canModify, responseJSON.response.userPermissions[i].canDelete);
            }

            var userListHtml = "<option value=\"blank\" selected></option><option value=\"none\">Leeren</option>";

            for (var i = 0; i < responseJSON.response.users.length; i++) {
                userListHtml += "<option>" + htmlEncode(responseJSON.response.users[i]) + "</option>";
            }

            $("#optEditPermissionsUserList").html(userListHtml);

            for (var i = 0; i < responseJSON.response.groupPermissions.length; i++) {
                addEditPermissionGroupRow(i, responseJSON.response.groupPermissions[i].name, responseJSON.response.groupPermissions[i].canView, responseJSON.response.groupPermissions[i].canModify, responseJSON.response.groupPermissions[i].canDelete);
            }

            var groupListHtml = "<option value=\"blank\" selected></option><option value=\"none\">Leeren</option>";

            for (var i = 0; i < responseJSON.response.groups.length; i++) {
                groupListHtml += "<option>" + htmlEncode(responseJSON.response.groups[i]) + "</option>";
            }

            $("#optEditPermissionsGroupList").html(groupListHtml);

            btnEditPermissionsSave.attr("data-zone", responseJSON.response.subItem);

            divEditPermissionsLoader.hide();
            divEditPermissionsViewer.show();
        },
        error: function () {
            divEditPermissionsLoader.hide();
        },
        invalidToken: function () {
            modalEditPermissions.modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divEditPermissionsAlert,
        objLoaderPlaceholder: divEditPermissionsLoader
    });
}

function saveZonePermissions(objBtn) {
    var btn = $(objBtn);
    var divEditPermissionsAlert = $("#divEditPermissionsAlert");

    var zone = btn.attr("data-zone");

    var userPermissions = serializeTableData($("#tableEditPermissionsUser"), 4);
    var groupPermissions = serializeTableData($("#tableEditPermissionsGroup"), 4);

    var apiUrl = "api/zones/permissions/set?zone=" + encodeURIComponent(zone) + "&userPermissions=" + encodeURIComponent(userPermissions) + "&groupPermissions=" + encodeURIComponent(groupPermissions);

    btn.button("loading");

    HTTPRequest({
        url: apiUrl,
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");
            $("#modalEditPermissions").modal("hide");

            showAlert("success", "Berechtigungen gespeichert", "Die Berechtigungen der Zone wurden gespeichert.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalEditPermissions").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divEditPermissionsAlert
    });
}

function showAddZoneModal() {
    $("#divAddZoneAlert").html("");

    $("#txtAddZone").val("");
    $("#chkAddZoneInitializeForwarder").prop("checked", true);
    $("#fileAddZoneImportZone").val("");
    $("input[name=rdAddZoneForwarderProtocol]:radio").attr("disabled", false);
    $("#rdAddZoneForwarderProtocolUdp").prop("checked", true);
    $("#chkAddZoneForwarderThisServer").prop("checked", false);
    $("#txtAddZoneForwarder").prop("disabled", false);
    $("#txtAddZoneForwarder").attr("placeholder", "8.8.8.8 oder [2620:fe::10]")
    $("#txtAddZoneForwarder").val("");
    $("#chkAddZoneForwarderDnssecValidation").prop("checked", $("#chkDnssecValidation").prop("checked"));
    $("#rdAddZoneForwarderProxyTypeDefaultProxy").prop("checked", true);
    $("#txtAddZoneForwarderProxyAddress").prop("disabled", true);
    $("#txtAddZoneForwarderProxyPort").prop("disabled", true);
    $("#txtAddZoneForwarderProxyUsername").prop("disabled", true);
    $("#txtAddZoneForwarderProxyPassword").prop("disabled", true);
    $("#txtAddZoneForwarderProxyAddress").val("");
    $("#txtAddZoneForwarderProxyPort").val("");
    $("#txtAddZoneForwarderProxyUsername").val("");
    $("#txtAddZoneForwarderProxyPassword").val("");

    updateAddZoneFormInitializeForwarder();

    $("#btnAddZone").button("reset");

    $("#modalAddZone").modal("show");

    setTimeout(function () {
        $("#txtAddZone").trigger("focus");
    }, 1000);
}

function updateAddZoneFormInitializeForwarder() {
    var initializeForwarder = $("#chkAddZoneInitializeForwarder").prop("checked");
    var useThisServer = $("#chkAddZoneForwarderThisServer").prop("checked");

    $("#divAddZoneImportZoneFile").toggle(!initializeForwarder);
    $("#divAddZoneForwarderProtocol").toggle(initializeForwarder);
    $("#divAddZoneForwarder").toggle(initializeForwarder);
    $("#divAddZoneForwarderDnssecValidation").toggle(initializeForwarder);
    $("#divAddZoneForwarderProxy").toggle(initializeForwarder && !useThisServer);
}

function updateAddZoneFormForwarderThisServer() {
    var useThisServer = $("#chkAddZoneForwarderThisServer").prop('checked');

    if (useThisServer) {
        $("input[name=rdAddZoneForwarderProtocol]:radio").attr("disabled", true);
        $("#rdAddZoneForwarderProtocolUdp").prop("checked", true);
        $("#txtAddZoneForwarder").attr("placeholder", "8.8.8.8 oder [2620:fe::10]")

        $("#txtAddZoneForwarder").prop("disabled", true);
        $("#txtAddZoneForwarder").val("this-server");
    }
    else {
        $("input[name=rdAddZoneForwarderProtocol]:radio").attr("disabled", false);

        $("#txtAddZoneForwarder").prop("disabled", false);
        $("#txtAddZoneForwarder").val("");
    }

    updateAddZoneFormInitializeForwarder();
}

function addZone() {
    var divAddZoneAlert = $("#divAddZoneAlert");
    var zone = $("#txtAddZone").val();

    if ((zone == null) || (zone === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte die Domain für die Zone eingeben.", divAddZoneAlert);
        $("#txtAddZone").trigger("focus");
        return;
    }

    var parameters;
    var initializeForwarder = $("#chkAddZoneInitializeForwarder").prop("checked");

    if (initializeForwarder) {
        var protocol = $("input[name=rdAddZoneForwarderProtocol]:checked").val();

        var forwarder = $("#txtAddZoneForwarder").val();
        if ((forwarder == null) || (forwarder === "")) {
            showAlert("warning", "Angabe fehlt", "Bitte die Adresse des Zielservers eingeben.", divAddZoneAlert);
            $("#txtAddZoneForwarder").trigger("focus");
            return;
        }

        var dnssecValidation = $("#chkAddZoneForwarderDnssecValidation").prop("checked");

        parameters = "&protocol=" + protocol + "&forwarder=" + encodeURIComponent(forwarder) + "&dnssecValidation=" + dnssecValidation;

        if (forwarder !== "this-server") {
            var proxyType = $("input[name=rdAddZoneForwarderProxyType]:checked").val();

            parameters += "&proxyType=" + proxyType;

            switch (proxyType) {
                case "Http":
                case "Socks5":
                    var proxyAddress = $("#txtAddZoneForwarderProxyAddress").val();
                    var proxyPort = $("#txtAddZoneForwarderProxyPort").val();
                    var proxyUsername = $("#txtAddZoneForwarderProxyUsername").val();
                    var proxyPassword = $("#txtAddZoneForwarderProxyPassword").val();

                    if ((proxyAddress == null) || (proxyAddress === "")) {
                        showAlert("warning", "Angabe fehlt", "Bitte die Adresse des Proxys eingeben.", divAddZoneAlert);
                        $("#txtAddZoneForwarderProxyAddress").trigger("focus");
                        return;
                    }

                    if ((proxyPort == null) || (proxyPort === "")) {
                        showAlert("warning", "Angabe fehlt", "Bitte den Port des Proxys eingeben.", divAddZoneAlert);
                        $("#txtAddZoneForwarderProxyPort").trigger("focus");
                        return;
                    }

                    parameters += "&proxyAddress=" + encodeURIComponent(proxyAddress) + "&proxyPort=" + proxyPort + "&proxyUsername=" + encodeURIComponent(proxyUsername) + "&proxyPassword=" + encodeURIComponent(proxyPassword);
                    break;
            }
        }

        parameters += "&initializeForwarder=true";
    }
    else {
        parameters = "&initializeForwarder=false";
    }

    var formData;
    var fileAddZoneImportZone = $("#fileAddZoneImportZone");

    if (!initializeForwarder && (fileAddZoneImportZone[0].files.length > 0)) {
        formData = new FormData();
        formData.append("fileImportZone", fileAddZoneImportZone[0].files[0]);
    }

    var btn = $("#btnAddZone");
    btn.button("loading");

    HTTPRequest({
        url: "api/zones/create?zone=" + encodeURIComponent(zone) + "&type=Forwarder" + parameters,
        token: sessionData.token,
        method: "POST",
        data: formData,
        contentType: false,
        processData: false,
        success: function (responseJSON) {
            $("#modalAddZone").modal("hide");
            showEditZone(responseJSON.response.domain);

            showAlert("success", "Zone angelegt", "Die Weiterleitungszone wurde angelegt.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalAddZone").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divAddZoneAlert
    });
}

function showEditZone(zone, showPageNumber, zoneFilterName, zoneFilterType) {
    if (zone == null)
        return;

    if (showPageNumber == null)
        showPageNumber = 1;

    if (zoneFilterName == null)
        zoneFilterName = "";

    if (zoneFilterType == null)
        zoneFilterType = "";

    var divViewZonesLoader = $("#divViewZonesLoader");
    var divViewZones = $("#divViewZones");
    var divEditZone = $("#divEditZone");

    divViewZones.hide();
    divEditZone.hide();
    divViewZonesLoader.show();

    HTTPRequest({
        url: "api/zones/records/get?domain=" + encodeURIComponent(zone) + "&zone=" + encodeURIComponent(zone) + "&listZone=true",
        token: sessionData.token,
        success: function (responseJSON) {
            zone = responseJSON.response.zone.name;
            if (zone === "")
                zone = ".";

            if (responseJSON.response.zone.disabled) {
                $("#titleEditZoneStatus").text("Deaktiviert");
                $("#titleEditZoneStatus").attr("class", "label label-default");
                $("#btnEnableZoneEditZone").show();
                $("#btnDisableZoneEditZone").hide();
            }
            else {
                $("#titleEditZoneStatus").text("Aktiv");
                $("#titleEditZoneStatus").attr("class", "label label-success");
                $("#btnEnableZoneEditZone").hide();
                $("#btnDisableZoneEditZone").show();
            }

            $("#titleEditZoneType").text("Weiterleitungszone");
            $("#btnEditZoneAddRecord").show();
            editZoneInfo = responseJSON.response.zone;
            editZoneRecords = [];

            var records = responseJSON.response.records;

            for (var i = 0; i < records.length; i++) {
                if (records[i].type.toUpperCase() !== "SOA")
                    editZoneRecords.push(records[i]);
            }

            if (responseJSON.response.zone.nameIdn == null)
                $("#titleEditZone").text(zone === "." ? "<root>" : zone);
            else
                $("#titleEditZone").text(responseJSON.response.zone.nameIdn + " (" + zone + ")");

            $("#titleEditZone").attr("data-zone", zone);
            $("#titleEditZone").attr("data-zone-type", responseJSON.response.zone.type);

            $("#txtEditZoneFilterName").val(zoneFilterName);
            $("#txtEditZoneFilterType").val(zoneFilterType);
            editZoneFilteredRecords = null;

            showEditZonePage(showPageNumber);

            divViewZonesLoader.hide();
            divEditZone.show();
        },
        error: function () {
            divViewZonesLoader.hide();
            divViewZones.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divViewZonesLoader
    });
}

function showEditZonePage(pageNumber) {
    var filterName = $("#txtEditZoneFilterName").val();
    if (filterName === "")
        filterName = null;

    var filterType = $("#txtEditZoneFilterType").val();
    if (filterType === "")
        filterType = null;

    if (pageNumber == null)
        pageNumber = Number($("#txtEditZonePageNumber").val());

    if (pageNumber == 0)
        pageNumber = 1;

    var recordsPerPage = Number($("#optEditZoneRecordsPerPage").val());
    if (recordsPerPage < 1)
        recordsPerPage = 10;

    var zone = $("#titleEditZone").attr("data-zone");
    var zoneType = $("#titleEditZone").attr("data-zone-type");

    if (editZoneFilteredRecords == null) {
        if ((filterName != null) || (filterType != null)) {
            editZoneFilteredRecords = [];
            var filterDomain = null;
            var filterRegex = null;

            if (filterName != null) {
                filterDomain = filterName.toLowerCase();

                if (zone == ".") {
                    if (filterDomain === "@")
                        filterDomain = "";
                }
                else {
                    if (filterDomain === "@")
                        filterDomain = zone;
                    else
                        filterDomain += "." + zone;
                }

                if ((filterName.indexOf("*") > -1) || (filterName.indexOf("?") > -1)) {
                    filterDomain = filterDomain.replace(/\./g, "\\\.");
                    filterDomain = filterDomain.replace(/\*/g, ".*");
                    filterDomain = filterDomain.replace(/\?/g, ".");

                    if (filterDomain.startsWith(".*\\\."))
                        filterDomain = "\\\*" + filterDomain.substring(2);

                    filterRegex = new RegExp("^" + filterDomain + "$");
                }
            }

            if (filterType != null)
                filterType = filterType.toUpperCase();

            for (var i = 0; i < editZoneRecords.length; i++) {
                if (filterRegex == null) {
                    if ((filterDomain != null) && (editZoneRecords[i].name.toLowerCase() !== filterDomain))
                        continue;
                }
                else if (!filterRegex.test(editZoneRecords[i].name.toLowerCase())) {
                    continue;
                }

                if ((filterType != null) && (editZoneRecords[i].type !== filterType))
                    continue;

                editZoneRecords[i].index = i;

                editZoneFilteredRecords.push(editZoneRecords[i]);
            }
        }
        else {
            for (var i = 0; i < editZoneRecords.length; i++)
                editZoneRecords[i].index = i;

            editZoneFilteredRecords = editZoneRecords;
        }
    }

    var totalRecords = editZoneFilteredRecords.length;
    var totalPages = Math.floor(totalRecords / recordsPerPage) + (totalRecords % recordsPerPage > 0 ? 1 : 0);

    if ((pageNumber > totalPages) || (pageNumber < 0))
        pageNumber = totalPages;

    if (pageNumber < 1)
        pageNumber = 1;

    var start = (pageNumber - 1) * recordsPerPage;
    var end = Math.min(start + recordsPerPage, totalRecords);

    var tableHtmlRows = "";

    for (var i = start; i < end; i++)
        tableHtmlRows += getZoneRecordRowHtml(i, zone, zoneType, editZoneFilteredRecords[i]);

    var paginationHtml = "";

    if (pageNumber > 1) {
        paginationHtml += "<li><a href=\"#\" aria-label=\"First\" onClick=\"showEditZonePage(1); return false;\"><span aria-hidden=\"true\">&laquo;</span></a></li>";
        paginationHtml += "<li><a href=\"#\" aria-label=\"Zurück\" onClick=\"showEditZonePage(" + (pageNumber - 1) + "); return false;\"><span aria-hidden=\"true\">&lsaquo;</span></a></li>";
    }

    var pageStart = pageNumber - 5;
    if (pageStart < 1)
        pageStart = 1;

    var pageEnd = pageStart + 9;
    if (pageEnd > totalPages) {
        var endDiff = pageEnd - totalPages;
        pageEnd = totalPages;

        pageStart -= endDiff;
        if (pageStart < 1)
            pageStart = 1;
    }

    for (var i = pageStart; i <= pageEnd; i++) {
        if (i == pageNumber)
            paginationHtml += "<li class=\"active\"><a href=\"#\" onClick=\"showEditZonePage(" + i + "); return false;\">" + i + "</a></li>";
        else
            paginationHtml += "<li><a href=\"#\" onClick=\"showEditZonePage(" + i + "); return false;\">" + i + "</a></li>";
    }

    if (pageNumber < totalPages) {
        paginationHtml += "<li><a href=\"#\" aria-label=\"Weiter\" onClick=\"showEditZonePage(" + (pageNumber + 1) + "); return false;\"><span aria-hidden=\"true\">&rsaquo;</span></a></li>";
        paginationHtml += "<li><a href=\"#\" aria-label=\"Last\" onClick=\"showEditZonePage(-1); return false;\"><span aria-hidden=\"true\">&raquo;</span></a></li>";
    }

    var statusHtml;

    if (editZoneFilteredRecords.length > 0)
        statusHtml = (start + 1) + "–" + end + " von " + editZoneFilteredRecords.length + " Einträgen (Seite " + pageNumber + " von " + totalPages + ")";
    else
        statusHtml = "0 Einträge";

    $("#txtEditZonePageNumber").val(pageNumber);
    $("#tableEditZoneBody").html(tableHtmlRows);

    $("#tableEditZoneTopStatus").html(statusHtml);
    $("#tableEditZoneTopPagination").html(paginationHtml);

    $("#tableEditZoneFooterStatus").html(statusHtml);
    $("#tableEditZoneFooterPagination").html(paginationHtml);
}

function getProxyTypeLabel(proxyType) {
    switch (proxyType) {
        case "NoProxy":
            return "kein Proxy";

        case "DefaultProxy":
            return "Standard-Proxy des Servers";

        case "Http":
            return "HTTP";

        case "Socks5":
            return "SOCKS5";

        default:
            return proxyType;
    }
}

function getZoneRecordRowHtml(index, zone, zoneType, record) {
    var name = record.name;
    if (name === "")
        name = ".";

    var lowerName = name.toLowerCase();

    if (lowerName === zone) {
        name = "@";
    } else {
        var i = lowerName.lastIndexOf("." + zone)
        if (i > -1)
            name = name.substring(0, i);
    }

    var tableHtmlRow = "<tr id=\"trZoneRecord" + index + "\"><td>" + (index + 1) + "</td><td>" + htmlEncode(name) + "</td>";
    tableHtmlRow += "<td>" + record.type + "</td>";
    tableHtmlRow += "<td>" + record.ttl + "<br />(" + record.ttlString + ")</td>";

    var additionalDataAttributes = "";

    tableHtmlRow += "<td style=\"word-break: break-all;\">";

    switch (record.type.toUpperCase()) {
        case "A":
        case "AAAA":
            tableHtmlRow += htmlEncode(record.rData.ipAddress);
            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-ip-address=\"" + htmlEncode(record.rData.ipAddress) + "\" ";
            break;

        case "NS":
            tableHtmlRow += "<b>Nameserver:</b> " + htmlEncode(record.rData.nameServer);

            if (record.glueRecords != null) {
                var glue = null;

                for (var i = 0; i < record.glueRecords.length; i++) {
                    if (i == 0)
                        glue = record.glueRecords[i];
                    else
                        glue += ", " + record.glueRecords[i];
                }

                tableHtmlRow += "<br /><b>Glue-Adressen:</b> " + glue;

                additionalDataAttributes = "data-record-glue=\"" + htmlEncode(glue) + "\" ";
            } else {
                additionalDataAttributes = "data-record-glue=\"\" ";
            }

            tableHtmlRow += "<br /><br />";

            additionalDataAttributes += "data-record-name-server=\"" + htmlEncode(record.rData.nameServer) + "\" ";
            break;

        case "CNAME":
            tableHtmlRow += htmlEncode(record.rData.cname);
            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-cname=\"" + htmlEncode(record.rData.cname) + "\" ";
            break;

        case "PTR":
            tableHtmlRow += htmlEncode(record.rData.ptrName);
            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-ptr-name=\"" + htmlEncode(record.rData.ptrName) + "\" ";
            break;

        case "MX":
            tableHtmlRow += "<b>Priorität: </b> " + htmlEncode(record.rData.preference) +
                "<br /><b>Mailserver:</b> " + htmlEncode(record.rData.exchange);

            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-preference=\"" + htmlEncode(record.rData.preference) + "\" " +
                "data-record-exchange=\"" + htmlEncode(record.rData.exchange) + "\" ";
            break;

        case "TXT":
            var text;

            if (record.rData.splitText) {
                for (var i = 0; i < record.rData.characterStrings.length; i++) {
                    var characterString = record.rData.characterStrings[i].replace(/\\/g, "\\\\").replace(/\r/g, "\\r").replace(/\n/g, "\\n");

                    tableHtmlRow += "\"" + htmlEncode(characterString.replace(/"/g, "\\\"")) + "\"<br />";

                    if (text == null)
                        text = characterString;
                    else
                        text += "\n" + characterString;
                }
            }
            else {
                var characterString = record.rData.text.replace(/\\/g, "\\\\").replace(/\r/g, "\\r").replace(/\n/g, "\\n");
                tableHtmlRow += htmlEncode(characterString.replace(/"/g, "\\\"")) + "<br />";

                text = record.rData.text;
            }

            tableHtmlRow += "<br />";

            var b64CharacterStrings;

            for (var i = 0; i < record.rData.characterStringsBase64.length; i++) {
                if (b64CharacterStrings == null)
                    b64CharacterStrings = record.rData.characterStringsBase64[i];
                else
                    b64CharacterStrings += "," + record.rData.characterStringsBase64[i];
            }

            additionalDataAttributes = "data-record-text=\"" + htmlEncode(text) + "\" data-record-character-strings-base64=\"" + htmlEncode(b64CharacterStrings) + "\" " +
                "data-record-split-text=\"" + htmlEncode(record.rData.splitText) + "\" ";
            break;

        case "RP":
            tableHtmlRow += "<b>Postfach: </b> " + htmlEncode(record.rData.mailbox) +
                "<br /><b>TXT-Domain:</b> " + htmlEncode(record.rData.txtDomain);

            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-mailbox=\"" + htmlEncode(record.rData.mailbox) + "\" " +
                "data-record-txt-domain=\"" + htmlEncode(record.rData.txtDomain) + "\" ";
            break;

        case "SRV":
            tableHtmlRow += "<b>Priorität: </b> " + htmlEncode(record.rData.priority) +
                "<br /><b>Gewichtung:</b> " + htmlEncode(record.rData.weight) +
                "<br /><b>Port:</b> " + htmlEncode(record.rData.port) +
                "<br /><b>Ziel:</b> " + htmlEncode(record.rData.target);

            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-priority=\"" + htmlEncode(record.rData.priority) + "\" " +
                "data-record-weight=\"" + htmlEncode(record.rData.weight) + "\" " +
                "data-record-port=\"" + htmlEncode(record.rData.port) + "\" " +
                "data-record-target=\"" + htmlEncode(record.rData.target) + "\" ";
            break;

        case "NAPTR":
            tableHtmlRow += "<b>Reihenfolge: </b> " + htmlEncode(record.rData.order) +
                "<br /><b>Priorität:</b> " + htmlEncode(record.rData.preference) +
                "<br /><b>Flags:</b> " + htmlEncode(record.rData.flags) +
                "<br /><b>Dienste:</b> " + htmlEncode(record.rData.services) +
                "<br /><b>Regulärer Ausdruck:</b> " + htmlEncode(record.rData.regexp) +
                "<br /><b>Ersetzung:</b> " + htmlEncode(record.rData.replacement);

            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-order=\"" + htmlEncode(record.rData.order) + "\" " +
                "data-record-preference=\"" + htmlEncode(record.rData.preference) + "\" " +
                "data-record-flags=\"" + htmlEncode(record.rData.flags) + "\" " +
                "data-record-services=\"" + htmlEncode(record.rData.services) + "\" " +
                "data-record-regexp=\"" + htmlEncode(record.rData.regexp) + "\" " +
                "data-record-replacement=\"" + htmlEncode(record.rData.replacement) + "\" ";
            break;

        case "DNAME":
            tableHtmlRow += htmlEncode(record.rData.dname);
            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-dname=\"" + htmlEncode(record.rData.dname) + "\" ";
            break;

        case "APL":
            tableHtmlRow += "<table class=\"table\" style=\"background: transparent;\"><thead><tr><th>Adressfamilie</th><th>Negation</th><th>AFD-Teil</th><th>Präfix</th></tr></thead><tbody>";

            for (var i = 0; i < record.rData.addressPrefixes.length; i++) {
                tableHtmlRow += "<tr><td>" + record.rData.addressPrefixes[i].addressFamily + "</td>";
                tableHtmlRow += "<td>" + record.rData.addressPrefixes[i].negation + "</td>";
                tableHtmlRow += "<td>" + record.rData.addressPrefixes[i].afdPart + "</td>";
                tableHtmlRow += "<td>" + record.rData.addressPrefixes[i].prefix + "</td></tr>";
            }

            tableHtmlRow += "</tbody></table>";

            additionalDataAttributes = "";
            break;

        case "SVCB":
        case "HTTPS":
            var tableHtmlSvcParams;

            if (Object.keys(record.rData.svcParams).length == 0) {
                tableHtmlSvcParams = "<br />";
            }
            else {
                tableHtmlSvcParams = "<br /><b>Parameter: </b><table class=\"table table-condensed\" style=\"background: transparent; margin-bottom: 0px;\">" +
                    "<thead><tr>" +
                    "<th>Schlüssel</th>" +
                    "<th>Wert</th>" +
                    "</thead>" +
                    "<tbody>";

                for (var paramKey in record.rData.svcParams) {
                    switch (paramKey) {
                        case "ipv4hint":
                            if (record.rData.autoIpv4Hint)
                                continue;

                            break;

                        case "ipv6hint":
                            if (record.rData.autoIpv6Hint)
                                continue;

                            break;
                    }

                    tableHtmlSvcParams += "<tr><td>" + htmlEncode(paramKey) + "</td><td>" + htmlEncode(record.rData.svcParams[paramKey]) + "</td></tr>";
                }

                tableHtmlSvcParams += "</tbody></table>";
            }

            tableHtmlRow += "<b>Priorität: </b> " + htmlEncode(record.rData.svcPriority) + (record.rData.svcPriority == 0 ? " (alias mode)" : " (service mode)") +
                "<br /><b>Zielname: </b> " + (record.rData.svcTargetName == "" ? "." : htmlEncode(record.rData.svcTargetName)) +
                tableHtmlSvcParams +
                "<br /><b>IPv4-Hint automatisch: </b> " + record.rData.autoIpv4Hint +
                "<br /><b>IPv6-Hint automatisch: </b> " + record.rData.autoIpv6Hint +
                "<br />";

            tableHtmlRow += "<br />";

            additionalDataAttributes = "data-record-svc-priority=\"" + htmlEncode(record.rData.svcPriority) + "\"" +
                "data-record-svc-target-name=\"" + (record.rData.svcTargetName == "" ? "." : htmlEncode(record.rData.svcTargetName)) + "\"" +
                "data-record-svc-params=\"" + htmlEncode(JSON.stringify(record.rData.svcParams)) + "\"" +
                "data-record-auto-ipv4hint=\"" + htmlEncode(record.rData.autoIpv4Hint) + "\"" +
                "data-record-auto-ipv6hint=\"" + htmlEncode(record.rData.autoIpv6Hint) + "\"";
            break;

        case "URI":
            tableHtmlRow += "<b>Priorität: </b> " + htmlEncode(record.rData.priority) +
                "<br /><b>Gewichtung:</b> " + htmlEncode(record.rData.weight) +
                "<br /><b>URI:</b> " + htmlEncode(record.rData.uri);

            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-priority=\"" + htmlEncode(record.rData.priority) + "\" " +
                "data-record-weight=\"" + htmlEncode(record.rData.weight) + "\" " +
                "data-record-uri=\"" + htmlEncode(record.rData.uri) + "\" ";
            break;

        case "CAA":
            tableHtmlRow += "<b>Flags: </b> " + htmlEncode(record.rData.flags) +
                "<br /><b>Tag:</b> " + htmlEncode(record.rData.tag) +
                "<br /><b>Authority:</b> " + htmlEncode(record.rData.value);

            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-flags=\"" + htmlEncode(record.rData.flags) + "\" " +
                "data-record-tag=\"" + htmlEncode(record.rData.tag) + "\" " +
                "data-record-value=\"" + htmlEncode(record.rData.value) + "\" ";
            break;

        case "ANAME":
            tableHtmlRow += "" + htmlEncode(record.rData.aname);
            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-aname=\"" + htmlEncode(record.rData.aname) + "\" ";
            break;

        case "FWD":
            tableHtmlRow += "<b>Protokoll: </b> " + htmlEncode(record.rData.protocol) +
                "<br /><b>Forwarder:</b> " + (record.rData.forwarder == "this-server" ? "Dieser Server (rekursiv)" : htmlEncode(record.rData.forwarder)) +
                "<br /><b>Priorität:</b> " + htmlEncode(record.rData.priority) +
                "<br /><b>DNSSEC-Validierung:</b> " + (record.rData.dnssecValidation ? "ja" : "nein") +
                "<br /><b>Proxy:</b> " + htmlEncode(getProxyTypeLabel(record.rData.proxyType));

            switch (record.rData.proxyType) {
                case "Http":
                case "Socks5":
                    tableHtmlRow += "<br /><b>Proxy-Adresse:</b> " + htmlEncode(record.rData.proxyAddress) +
                        "<br /><b>Proxy-Port:</b> " + htmlEncode(record.rData.proxyPort) +
                        "<br /><b>Proxy-Benutzer:</b> " + htmlEncode(record.rData.proxyUsername) +
                        "<br /><b>Proxy-Passwort:</b> ************";
                    break;
            }

            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-protocol=\"" + htmlEncode(record.rData.protocol) + "\" " +
                "data-record-forwarder=\"" + htmlEncode(record.rData.forwarder) + "\" " +
                "data-record-priority=\"" + htmlEncode(record.rData.priority) + "\" " +
                "data-record-dnssec-validation=\"" + htmlEncode(record.rData.dnssecValidation) + "\" " +
                "data-record-proxy-type=\"" + htmlEncode(record.rData.proxyType) + "\" ";

            switch (record.rData.proxyType) {
                case "Http":
                case "Socks5":
                    additionalDataAttributes += "data-record-proxy-address=\"" + htmlEncode(record.rData.proxyAddress) + "\" " +
                        "data-record-proxy-port=\"" + htmlEncode(record.rData.proxyPort) + "\" " +
                        "data-record-proxy-username=\"" + htmlEncode(record.rData.proxyUsername) + "\" " +
                        "data-record-proxy-password=\"" + htmlEncode(record.rData.proxyPassword) + "\" ";
                    break;
            }
            break;

        case "APP":
            tableHtmlRow += "<b>App: </b> " + htmlEncode(record.rData.appName) +
                "<br /><b>Klassenpfad:</b> " + htmlEncode(record.rData.classPath) +
                "<br /><b>Daten:</b> " + (record.rData.data == "" ? "<br />" : "<pre style=\"white-space: pre-wrap;\">" + htmlEncode(record.rData.data) + "</pre>");

            tableHtmlRow += "<br />";

            additionalDataAttributes = "data-record-app-name=\"" + htmlEncode(record.rData.appName) + "\" " +
                "data-record-classpath=\"" + htmlEncode(record.rData.classPath) + "\" " +
                "data-record-data=\"" + htmlEncode(record.rData.data) + "\"";
            break;

        case "ALIAS":
            tableHtmlRow += "<b>Typ: </b> " + htmlEncode(record.rData.type) +
                "<br /><b>Alias:</b> " + htmlEncode(record.rData.alias);

            tableHtmlRow += "<br /><br />";
            break;

        default:
            tableHtmlRow += "<b>RDATA:</b> " + htmlEncode(record.rData.value);
            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-rdata=\"" + htmlEncode(record.rData.value) + "\"";
            break;
    }

    if (record.expiryTtl > 0) {
        var expiresOn = moment(record.lastModified).add(record.expiryTtl, "s");
        tableHtmlRow += "<b>Ablaufzeit:</b> " + record.expiryTtl + " (" + record.expiryTtlString + ")";
        tableHtmlRow += "<br /><b>Läuft ab am:</b> " + expiresOn.local().format("DD.MM.YYYY HH:mm:ss") + " (" + expiresOn.fromNow() + ")";
        tableHtmlRow += "<br />";
    }

    if ((record.lastUsedOn == "0001-01-01T00:00:00") || (record.lastUsedOn == "0001-01-01T00:00:00Z"))
        tableHtmlRow += "<b>Zuletzt genutzt:</b> nie";
    else
        tableHtmlRow += "<b>Zuletzt genutzt:</b> " + moment(record.lastUsedOn).local().format("DD.MM.YYYY HH:mm:ss") + " (" + moment(record.lastUsedOn).fromNow() + ")";

    if ((record.lastModified != "0001-01-01T00:00:00") && (record.lastModified != "0001-01-01T00:00:00Z"))
        tableHtmlRow += "<br /><b>Zuletzt geändert:</b> " + moment(record.lastModified).local().format("DD.MM.YYYY HH:mm:ss") + " (" + moment(record.lastModified).fromNow() + ")";

    if ((record.comments != null) && (record.comments.length > 0))
        tableHtmlRow += "<br /><b>Kommentar:</b> <pre style=\"white-space: pre-wrap;\">" + htmlEncode(record.comments) + "</pre>";

    tableHtmlRow += "</td>";

    tableHtmlRow += "<td class=\"record-actions\">";
    tableHtmlRow += "<div id=\"data" + index + "\" data-record-index=\"" + (record.index == null ? index : record.index) + "\" data-record-name=\"" + htmlEncode(record.name) + "\" data-record-type=\"" + record.type + "\" data-record-ttl=\"" + record.ttl + "\" " + additionalDataAttributes + " data-record-disabled=\"" + record.disabled + "\" data-record-comments=\"" + htmlEncode(record.comments) + "\" data-record-expiry-ttl=\"" + record.expiryTtl + "\" style=\"display: none;\"></div>";
    tableHtmlRow += "<button type=\"button\" class=\"btn btn-primary btn-xs\" data-id=\"" + index + "\" onclick=\"showEditRecordModal(this);\">Bearbeiten</button>";
    tableHtmlRow += "<button type=\"button\" class=\"btn btn-default btn-xs\" id=\"btnEnableRecord" + index + "\"" + (record.disabled ? "" : " style=\"display: none;\"") + " data-id=\"" + index + "\" onclick=\"updateRecordState(this, false);\" data-loading-text=\"Aktiviere...\">Aktivieren</button>";
    tableHtmlRow += "<button type=\"button\" class=\"btn btn-warning btn-xs\" id=\"btnDisableRecord" + index + "\"" + (!record.disabled ? "" : " style=\"display: none;\"") + " data-id=\"" + index + "\" onclick=\"updateRecordState(this, true);\" data-loading-text=\"Deaktiviere...\">Deaktivieren</button>";
    tableHtmlRow += "<button type=\"button\" class=\"btn btn-danger btn-xs\" data-loading-text=\"Lösche...\" data-id=\"" + index + "\" onclick=\"deleteRecord(this);\">Löschen</button></td>";

    tableHtmlRow += "</tr>";

    return tableHtmlRow;
}

function clearAddEditRecordForm() {
    $("#divAddEditRecordAlert").html("");

    $("#txtAddEditRecordName").prop("placeholder", "@");
    $("#txtAddEditRecordName").prop("disabled", false);
    $("#optAddEditRecordType").prop("disabled", false);
    $("#txtAddEditRecordTtl").prop("disabled", false);

    $("#txtAddEditRecordName").val("");
    $("#optAddEditRecordType").val("A");
    $("#txtAddEditRecordTtl").val("");
    $("#txtAddEditRecordTtl").attr("placeholder", sessionData.info.defaultRecordTtl);
    $("#spanAddEditRecordTtlUnit").text("Sekunden (Standard " + sessionData.info.defaultRecordTtl + ")");

    $("#divAddEditRecordData").show();
    $("#divAddEditRecordDataUnknownType").hide();
    $("#txtAddEditRecordDataUnknownType").val("");
    $("#txtAddEditRecordDataUnknownType").prop("disabled", false);
    $("#lblAddEditRecordDataValue").text("IPv4-Adresse");
    $("#txtAddEditRecordDataValue").val("");
    $("#divAddEditRecordDataPtr").show();
    $("#chkAddEditRecordDataPtr").prop("checked", false);
    $("#chkAddEditRecordDataCreatePtrZone").prop("disabled", true);
    $("#chkAddEditRecordDataCreatePtrZone").prop("checked", false);
    $("#chkAddEditRecordDataPtrLabel").text("Reverse-Eintrag (PTR) anlegen");

    $("#divAddEditRecordDataNs").hide();
    $("#txtAddEditRecordDataNsNameServer").prop("disabled", false);
    $("#txtAddEditRecordDataNsNameServer").val("");
    $("#txtAddEditRecordDataNsGlue").prop("disabled", false);
    $("#txtAddEditRecordDataNsGlue").val("");


    $("#divAddEditRecordDataMx").hide();
    $("#txtAddEditRecordDataMxPreference").val("");
    $("#txtAddEditRecordDataMxExchange").val("");

    $("#divAddEditRecordDataTxt").hide();
    $("#txtAddEditRecordDataTxt").val("");
    $("#chkAddEditRecordDataTxtSplitText").prop("checked", false);

    $("#divAddEditRecordDataSrv").hide();
    $("#txtAddEditRecordDataSrvPriority").val("");
    $("#txtAddEditRecordDataSrvWeight").val("");
    $("#txtAddEditRecordDataSrvPort").val("");
    $("#txtAddEditRecordDataSrvTarget").val("");

    $("#divAddEditRecordDataNaptr").hide();
    $("#txtAddEditRecordDataNaptrOrder").val("");
    $("#txtAddEditRecordDataNaptrPreference").val("");
    $("#txtAddEditRecordDataNaptrFlags").val("");
    $("#txtAddEditRecordDataNaptrServices").val("");
    $("#txtAddEditRecordDataNaptrRegExp").val("");
    $("#txtAddEditRecordDataNaptrReplacement").val("");
    $("#divAddEditRecordDataSvcb").hide();
    $("#txtAddEditRecordDataSvcbPriority").val("");
    $("#txtAddEditRecordDataSvcbTargetName").val("");
    $("#tableAddEditRecordDataSvcbParams").html("");
    $("#chkAddEditRecordDataSvcbAutoIpv4Hint").prop("checked", false);
    $("#chkAddEditRecordDataSvcbAutoIpv6Hint").prop("checked", false);

    $("#divAddEditRecordDataUri").hide();
    $("#txtAddEditRecordDataUriPriority").val("");
    $("#txtAddEditRecordDataUriWeight").val("");
    $("#txtAddEditRecordDataUri").val("");

    $("#divAddEditRecordDataCaa").hide();
    $("#txtAddEditRecordDataCaaFlags").val("");
    $("#txtAddEditRecordDataCaaTag").val("");
    $("#txtAddEditRecordDataCaaValue").val("");

    $("#divAddEditRecordDataForwarder").hide();
    $("#rdAddEditRecordDataForwarderProtocolUdp").prop("checked", true);
    $("input[name=rdAddEditRecordDataForwarderProtocol]:radio").attr("disabled", false);
    $("#chkAddEditRecordDataForwarderThisServer").prop("checked", false);
    $('#txtAddEditRecordDataForwarder').prop("disabled", false);
    $("#txtAddEditRecordDataForwarder").attr("placeholder", "8.8.8.8 or [2620:fe::10]")
    $("#txtAddEditRecordDataForwarder").val("");
    $("#txtAddEditRecordDataForwarderPriority").val("");
    $("#chkAddEditRecordDataForwarderDnssecValidation").prop("checked", $("#chkDnssecValidation").prop("checked"));
    $("#rdAddEditRecordDataForwarderProxyTypeDefaultProxy").prop("checked", true);
    $("#txtAddEditRecordDataForwarderProxyAddress").prop("disabled", true);
    $("#txtAddEditRecordDataForwarderProxyPort").prop("disabled", true);
    $("#txtAddEditRecordDataForwarderProxyUsername").prop("disabled", true);
    $("#txtAddEditRecordDataForwarderProxyPassword").prop("disabled", true);
    $("#txtAddEditRecordDataForwarderProxyAddress").val("");
    $("#txtAddEditRecordDataForwarderProxyPort").val("");
    $("#txtAddEditRecordDataForwarderProxyUsername").val("");
    $("#txtAddEditRecordDataForwarderProxyPassword").val("");

    $("#divAddEditRecordDataApplication").hide();
    $("#optAddEditRecordDataAppName").html("");
    $("#optAddEditRecordDataAppName").prop("disabled", false);
    $("#optAddEditRecordDataClassPath").html("");
    $("#optAddEditRecordDataClassPath").prop("disabled", false);
    $("#txtAddEditRecordDataData").val("");

    $("#divAddEditRecordOverwrite").show();
    $("#chkAddEditRecordOverwrite").prop("checked", false);

    $("#txtAddEditRecordComments").val("");

    $("#divAddEditRecordExpiryTtl").show();
    $("#txtAddEditRecordExpiryTtl").prop("disabled", false);
    $("#txtAddEditRecordExpiryTtl").val("");

    $("#btnAddEditRecord").button("reset");
}

function showAddRecordModal() {
    var zone = $("#titleEditZone").attr("data-zone");

    var lastType = $("#optAddEditRecordType").val();

    clearAddEditRecordForm();

    if (zone.endsWith(".in-addr.arpa") || zone.endsWith(".ip6.arpa")) {
        $("#optAddEditRecordType").val("PTR");
        modifyAddRecordFormByType(true);
    }
    else {
        $("#optAddEditRecordType").val(lastType);
        modifyAddRecordFormByType(true);
    }

    $("#titleAddEditRecord").text("Eintrag hinzufügen");
    $("#lblAddEditRecordZoneName").text(zone === "." ? "" : zone);
    $("#btnAddEditRecord").attr("onclick", "addRecord(); return false;");

    $("#modalAddEditRecord").modal("show");

    setTimeout(function () {
        $("#txtAddEditRecordName").trigger("focus");
    }, 1000);
}

var appsList;

function loadAddRecordModalAppNames() {
    var optAddEditRecordDataAppName = $("#optAddEditRecordDataAppName");
    var optAddEditRecordDataClassPath = $("#optAddEditRecordDataClassPath");
    var txtAddEditRecordDataData = $("#txtAddEditRecordDataData");
    var divAddEditRecordAlert = $("#divAddEditRecordAlert");

    optAddEditRecordDataAppName.prop("disabled", true);
    optAddEditRecordDataClassPath.prop("disabled", true);
    txtAddEditRecordDataData.prop("disabled", true);

    optAddEditRecordDataAppName.html("");
    optAddEditRecordDataClassPath.html("");
    txtAddEditRecordDataData.val("");

    HTTPRequest({
        url: "api/apps/list",
        token: sessionData.token,
        success: function (responseJSON) {
            appsList = responseJSON.response.apps;

            var optApps = "<option></option>";
            var optClassPaths = "<option></option>";

            for (var i = 0; i < appsList.length; i++) {
                for (var j = 0; j < appsList[i].dnsApps.length; j++) {
                    if (appsList[i].dnsApps[j].isAppRecordRequestHandler) {
                        optApps += "<option>" + htmlEncode(appsList[i].name) + "</option>";
                        break;
                    }
                }
            }

            $("#optAddEditRecordDataAppName").html(optApps);
            $("#optAddEditRecordDataClassPath").html(optClassPaths);

            optAddEditRecordDataAppName.prop("disabled", false);
            optAddEditRecordDataClassPath.prop("disabled", false);
            txtAddEditRecordDataData.prop("disabled", false);
        },
        invalidToken: function () {
            showPageLogin();
        },
        objAlertPlaceholder: divAddEditRecordAlert
    });
}

function modifyAddRecordFormByType(addMode) {
    $("#divAddEditRecordAlert").html("");

    $("#txtAddEditRecordName").prop("placeholder", "@");
    $("#txtAddEditRecordTtl").prop("disabled", false);
    $("#txtAddEditRecordTtl").val("");
    $("#txtAddEditRecordTtl").attr("placeholder", sessionData.info.defaultRecordTtl);
    $("#spanAddEditRecordTtlUnit").text("Sekunden (Standard " + sessionData.info.defaultRecordTtl + ")");
    $("#txtAddEditRecordDataValue").attr("placeholder", "");

    var type = $("#optAddEditRecordType").val();

    $("#divAddEditRecordData").hide();
    $("#divAddEditRecordDataUnknownType").hide();
    $("#divAddEditRecordDataPtr").hide();
    $("#divAddEditRecordDataNs").hide();
    $("#divAddEditRecordDataMx").hide();
    $("#divAddEditRecordDataTxt").hide();
    $("#divAddEditRecordDataRp").hide();
    $("#divAddEditRecordDataSrv").hide();
    $("#divAddEditRecordDataNaptr").hide();
    $("#divAddEditRecordDataSvcb").hide();
    $("#divAddEditRecordDataUri").hide();
    $("#divAddEditRecordDataCaa").hide();
    $("#divAddEditRecordDataForwarder").hide();
    $("#divAddEditRecordDataApplication").hide();

    switch (type) {
        case "A":
            $("#lblAddEditRecordDataValue").text("IPv4-Adresse");
            $("#txtAddEditRecordDataValue").val("");
            $("#chkAddEditRecordDataPtr").prop("checked", false);
            $("#chkAddEditRecordDataCreatePtrZone").prop('disabled', true);
            $("#chkAddEditRecordDataCreatePtrZone").prop("checked", false);
            $("#chkAddEditRecordDataPtrLabel").text("Reverse-Eintrag (PTR) anlegen");
            $("#divAddEditRecordData").show();
            $("#divAddEditRecordDataPtr").show();
            break;

        case "AAAA":
            $("#lblAddEditRecordDataValue").text("IPv6-Adresse");
            $("#txtAddEditRecordDataValue").val("");
            $("#chkAddEditRecordDataPtr").prop("checked", false);
            $("#chkAddEditRecordDataCreatePtrZone").prop('disabled', true);
            $("#chkAddEditRecordDataCreatePtrZone").prop("checked", false);
            $("#chkAddEditRecordDataPtrLabel").text("Reverse-Eintrag (PTR) anlegen");
            $("#divAddEditRecordData").show();
            $("#divAddEditRecordDataPtr").show();
            break;

        case "NS":
            $("#txtAddEditRecordDataNsNameServer").val("");
            $("#txtAddEditRecordDataNsGlue").val("");
            $("#divAddEditRecordDataNs").show();
            $("#txtAddEditRecordTtl").attr("placeholder", sessionData.info.defaultNsRecordTtl);
            $("#spanAddEditRecordTtlUnit").text("Sekunden (Standard " + sessionData.info.defaultNsRecordTtl + ")");
            break;

        case "PTR":
        case "CNAME":
        case "DNAME":
        case "ANAME":
            $("#lblAddEditRecordDataValue").text("Domainname");
            $("#txtAddEditRecordDataValue").val("");
            $("#divAddEditRecordData").show();
            break;

        case "MX":
            $("#txtAddEditRecordDataMxPreference").val("");
            $("#txtAddEditRecordDataMxExchange").val("");
            $("#divAddEditRecordDataMx").show();
            break;

        case "TXT":
            $("#txtAddEditRecordDataTxt").val("");
            $("#chkAddEditRecordDataTxtSplitText").prop("checked", false);
            $("#divAddEditRecordDataTxt").show();
            break;

        case "RP":
            $("#txtAddEditRecordDataRpMailbox").val("");
            $("#txtAddEditRecordDataRpTxtDomain").val("");
            $("#divAddEditRecordDataRp").show();
            break;

        case "SRV":
            $("#txtAddEditRecordName").prop("placeholder", "_service._protocol.name");
            $("#txtAddEditRecordDataSrvPriority").val("");
            $("#txtAddEditRecordDataSrvWeight").val("");
            $("#txtAddEditRecordDataSrvPort").val("");
            $("#txtAddEditRecordDataSrvTarget").val("");
            $("#divAddEditRecordDataSrv").show();
            break;

        case "NAPTR":
            $("#txtAddEditRecordDataNaptrOrder").val("");
            $("#txtAddEditRecordDataNaptrPreference").val("");
            $("#txtAddEditRecordDataNaptrFlags").val("");
            $("#txtAddEditRecordDataNaptrServices").val("");
            $("#txtAddEditRecordDataNaptrRegExp").val("");
            $("#txtAddEditRecordDataNaptrReplacement").val("");
            $("#divAddEditRecordDataNaptr").show();
            break;

        case "SVCB":
        case "HTTPS":
            $("#txtAddEditRecordName").prop("placeholder", "_port._scheme.name");
            $("#txtAddEditRecordDataSvcbPriority").val("");
            $("#txtAddEditRecordDataSvcbTargetName").val("");
            $("#tableAddEditRecordDataSvcbParams").html("");
            $("#chkAddEditRecordDataSvcbAutoIpv4Hint").prop("checked", false);
            $("#chkAddEditRecordDataSvcbAutoIpv6Hint").prop("checked", false);
            $("#divAddEditRecordDataSvcb").show();
            break;

        case "URI":
            $("#txtAddEditRecordDataUriPriority").val("");
            $("#txtAddEditRecordDataUriWeight").val("");
            $("#txtAddEditRecordDataUri").val("");
            $("#divAddEditRecordDataUri").show();
            break;

        case "CAA":
            $("#txtAddEditRecordDataCaaFlags").val("");
            $("#txtAddEditRecordDataCaaTag").val("");
            $("#txtAddEditRecordDataCaaValue").val("");
            $("#divAddEditRecordDataCaa").show();
            break;

        case "FWD":
            $("#txtAddEditRecordTtl").prop("disabled", true);
            $("#txtAddEditRecordTtl").val("0");
            $("input[name=rdAddEditRecordDataForwarderProtocol]:radio").attr("disabled", false);
            $("#rdAddEditRecordDataForwarderProtocolUdp").prop("checked", true);
            $("#chkAddEditRecordDataForwarderThisServer").prop("checked", false);
            $("#txtAddEditRecordDataForwarder").prop("disabled", false);
            $("#txtAddEditRecordDataForwarder").val("");
            $("#txtAddEditRecordDataForwarderPriority").val("");
            $("#chkAddEditRecordDataForwarderDnssecValidation").prop("checked", $("#chkDnssecValidation").prop("checked"));
            $("#rdAddEditRecordDataForwarderProxyTypeDefaultProxy").prop("checked", true);
            $("#txtAddEditRecordDataForwarderProxyAddress").prop("disabled", true);
            $("#txtAddEditRecordDataForwarderProxyPort").prop("disabled", true);
            $("#txtAddEditRecordDataForwarderProxyUsername").prop("disabled", true);
            $("#txtAddEditRecordDataForwarderProxyPassword").prop("disabled", true);
            $("#txtAddEditRecordDataForwarderProxyAddress").val("");
            $("#txtAddEditRecordDataForwarderProxyPort").val("");
            $("#txtAddEditRecordDataForwarderProxyUsername").val("");
            $("#txtAddEditRecordDataForwarderProxyPassword").val("");
            $("#divAddEditRecordDataForwarder").show();
            $("#divAddEditRecordDataForwarderProxy").show();
            break;

        case "APP":
            $("#optAddEditRecordDataAppName").val("");
            $("#optAddEditRecordDataClassPath").val("");
            $("#txtAddEditRecordDataData").val("");
            $("#divAddEditRecordDataApplication").show();

            if (addMode)
                loadAddRecordModalAppNames();

            break;

        default:
            $("#txtAddEditRecordDataUnknownType").val("");
            $("#lblAddEditRecordDataValue").text("RDATA");
            $("#txtAddEditRecordDataValue").val("");
            $("#txtAddEditRecordDataValue").attr("placeholder", "hex string");

            $("#divAddEditRecordData").show();
            $("#divAddEditRecordDataUnknownType").show();
            break;
    }
}

function zoneHasSvcbAutoHint(ipv4, ipv6) {
    if (editZoneRecords == null)
        return true;

    for (var i = 0; i < editZoneRecords.length; i++) {
        switch (editZoneRecords[i].type) {
            case "SVCB":
            case "HTTPS":
                if ((editZoneRecords[i].rData.autoIpv4Hint && ipv4) || (editZoneRecords[i].rData.autoIpv6Hint && ipv6))
                    return true;

                break;
        }
    }

    return false;
}

function addRecord() {
    var btn = $("#btnAddEditRecord");
    var divAddEditRecordAlert = $("#divAddEditRecordAlert");

    var zone = $("#titleEditZone").attr("data-zone");

    var domain;
    {
        var subDomain = $("#txtAddEditRecordName").val();
        if (subDomain === "")
            subDomain = "@";

        if (subDomain === "@")
            domain = zone;
        else if (zone === ".")
            domain = subDomain + ".";
        else
            domain = subDomain + "." + zone;
    }

    var type = $("#optAddEditRecordType").val();

    var ttl = $("#txtAddEditRecordTtl").val();
    var overwrite = $("#chkAddEditRecordOverwrite").prop("checked");
    var comments = $("#txtAddEditRecordComments").val();
    var expiryTtl = $("#txtAddEditRecordExpiryTtl").val();

    var formData = "";

    switch (type) {
        case "A":
        case "AAAA":
            var ipAddress = $("#txtAddEditRecordDataValue").val();
            if (ipAddress === "") {
                showAlert("warning", "Angabe fehlt", "Bitte eine IP-Adresse eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").trigger("focus");
                return;
            }

            var updateSvcbHints = zoneHasSvcbAutoHint(type == "A", type == "AAAA");

            formData += "&ipAddress=" + encodeURIComponent(ipAddress) + "&ptr=" + $("#chkAddEditRecordDataPtr").prop('checked') + "&createPtrZone=" + $("#chkAddEditRecordDataCreatePtrZone").prop('checked') + "&updateSvcbHints=" + updateSvcbHints;
            break;

        case "NS":
            var nameServer = $("#txtAddEditRecordDataNsNameServer").val();
            if (nameServer === "") {
                showAlert("warning", "Angabe fehlt", "Bitte einen Nameserver eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataNsNameServer").trigger("focus");
                return;
            }

            var glue = cleanTextList($("#txtAddEditRecordDataNsGlue").val());

            formData += "&nameServer=" + encodeURIComponent(nameServer) + "&glue=" + encodeURIComponent(glue);
            break;

        case "CNAME":
            var subDomainName = $("#txtAddEditRecordName").val();
            if ((subDomainName === "") || (subDomainName === "@")) {
                showAlert("warning", "Angabe fehlt", "Bitte einen Namen für den CNAME-Eintrag eingeben. Am Zonenursprung ist CNAME nicht erlaubt; dafür ANAME verwenden.", divAddEditRecordAlert);
                $("#txtAddEditRecordName").trigger("focus");
                return;
            }

            var cname = $("#txtAddEditRecordDataValue").val();
            if (cname === "") {
                showAlert("warning", "Angabe fehlt", "Bitte einen Domainnamen eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").trigger("focus");
                return;
            }

            formData += "&cname=" + encodeURIComponent(cname);
            break;

        case "PTR":
            var ptrName = $("#txtAddEditRecordDataValue").val();
            if (ptrName === "") {
                showAlert("warning", "Angabe fehlt", "Bitte einen gültigen Wert eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").trigger("focus");
                return;
            }

            formData += "&ptrName=" + encodeURIComponent(ptrName);
            break;

        case "MX":
            var preference = $("#txtAddEditRecordDataMxPreference").val();
            if (preference === "")
                preference = 1;

            var exchange = $("#txtAddEditRecordDataMxExchange").val();
            if (exchange === "") {
                showAlert("warning", "Angabe fehlt", "Bitte den Mailserver eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataMxExchange").trigger("focus");
                return;
            }

            formData += "&preference=" + preference + "&exchange=" + encodeURIComponent(exchange);
            break;

        case "TXT":
            var text = $("#txtAddEditRecordDataTxt").val();
            if (text === "") {
                showAlert("warning", "Angabe fehlt", "Bitte einen gültigen Wert eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataTxt").trigger("focus");
                return;
            }

            var splitText = $("#chkAddEditRecordDataTxtSplitText").prop("checked");

            formData += "&text=" + encodeURIComponent(text) + "&splitText=" + splitText;
            break;

        case "RP":
            var mailbox = $("#txtAddEditRecordDataRpMailbox").val();
            if (mailbox === "")
                mailbox = ".";

            var txtDomain = $("#txtAddEditRecordDataRpTxtDomain").val();
            if (txtDomain === "")
                txtDomain = ".";

            formData += "&mailbox=" + encodeURIComponent(mailbox) + "&txtDomain=" + encodeURIComponent(txtDomain);
            break;

        case "SRV":
            if ($("#txtAddEditRecordName").val() === "") {
                showAlert("warning", "Angabe fehlt", "Bitte einen Namen mit Dienst- und Protokoll-Label eingeben (z. B. _sip._tcp).", divAddEditRecordAlert);
                $("#txtAddEditRecordName").trigger("focus");
                return;
            }

            var priority = $("#txtAddEditRecordDataSrvPriority").val();
            if (priority === "") {
                showAlert("warning", "Angabe fehlt", "Bitte eine gültige Priorität eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSrvPriority").trigger("focus");
                return;
            }

            var weight = $("#txtAddEditRecordDataSrvWeight").val();
            if (weight === "") {
                showAlert("warning", "Angabe fehlt", "Bitte eine gültige Gewichtung eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSrvWeight").trigger("focus");
                return;
            }

            var port = $("#txtAddEditRecordDataSrvPort").val();
            if (port === "") {
                showAlert("warning", "Angabe fehlt", "Bitte einen gültigen Port eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSrvPort").trigger("focus");
                return;
            }

            var target = $("#txtAddEditRecordDataSrvTarget").val();
            if (target === "") {
                showAlert("warning", "Angabe fehlt", "Bitte ein gültiges Ziel eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSrvTarget").trigger("focus");
                return;
            }

            formData += "&priority=" + priority + "&weight=" + weight + "&port=" + port + "&target=" + encodeURIComponent(target);
            break;

        case "NAPTR":
            var order = $("#txtAddEditRecordDataNaptrOrder").val();
            if (order === "") {
                showAlert("warning", "Angabe fehlt", "Bitte eine gültige Reihenfolge eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataNaptrOrder").trigger("focus");
                return;
            }

            var preference = $("#txtAddEditRecordDataNaptrPreference").val();
            if (preference === "") {
                showAlert("warning", "Angabe fehlt", "Bitte eine gültige Priorität eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataNaptrPreference").trigger("focus");
                return;
            }

            var flags = $("#txtAddEditRecordDataNaptrFlags").val();
            var services = $("#txtAddEditRecordDataNaptrServices").val();
            var regexp = $("#txtAddEditRecordDataNaptrRegExp").val();
            var replacement = $("#txtAddEditRecordDataNaptrReplacement").val();

            formData += "&naptrOrder=" + order + "&naptrPreference=" + preference + "&naptrFlags=" + encodeURIComponent(flags) + "&naptrServices=" + encodeURIComponent(services) + "&naptrRegexp=" + encodeURIComponent(regexp) + "&naptrReplacement=" + encodeURIComponent(replacement);
            break;

        case "DNAME":
            var dname = $("#txtAddEditRecordDataValue").val();
            if (dname === "") {
                showAlert("warning", "Angabe fehlt", "Bitte einen Domainnamen eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").trigger("focus");
                return;
            }

            formData += "&dname=" + encodeURIComponent(dname);
            break;

        case "SVCB":
        case "HTTPS":
            var svcPriority = $("#txtAddEditRecordDataSvcbPriority").val();
            if ((svcPriority === null) || (svcPriority === "")) {
                showAlert("warning", "Angabe fehlt", "Bitte eine Priorität eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSvcbPriority").trigger("focus");
                return;
            }

            var svcTargetName = $("#txtAddEditRecordDataSvcbTargetName").val();
            if ((svcTargetName === null) || (svcTargetName === "")) {
                showAlert("warning", "Angabe fehlt", "Bitte einen Zielnamen eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSvcbTargetName").trigger("focus");
                return;
            }

            var svcParams = serializeTableData($("#tableAddEditRecordDataSvcbParams"), 2, divAddEditRecordAlert);
            if (svcParams === false)
                return;

            if (svcParams.length === 0)
                svcParams = false;

            var autoIpv4Hint = $("#chkAddEditRecordDataSvcbAutoIpv4Hint").prop("checked");
            var autoIpv6Hint = $("#chkAddEditRecordDataSvcbAutoIpv6Hint").prop("checked");

            formData += "&svcPriority=" + svcPriority + "&svcTargetName=" + encodeURIComponent(svcTargetName) + "&svcParams=" + encodeURIComponent(svcParams) + "&autoIpv4Hint=" + autoIpv4Hint + "&autoIpv6Hint=" + autoIpv6Hint;
            break;

        case "URI":
            var uriPriority = $("#txtAddEditRecordDataUriPriority").val();
            if (uriPriority === "") {
                showAlert("warning", "Angabe fehlt", "Bitte eine gültige Priorität eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataUriPriority").trigger("focus");
                return;
            }

            var uriWeight = $("#txtAddEditRecordDataUriWeight").val();
            if (uriWeight === "") {
                showAlert("warning", "Angabe fehlt", "Bitte eine gültige Gewichtung eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataUriWeight").trigger("focus");
                return;
            }

            var uri = $("#txtAddEditRecordDataUri").val();
            if (uri === "") {
                showAlert("warning", "Angabe fehlt", "Bitte eine gültige URI eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataUri").trigger("focus");
                return;
            }

            formData += "&uriPriority=" + uriPriority + "&uriWeight=" + uriWeight + "&uri=" + encodeURIComponent(uri);
            break;

        case "CAA":
            var flags = $("#txtAddEditRecordDataCaaFlags").val();
            if (flags === "")
                flags = 0;

            var tag = $("#txtAddEditRecordDataCaaTag").val();
            if (tag === "")
                tag = "issue";

            var value = $("#txtAddEditRecordDataCaaValue").val();
            if (value === "") {
                showAlert("warning", "Angabe fehlt", "Bitte eine gültige Authority eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataCaaValue").trigger("focus");
                return;
            }

            formData += "&flags=" + flags + "&tag=" + encodeURIComponent(tag) + "&value=" + encodeURIComponent(value);
            break;

        case "ANAME":
            var aname = $("#txtAddEditRecordDataValue").val();
            if (aname === "") {
                showAlert("warning", "Angabe fehlt", "Bitte einen gültigen Wert eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").trigger("focus");
                return;
            }

            formData += "&aname=" + encodeURIComponent(aname);
            break;

        case "FWD":
            var forwarder = $("#txtAddEditRecordDataForwarder").val();
            if (forwarder === "") {
                showAlert("warning", "Angabe fehlt", "Bitte Domainname, IP-Adresse oder URL des Forwarders eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataForwarder").trigger("focus");
                return;
            }

            var forwarderPriority = $("#txtAddEditRecordDataForwarderPriority").val();
            var dnssecValidation = $("#chkAddEditRecordDataForwarderDnssecValidation").prop("checked");
            var proxyType = $("input[name=rdAddEditRecordDataForwarderProxyType]:checked").val();

            formData += "&protocol=" + $('input[name=rdAddEditRecordDataForwarderProtocol]:checked').val() + "&forwarder=" + encodeURIComponent(forwarder);
            formData += "&forwarderPriority=" + forwarderPriority + "&dnssecValidation=" + dnssecValidation + "&proxyType=" + proxyType;

            switch (proxyType) {
                case "Http":
                case "Socks5":
                    var proxyAddress = $("#txtAddEditRecordDataForwarderProxyAddress").val();
                    var proxyPort = $("#txtAddEditRecordDataForwarderProxyPort").val();
                    var proxyUsername = $("#txtAddEditRecordDataForwarderProxyUsername").val();
                    var proxyPassword = $("#txtAddEditRecordDataForwarderProxyPassword").val();

                    if ((proxyAddress == null) || (proxyAddress === "")) {
                        showAlert("warning", "Angabe fehlt", "Bitte die Proxy-Adresse eingeben.", divAddEditRecordAlert);
                        $("#txtAddEditRecordDataForwarderProxyAddress").trigger("focus");
                        return;
                    }

                    if ((proxyPort == null) || (proxyPort === "")) {
                        showAlert("warning", "Angabe fehlt", "Bitte den Proxy-Port eingeben.", divAddEditRecordAlert);
                        $("#txtAddEditRecordDataForwarderProxyPort").trigger("focus");
                        return;
                    }

                    formData += "&proxyAddress=" + encodeURIComponent(proxyAddress) + "&proxyPort=" + proxyPort + "&proxyUsername=" + encodeURIComponent(proxyUsername) + "&proxyPassword=" + encodeURIComponent(proxyPassword);
                    break;
            }
            break;

        case "APP":
            var appName = $("#optAddEditRecordDataAppName").val();

            if ((appName === null) || (appName === "")) {
                showAlert("warning", "Angabe fehlt", "Bitte eine App auswählen.", divAddEditRecordAlert);
                $("#optAddEditRecordDataAppName").trigger("focus");
                return;
            }

            var classPath = $("#optAddEditRecordDataClassPath").val();

            if ((classPath === null) || (classPath === "")) {
                showAlert("warning", "Angabe fehlt", "Bitte einen Klassenpfad auswählen.", divAddEditRecordAlert);
                $("#optAddEditRecordDataClassPath").trigger("focus");
                return;
            }

            var recordData = $("#txtAddEditRecordDataData").val();

            formData += "&appName=" + encodeURIComponent(appName) + "&classPath=" + encodeURIComponent(classPath) + "&recordData=" + encodeURIComponent(recordData);
            break;

        default:
            type = $("#txtAddEditRecordDataUnknownType").val();
            if ((type === null) || (type === "")) {
                showAlert("warning", "Angabe fehlt", "Bitte Name oder Nummer des Eintragstyps eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataUnknownType").trigger("focus");
                return;
            }

            var rdata = $("#txtAddEditRecordDataValue").val();
            if ((rdata === null) || (rdata === "")) {
                showAlert("warning", "Angabe fehlt", "Bitte die RDATA als Hex-Wert eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").trigger("focus");
                return;
            }

            formData += "&rdata=" + encodeURIComponent(rdata);
            break;
    }

    formData = "zone=" + encodeURIComponent(zone) + "&domain=" + encodeURIComponent(domain) + "&type=" + encodeURIComponent(type) + "&ttl=" + ttl + "&overwrite=" + overwrite + "&comments=" + encodeURIComponent(comments) + "&expiryTtl=" + expiryTtl + formData;

    btn.button("loading");

    HTTPRequest({
        url: "api/zones/records/add",
        token: sessionData.token,
        method: "POST",
        data: formData,
        processData: false,
        success: function (responseJSON) {
            $("#modalAddEditRecord").modal("hide");

            if (overwrite) {
                var currentPageNumber = Number($("#txtEditZonePageNumber").val());
                showEditZone(zone, currentPageNumber);
            }
            else {
                editZoneRecords.unshift(responseJSON.response.addedRecord);
                editZoneFilteredRecords = null;

                showEditZonePage(1);
            }

            showAlert("success", "Eintrag hinzugefügt", "Der Eintrag wurde hinzugefügt.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalAddEditRecord").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divAddEditRecordAlert
    });
}

function updateAddEditFormForwarderPlaceholder() {
    var protocol = $('input[name=rdAddEditRecordDataForwarderProtocol]:checked').val();
    switch (protocol) {
        case "Udp":
        case "Tcp":
            $("#txtAddEditRecordDataForwarder").attr("placeholder", "8.8.8.8 or [2620:fe::10]")
            break;

        case "Tls":
        case "Quic":
            $("#txtAddEditRecordDataForwarder").attr("placeholder", "dns.quad9.net (9.9.9.9:853)")
            break;

        case "Https":
            $("#txtAddEditRecordDataForwarder").attr("placeholder", "https://cloudflare-dns.com/dns-query (1.1.1.1)")
            break;
    }
}

function updateAddEditFormForwarderProxyType() {
    var proxyType = $('input[name=rdAddEditRecordDataForwarderProxyType]:checked').val();
    var disabled = (proxyType === "NoProxy") || (proxyType === "DefaultProxy");

    $("#txtAddEditRecordDataForwarderProxyAddress").prop("disabled", disabled);
    $("#txtAddEditRecordDataForwarderProxyPort").prop("disabled", disabled);
    $("#txtAddEditRecordDataForwarderProxyUsername").prop("disabled", disabled);
    $("#txtAddEditRecordDataForwarderProxyPassword").prop("disabled", disabled);
}

function updateAddEditFormForwarderThisServer() {
    var useThisServer = $("#chkAddEditRecordDataForwarderThisServer").prop('checked');

    if (useThisServer) {
        $("input[name=rdAddEditRecordDataForwarderProtocol]:radio").attr("disabled", true);
        $("#rdAddEditRecordDataForwarderProtocolUdp").prop("checked", true);
        $("#txtAddEditRecordDataForwarder").attr("placeholder", "8.8.8.8 or [2620:fe::10]")

        $("#txtAddEditRecordDataForwarder").prop("disabled", true);
        $("#txtAddEditRecordDataForwarder").val("this-server");

        $("#divAddEditRecordDataForwarderProxy").hide();
    }
    else {
        $("input[name=rdAddEditRecordDataForwarderProtocol]:radio").attr("disabled", false);

        $("#txtAddEditRecordDataForwarder").prop("disabled", false);
        $("#txtAddEditRecordDataForwarder").val("");

        $("#divAddEditRecordDataForwarderProxy").show();
    }
}

function addSvcbRecordParamEditRow(paramKey, paramValue) {
    var id = Math.floor(Math.random() * 10000);

    var tableHtmlRows = "<tr id=\"tableAddEditRecordDataSvcbParamsRow" + id + "\">";

    if ((paramKey != "") && isFinite(paramKey)) {
        tableHtmlRows += "<td><input type=\"text\" class=\"form-control\" placeholder=\"key number\" value=\"" + htmlEncode(paramKey) + "\"></td>";
        tableHtmlRows += "<td><input type=\"text\" data-optional=\"true\" class=\"form-control\" placeholder=\"hex string\" value=\"" + htmlEncode(paramValue) + "\"></td>";
    }
    else {
        tableHtmlRows += "<td id=\"tableAddEditRecordDataSvcbParamsRowColumn1" + id + "\">";
        tableHtmlRows += "<select class=\"form-control\" onchange=\"if (event.target.value === 'Unknown') { $('#tableAddEditRecordDataSvcbParamsRowColumn1" + id + "').html('<input type=\\\'text\\\' class=\\\'form-control\\\' placeholder=\\\'key number\\\' >'); $('#tableAddEditRecordDataSvcbParamsRowColumn2" + id + "').html('<input type=\\\'text\\\' data-optional=\\\'true\\\' class=\\\'form-control\\\' placeholder=\\\'hex string\\\' >'); }\">";
        tableHtmlRows += "<option" + (paramKey == "mandatory" ? " selected" : "") + ">mandatory</option>";
        tableHtmlRows += "<option" + (paramKey == "alpn" ? " selected" : "") + ">alpn</option>";
        tableHtmlRows += "<option" + (paramKey == "no-default-alpn" ? " selected" : "") + ">no-default-alpn</option>";
        tableHtmlRows += "<option" + (paramKey == "port" ? " selected" : "") + ">port</option>";
        tableHtmlRows += "<option" + (paramKey == "ipv4hint" ? " selected" : "") + ">ipv4hint</option>";
        tableHtmlRows += "<option" + (paramKey == "ipv6hint" ? " selected" : "") + ">ipv6hint</option>";
        tableHtmlRows += "<option" + (paramKey == "dohpath" ? " selected" : "") + ">dohpath</option>";
        tableHtmlRows += "<option>Unknown</option>";
        tableHtmlRows += "</select></td>";

        tableHtmlRows += "<td id=\"tableAddEditRecordDataSvcbParamsRowColumn2" + id + "\"><input type=\"text\" data-optional=\"true\" class=\"form-control\" value=\"" + htmlEncode(paramValue) + "\"></td>";
    }

    tableHtmlRows += "<td><button type=\"button\" class=\"btn btn-warning\" onclick=\"$('#tableAddEditRecordDataSvcbParamsRow" + id + "').remove();\">Entfernen</button></td></tr>";

    $("#tableAddEditRecordDataSvcbParams").append(tableHtmlRows);
}

function showEditRecordModal(objBtn) {
    var btn = $(objBtn);
    var id = btn.attr("data-id");
    var divData = $("#data" + id);

    var zone = $("#titleEditZone").attr("data-zone");
    var zoneType = $("#titleEditZone").attr("data-zone-type");
    var name = divData.attr("data-record-name");
    var type = divData.attr("data-record-type");
    var ttl = divData.attr("data-record-ttl");
    var comments = divData.attr("data-record-comments");
    var expiryTtl = divData.attr("data-record-expiry-ttl");

    if (name === zone)
        name = "@";
    else
        name = name.replace("." + zone, "");

    clearAddEditRecordForm();
    $("#titleAddEditRecord").text("Eintrag bearbeiten");
    $("#lblAddEditRecordZoneName").text(zone === "." ? "" : zone);
    $("#optAddEditRecordType").val(type);
    $("#divAddEditRecordOverwrite").hide();
    modifyAddRecordFormByType(false);

    $("#txtAddEditRecordName").val(name);
    $("#txtAddEditRecordTtl").val(ttl)
    $("#txtAddEditRecordComments").val(comments);
    $("#txtAddEditRecordExpiryTtl").val(expiryTtl);

    switch (type) {
        case "A":
        case "AAAA":
            $("#txtAddEditRecordDataValue").val(divData.attr("data-record-ip-address"));
            $("#chkAddEditRecordDataPtr").prop("checked", false);
            $("#chkAddEditRecordDataCreatePtrZone").prop("disabled", true);
            $("#chkAddEditRecordDataCreatePtrZone").prop("checked", false);
            $("#chkAddEditRecordDataPtrLabel").text("Reverse-Eintrag (PTR) mit aktualisieren");
            break;

        case "NS":
            $("#txtAddEditRecordDataNsNameServer").val(divData.attr("data-record-name-server"));
            $("#txtAddEditRecordDataNsGlue").val(divData.attr("data-record-glue").replace(/, /g, "\n"));
            break;

        case "CNAME":
            $("#txtAddEditRecordDataValue").val(divData.attr("data-record-cname"));
            break;

        case "PTR":
            $("#txtAddEditRecordDataValue").val(divData.attr("data-record-ptr-name"));
            break;

        case "MX":
            $("#txtAddEditRecordDataMxPreference").val(divData.attr("data-record-preference"));
            $("#txtAddEditRecordDataMxExchange").val(divData.attr("data-record-exchange"));
            break;

        case "TXT":
            $("#txtAddEditRecordDataTxt").val(divData.attr("data-record-text"));
            $("#chkAddEditRecordDataTxtSplitText").prop("checked", divData.attr("data-record-split-text") === "true");
            break;

        case "RP":
            $("#txtAddEditRecordDataRpMailbox").val(divData.attr("data-record-mailbox"));
            $("#txtAddEditRecordDataRpTxtDomain").val(divData.attr("data-record-txt-domain"));
            break;

        case "SRV":
            $("#txtAddEditRecordDataSrvPriority").val(divData.attr("data-record-priority"));
            $("#txtAddEditRecordDataSrvWeight").val(divData.attr("data-record-weight"));
            $("#txtAddEditRecordDataSrvPort").val(divData.attr("data-record-port"));
            $("#txtAddEditRecordDataSrvTarget").val(divData.attr("data-record-target"));
            break;

        case "NAPTR":
            $("#txtAddEditRecordDataNaptrOrder").val(divData.attr("data-record-order"));
            $("#txtAddEditRecordDataNaptrPreference").val(divData.attr("data-record-preference"));
            $("#txtAddEditRecordDataNaptrFlags").val(divData.attr("data-record-flags"));
            $("#txtAddEditRecordDataNaptrServices").val(divData.attr("data-record-services"));
            $("#txtAddEditRecordDataNaptrRegExp").val(divData.attr("data-record-regexp"));
            $("#txtAddEditRecordDataNaptrReplacement").val(divData.attr("data-record-replacement"));
            break;

        case "DNAME":
            $("#txtAddEditRecordDataValue").val(divData.attr("data-record-dname"));
            break;

        case "SVCB":
        case "HTTPS":
            $("#txtAddEditRecordDataSvcbPriority").val(divData.attr("data-record-svc-priority"));
            $("#txtAddEditRecordDataSvcbTargetName").val(divData.attr("data-record-svc-target-name"));

            var svcParams = JSON.parse(divData.attr("data-record-svc-params"));
            var autoIpv4Hint = divData.attr("data-record-auto-ipv4hint") === "true";
            var autoIpv6Hint = divData.attr("data-record-auto-ipv6hint") === "true";

            for (var paramKey in svcParams) {
                switch (paramKey) {
                    case "ipv4hint":
                        if (autoIpv4Hint)
                            continue;

                        break;

                    case "ipv6hint":
                        if (autoIpv6Hint)
                            continue;

                        break;
                }

                addSvcbRecordParamEditRow(paramKey, svcParams[paramKey]);
            }

            $("#chkAddEditRecordDataSvcbAutoIpv4Hint").prop("checked", autoIpv4Hint);
            $("#chkAddEditRecordDataSvcbAutoIpv6Hint").prop("checked", autoIpv6Hint);
            break;

        case "URI":
            $("#txtAddEditRecordDataUriPriority").val(divData.attr("data-record-priority"));
            $("#txtAddEditRecordDataUriWeight").val(divData.attr("data-record-weight"));
            $("#txtAddEditRecordDataUri").val(divData.attr("data-record-uri"));
            break;

        case "CAA":
            $("#txtAddEditRecordDataCaaFlags").val(divData.attr("data-record-flags"));
            $("#txtAddEditRecordDataCaaTag").val(divData.attr("data-record-tag"));
            $("#txtAddEditRecordDataCaaValue").val(divData.attr("data-record-value"));
            break;

        case "ANAME":
            $("#txtAddEditRecordDataValue").val(divData.attr("data-record-aname"));
            break;

        case "FWD":
            $("#txtAddEditRecordTtl").prop("disabled", true);
            $("#rdAddEditRecordDataForwarderProtocol" + divData.attr("data-record-protocol")).prop("checked", true);

            var forwarder = divData.attr("data-record-forwarder");

            $("#chkAddEditRecordDataForwarderThisServer").prop("checked", (forwarder == "this-server"));
            $("#txtAddEditRecordDataForwarder").prop("disabled", (forwarder == "this-server"));
            $("#txtAddEditRecordDataForwarder").val(forwarder);

            if (forwarder === "this-server") {
                $("input[name=rdAddEditRecordDataForwarderProtocol]:radio").attr("disabled", true);
                $("#divAddEditRecordDataForwarderProxy").hide();
            }
            else {
                $("input[name=rdAddEditRecordDataForwarderProtocol]:radio").attr("disabled", false);
                $("#divAddEditRecordDataForwarderProxy").show();
            }

            $("#txtAddEditRecordDataForwarderPriority").val(divData.attr("data-record-priority"));
            $("#chkAddEditRecordDataForwarderDnssecValidation").prop("checked", divData.attr("data-record-dnssec-validation") === "true");

            var proxyType = divData.attr("data-record-proxy-type");
            $("#rdAddEditRecordDataForwarderProxyType" + proxyType).prop("checked", true);

            switch (proxyType) {
                case "Http":
                case "Socks5":
                    $("#txtAddEditRecordDataForwarderProxyAddress").val(divData.attr("data-record-proxy-address"));
                    $("#txtAddEditRecordDataForwarderProxyPort").val(divData.attr("data-record-proxy-port"));
                    $("#txtAddEditRecordDataForwarderProxyUsername").val(divData.attr("data-record-proxy-username"));
                    $("#txtAddEditRecordDataForwarderProxyPassword").val(divData.attr("data-record-proxy-password"));
                    break;
            }

            updateAddEditFormForwarderPlaceholder();
            updateAddEditFormForwarderProxyType();
            break;

        case "APP":
            $("#optAddEditRecordDataAppName").prop("disabled", true);
            $("#optAddEditRecordDataClassPath").prop("disabled", true);

            $("#optAddEditRecordDataAppName").html("<option>" + htmlEncode( divData.attr("data-record-app-name")) + "</option>")
            $("#optAddEditRecordDataAppName").val(divData.attr("data-record-app-name"))

            $("#optAddEditRecordDataClassPath").html("<option>" + htmlEncode(divData.attr("data-record-classpath")) + "</option>")
            $("#optAddEditRecordDataClassPath").val(divData.attr("data-record-classpath"))

            $("#txtAddEditRecordDataData").val(divData.attr("data-record-data"))
            break;

        default:
            var rdata = divData.attr("data-record-rdata");

            if (rdata == null) {
                showAlert("danger", "Nicht unterstützt", "Dieser Eintragstyp kann nicht bearbeitet werden.");
                return;
            }

            $("#optAddEditRecordType").val("Unknown");
            $("#txtAddEditRecordDataUnknownType").val(type);
            $("#txtAddEditRecordDataUnknownType").prop("disabled", true);

            $("#txtAddEditRecordDataValue").val(rdata);
            break;
    }

    $("#optAddEditRecordType").prop("disabled", true);

    $("#btnAddEditRecord").attr("data-id", id);
    $("#btnAddEditRecord").attr("onclick", "updateRecord(); return false;");

    $("#modalAddEditRecord").modal("show");

    setTimeout(function () {
        $("#txtAddEditRecordName").trigger("focus");
    }, 1000);
}

function updateRecord() {
    var btn = $("#btnAddEditRecord");
    var divAddEditRecordAlert = $("#divAddEditRecordAlert");

    var index = Number(btn.attr("data-id"));
    var divData = $("#data" + index);

    var zone = $("#titleEditZone").attr("data-zone");
    var recordIndex = Number(divData.attr("data-record-index"));
    var type = divData.attr("data-record-type");
    var domain = divData.attr("data-record-name");

    if (domain === "")
        domain = ".";

    var newDomain;
    {
        var newSubDomain = $("#txtAddEditRecordName").val();
        if (newSubDomain === "")
            newSubDomain = "@";

        if (newSubDomain === "@")
            newDomain = zone;
        else if (zone === ".")
            newDomain = newSubDomain + ".";
        else
            newDomain = newSubDomain + "." + zone;
    }

    var ttl = $("#txtAddEditRecordTtl").val();
    var disable = (divData.attr("data-record-disabled") === "true");
    var comments = $("#txtAddEditRecordComments").val();
    var expiryTtl = $("#txtAddEditRecordExpiryTtl").val();

    var formData = "";

    switch (type) {
        case "A":
        case "AAAA":
            var ipAddress = divData.attr("data-record-ip-address");

            var newIpAddress = $("#txtAddEditRecordDataValue").val();
            if (newIpAddress === "") {
                showAlert("warning", "Angabe fehlt", "Bitte eine IP-Adresse eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").trigger("focus");
                return;
            }

            var updateSvcbHints = zoneHasSvcbAutoHint(type == "A", type == "AAAA");

            formData += "&ipAddress=" + encodeURIComponent(ipAddress) + "&newIpAddress=" + encodeURIComponent(newIpAddress) + "&ptr=" + $("#chkAddEditRecordDataPtr").prop('checked') + "&createPtrZone=" + $("#chkAddEditRecordDataCreatePtrZone").prop('checked') + "&updateSvcbHints=" + updateSvcbHints;
            break;

        case "NS":
            var nameServer = divData.attr("data-record-name-server");

            var newNameServer = $("#txtAddEditRecordDataNsNameServer").val();
            if (newNameServer === "") {
                showAlert("warning", "Angabe fehlt", "Bitte einen Nameserver eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataNsNameServer").trigger("focus");
                return;
            }

            var glue = cleanTextList($("#txtAddEditRecordDataNsGlue").val());

            formData += "&nameServer=" + encodeURIComponent(nameServer) + "&newNameServer=" + encodeURIComponent(newNameServer) + "&glue=" + encodeURIComponent(glue);
            break;

        case "CNAME":
            var subDomainName = $("#txtAddEditRecordName").val();
            if ((subDomainName === "") || (subDomainName === "@")) {
                showAlert("warning", "Angabe fehlt", "Bitte einen Namen für den CNAME-Eintrag eingeben. Am Zonenursprung ist CNAME nicht erlaubt; dafür ANAME verwenden.", divAddEditRecordAlert);
                $("#txtAddEditRecordName").trigger("focus");
                return;
            }

            var cname = $("#txtAddEditRecordDataValue").val();
            if (cname === "") {
                showAlert("warning", "Angabe fehlt", "Bitte einen Domainnamen eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").trigger("focus");
                return;
            }

            formData += "&cname=" + encodeURIComponent(cname);
            break;

        case "PTR":
            var ptrName = divData.attr("data-record-ptr-name");

            var newPtrName = $("#txtAddEditRecordDataValue").val();
            if (newPtrName === "") {
                showAlert("warning", "Angabe fehlt", "Bitte einen gültigen Wert eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").trigger("focus");
                return;
            }

            formData += "&ptrName=" + encodeURIComponent(ptrName) + "&newPtrName=" + encodeURIComponent(newPtrName);
            break;

        case "MX":
            var preference = divData.attr("data-record-preference");

            var newPreference = $("#txtAddEditRecordDataMxPreference").val();
            if (newPreference === "")
                newPreference = 1;

            var exchange = divData.attr("data-record-exchange");

            var newExchange = $("#txtAddEditRecordDataMxExchange").val();
            if (newExchange === "") {
                showAlert("warning", "Angabe fehlt", "Bitte den Mailserver eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataMxExchange").trigger("focus");
                return;
            }

            formData += "&preference=" + preference + "&newPreference=" + newPreference + "&exchange=" + encodeURIComponent(exchange) + "&newExchange=" + encodeURIComponent(newExchange);
            break;

        case "TXT":
            var newText = $("#txtAddEditRecordDataTxt").val();
            if (newText === "") {
                showAlert("warning", "Angabe fehlt", "Bitte einen gültigen Wert eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataTxt").trigger("focus");
                return;
            }

            var newSplitText = $("#chkAddEditRecordDataTxtSplitText").prop("checked");

            formData += "&characterStringsBase64=" + encodeURIComponent(divData.attr("data-record-character-strings-base64")) + "&newText=" + encodeURIComponent(newText) + "&newSplitText=" + newSplitText;
            break;

        case "RP":
            var mailbox = divData.attr("data-record-mailbox");

            var newMailbox = $("#txtAddEditRecordDataRpMailbox").val();
            if (newMailbox === "")
                newMailbox = ".";

            var txtDomain = divData.attr("data-record-txt-domain");

            var newTxtDomain = $("#txtAddEditRecordDataRpTxtDomain").val();
            if (newTxtDomain === "")
                newTxtDomain = ".";

            formData += "&mailbox=" + encodeURIComponent(mailbox) + "&newMailbox=" + encodeURIComponent(newMailbox) + "&txtDomain=" + encodeURIComponent(txtDomain) + "&newTxtDomain=" + encodeURIComponent(newTxtDomain);
            break;

        case "SRV":
            if ($("#txtAddEditRecordName").val() === "") {
                showAlert("warning", "Angabe fehlt", "Bitte einen Namen mit Dienst- und Protokoll-Label eingeben (z. B. _sip._tcp).", divAddEditRecordAlert);
                $("#txtAddEditRecordName").trigger("focus");
                return;
            }

            var priority = divData.attr("data-record-priority");

            var newPriority = $("#txtAddEditRecordDataSrvPriority").val();
            if (newPriority === "") {
                showAlert("warning", "Angabe fehlt", "Bitte eine gültige Priorität eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSrvPriority").trigger("focus");
                return;
            }

            var weight = divData.attr("data-record-weight");

            var newWeight = $("#txtAddEditRecordDataSrvWeight").val();
            if (newWeight === "") {
                showAlert("warning", "Angabe fehlt", "Bitte eine gültige Gewichtung eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSrvWeight").trigger("focus");
                return;
            }

            var port = divData.attr("data-record-port");

            var newPort = $("#txtAddEditRecordDataSrvPort").val();
            if (newPort === "") {
                showAlert("warning", "Angabe fehlt", "Bitte einen gültigen Port eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSrvPort").trigger("focus");
                return;
            }

            var target = divData.attr("data-record-target");

            var newTarget = $("#txtAddEditRecordDataSrvTarget").val();
            if (newTarget === "") {
                showAlert("warning", "Angabe fehlt", "Bitte ein gültiges Ziel eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSrvTarget").trigger("focus");
                return;
            }

            formData += "&priority=" + priority + "&newPriority=" + newPriority + "&weight=" + weight + "&newWeight=" + newWeight + "&port=" + port + "&newPort=" + newPort + "&target=" + encodeURIComponent(target) + "&newTarget=" + encodeURIComponent(newTarget);
            break;

        case "NAPTR":
            var order = divData.attr("data-record-order");
            var preference = divData.attr("data-record-preference");
            var flags = divData.attr("data-record-flags");
            var services = divData.attr("data-record-services");
            var regexp = divData.attr("data-record-regexp");
            var replacement = divData.attr("data-record-replacement");

            var newOrder = $("#txtAddEditRecordDataNaptrOrder").val();
            if (newOrder === "") {
                showAlert("warning", "Angabe fehlt", "Bitte eine gültige Reihenfolge eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataNaptrOrder").trigger("focus");
                return;
            }

            var newPreference = $("#txtAddEditRecordDataNaptrPreference").val();
            if (newPreference === "") {
                showAlert("warning", "Angabe fehlt", "Bitte eine gültige Priorität eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataNaptrPreference").trigger("focus");
                return;
            }

            var newFlags = $("#txtAddEditRecordDataNaptrFlags").val();
            var newServices = $("#txtAddEditRecordDataNaptrServices").val();
            var newRegexp = $("#txtAddEditRecordDataNaptrRegExp").val();
            var newReplacement = $("#txtAddEditRecordDataNaptrReplacement").val();

            if (newReplacement === "")
                newReplacement = ".";

            formData += "&naptrOrder=" + order + "&naptrNewOrder=" + newOrder + "&naptrPreference=" + preference + "&naptrNewPreference=" + newPreference + "&naptrFlags=" + encodeURIComponent(flags) + "&naptrNewFlags=" + encodeURIComponent(newFlags) + "&naptrServices=" + encodeURIComponent(services) + "&naptrNewServices=" + encodeURIComponent(newServices) + "&naptrRegexp=" + encodeURIComponent(regexp) + "&naptrNewRegexp=" + encodeURIComponent(newRegexp) + "&naptrReplacement=" + encodeURIComponent(replacement) + "&naptrNewReplacement=" + encodeURIComponent(newReplacement);
            break;

        case "DNAME":
            var dname = $("#txtAddEditRecordDataValue").val();
            if (dname === "") {
                showAlert("warning", "Angabe fehlt", "Bitte einen Domainnamen eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").trigger("focus");
                return;
            }

            formData += "&dname=" + encodeURIComponent(dname);
            break;

        case "SVCB":
        case "HTTPS":
            var svcPriority = divData.attr("data-record-svc-priority");
            var svcTargetName = divData.attr("data-record-svc-target-name");
            var svcParams = "";
            {
                var jsonSvcParams = JSON.parse(divData.attr("data-record-svc-params"));

                for (var paramKey in jsonSvcParams) {
                    if (svcParams.length === 0)
                        svcParams = paramKey + "|" + jsonSvcParams[paramKey];
                    else
                        svcParams += "|" + paramKey + "|" + jsonSvcParams[paramKey];
                }

                if (svcParams.length === 0)
                    svcParams = false;
            }

            var newSvcPriority = $("#txtAddEditRecordDataSvcbPriority").val();
            if ((newSvcPriority === null) || (newSvcPriority === "")) {
                showAlert("warning", "Angabe fehlt", "Bitte eine Priorität eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSvcbPriority").trigger("focus");
                return;
            }

            var newSvcTargetName = $("#txtAddEditRecordDataSvcbTargetName").val();
            if ((newSvcTargetName === null) || (newSvcTargetName === "")) {
                showAlert("warning", "Angabe fehlt", "Bitte einen Zielnamen eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSvcbTargetName").trigger("focus");
                return;
            }

            var newSvcParams = serializeTableData($("#tableAddEditRecordDataSvcbParams"), 2, divAddEditRecordAlert);
            if (newSvcParams === false)
                return;

            if (newSvcParams.length === 0)
                newSvcParams = false;

            var autoIpv4Hint = $("#chkAddEditRecordDataSvcbAutoIpv4Hint").prop("checked");
            var autoIpv6Hint = $("#chkAddEditRecordDataSvcbAutoIpv6Hint").prop("checked");

            formData += "&svcPriority=" + svcPriority + "&newSvcPriority=" + newSvcPriority + "&svcTargetName=" + encodeURIComponent(svcTargetName) + "&newSvcTargetName=" + encodeURIComponent(newSvcTargetName) + "&svcParams=" + encodeURIComponent(svcParams) + "&newSvcParams=" + encodeURIComponent(newSvcParams) + "&autoIpv4Hint=" + autoIpv4Hint + "&autoIpv6Hint=" + autoIpv6Hint;
            break;

        case "URI":
            var uriPriority = divData.attr("data-record-priority");

            var newUriPriority = $("#txtAddEditRecordDataUriPriority").val();
            if (newUriPriority === "") {
                showAlert("warning", "Angabe fehlt", "Bitte eine gültige Priorität eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataUriPriority").trigger("focus");
                return;
            }

            var uriWeight = divData.attr("data-record-weight");

            var newUriWeight = $("#txtAddEditRecordDataUriWeight").val();
            if (newUriWeight === "") {
                showAlert("warning", "Angabe fehlt", "Bitte eine gültige Gewichtung eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataUriWeight").trigger("focus");
                return;
            }

            var uri = divData.attr("data-record-uri");

            var newUri = $("#txtAddEditRecordDataUri").val();
            if (newUri === "") {
                showAlert("warning", "Angabe fehlt", "Bitte eine gültige URI eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataUri").trigger("focus");
                return;
            }

            formData += "&uriPriority=" + uriPriority + "&newUriPriority=" + newUriPriority + "&uriWeight=" + uriWeight + "&newUriWeight=" + newUriWeight + "&uri=" + encodeURIComponent(uri) + "&newUri=" + encodeURIComponent(newUri);
            break;

        case "CAA":
            var flags = divData.attr("data-record-flags");
            var tag = divData.attr("data-record-tag");

            var newFlags = $("#txtAddEditRecordDataCaaFlags").val();
            if (newFlags === "")
                newFlags = 0;

            var newTag = $("#txtAddEditRecordDataCaaTag").val();
            if (newTag === "")
                newTag = "issue";

            var value = divData.attr("data-record-value");

            var newValue = $("#txtAddEditRecordDataCaaValue").val();
            if (newValue === "") {
                showAlert("warning", "Angabe fehlt", "Bitte eine gültige Authority eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataCaaValue").trigger("focus");
                return;
            }

            formData += "&flags=" + flags + "&tag=" + encodeURIComponent(tag) + "&newFlags=" + newFlags + "&newTag=" + encodeURIComponent(newTag) + "&value=" + encodeURIComponent(value) + "&newValue=" + encodeURIComponent(newValue);
            break;

        case "ANAME":
            var aname = divData.attr("data-record-aname");

            var newAName = $("#txtAddEditRecordDataValue").val();
            if (newAName === "") {
                showAlert("warning", "Angabe fehlt", "Bitte einen gültigen Wert eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").trigger("focus");
                return;
            }

            formData += "&aname=" + encodeURIComponent(aname) + "&newAName=" + encodeURIComponent(newAName);
            break;

        case "FWD":
            var protocol = divData.attr("data-record-protocol");
            var newProtocol = $("input[name=rdAddEditRecordDataForwarderProtocol]:checked").val();

            var forwarder = divData.attr("data-record-forwarder");

            var newForwarder = $("#txtAddEditRecordDataForwarder").val();
            if (newForwarder === "") {
                showAlert("warning", "Angabe fehlt", "Bitte Domainname, IP-Adresse oder URL des Forwarders eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataForwarder").trigger("focus");
                return;
            }

            var forwarderPriority = $("#txtAddEditRecordDataForwarderPriority").val();
            var dnssecValidation = $("#chkAddEditRecordDataForwarderDnssecValidation").prop("checked");

            formData += "&protocol=" + protocol + "&newProtocol=" + newProtocol + "&forwarder=" + encodeURIComponent(forwarder) + "&newForwarder=" + encodeURIComponent(newForwarder) + "&forwarderPriority=" + forwarderPriority + "&dnssecValidation=" + dnssecValidation;

            if (newForwarder !== "this-server") {
                var proxyType = $("input[name=rdAddEditRecordDataForwarderProxyType]:checked").val();

                formData += "&proxyType=" + proxyType;

                switch (proxyType) {
                    case "Http":
                    case "Socks5":
                        var proxyAddress = $("#txtAddEditRecordDataForwarderProxyAddress").val();
                        var proxyPort = $("#txtAddEditRecordDataForwarderProxyPort").val();
                        var proxyUsername = $("#txtAddEditRecordDataForwarderProxyUsername").val();
                        var proxyPassword = $("#txtAddEditRecordDataForwarderProxyPassword").val();

                        if ((proxyAddress == null) || (proxyAddress === "")) {
                            showAlert("warning", "Angabe fehlt", "Bitte die Proxy-Adresse eingeben.", divAddEditRecordAlert);
                            $("#txtAddEditRecordDataForwarderProxyAddress").trigger("focus");
                            return;
                        }

                        if ((proxyPort == null) || (proxyPort === "")) {
                            showAlert("warning", "Angabe fehlt", "Bitte den Proxy-Port eingeben.", divAddEditRecordAlert);
                            $("#txtAddEditRecordDataForwarderProxyPort").trigger("focus");
                            return;
                        }

                        formData += "&proxyAddress=" + encodeURIComponent(proxyAddress) + "&proxyPort=" + proxyPort + "&proxyUsername=" + encodeURIComponent(proxyUsername) + "&proxyPassword=" + encodeURIComponent(proxyPassword);
                        break;
                }
            }
            break;

        case "APP":
            formData += "&appName=" + encodeURIComponent(divData.attr("data-record-app-name")) + "&classPath=" + encodeURIComponent(divData.attr("data-record-classpath")) + "&recordData=" + encodeURIComponent($("#txtAddEditRecordDataData").val());
            break;

        default:
            type = $("#txtAddEditRecordDataUnknownType").val();
            var rdata = divData.attr("data-record-rdata");

            var newRData = $("#txtAddEditRecordDataValue").val();
            if ((newRData === null) || (newRData === "")) {
                showAlert("warning", "Angabe fehlt", "Bitte die RDATA als Hex-Wert eingeben.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").trigger("focus");
                return;
            }

            formData += "&rdata=" + encodeURIComponent(rdata) + "&newRData=" + encodeURIComponent(newRData);
            break;
    }

    formData = "zone=" + encodeURIComponent(zone) + "&type=" + encodeURIComponent(type) + "&domain=" + encodeURIComponent(domain) + "&newDomain=" + encodeURIComponent(newDomain) + "&ttl=" + ttl + "&disable=" + disable + "&comments=" + encodeURIComponent(comments) + "&expiryTtl=" + expiryTtl + formData;

    btn.button("loading");

    HTTPRequest({
        url: "api/zones/records/update",
        token: sessionData.token,
        method: "POST",
        data: formData,
        processData: false,
        success: function (responseJSON) {
            $("#modalAddEditRecord").modal("hide");

            editZoneInfo = responseJSON.response.zone;
            responseJSON.response.updatedRecord.index = recordIndex;
            editZoneRecords[recordIndex] = responseJSON.response.updatedRecord;

            if ((domain.toLowerCase() !== newDomain.toLowerCase()) && ($("#txtEditZoneFilterName").val() != "")) {
                editZoneFilteredRecords = null;

                showEditZonePage();
            }
            else {
                editZoneFilteredRecords[index] = responseJSON.response.updatedRecord;

                var tableHtmlRow = getZoneRecordRowHtml(index, zone, responseJSON.response.zone.type, responseJSON.response.updatedRecord);
                $("#trZoneRecord" + index).replaceWith(tableHtmlRow);
            }

            showAlert("success", "Eintrag gespeichert", "Der Eintrag wurde geändert.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalAddEditRecord").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divAddEditRecordAlert
    });
}

function updateRecordState(objBtn, disable) {
    var btn = $(objBtn);
    var index = Number(btn.attr("data-id"));
    var divData = $("#data" + index);

    var zone = $("#titleEditZone").attr("data-zone");
    var recordIndex = Number(divData.attr("data-record-index"));
    var type = divData.attr("data-record-type");
    var domain = divData.attr("data-record-name");
    var ttl = divData.attr("data-record-ttl");
    var comments = divData.attr("data-record-comments");
    var expiryTtl = $("#txtAddEditRecordExpiryTtl").val();

    if (domain === "")
        domain = ".";

    if (disable && !confirm(type + "-Eintrag '" + domain + "' deaktivieren?"))
        return;

    var formData = "zone=" + encodeURIComponent(zone) + "&type=" + encodeURIComponent(type) + "&domain=" + encodeURIComponent(domain) + "&ttl=" + ttl + "&disable=" + disable + "&comments=" + encodeURIComponent(comments) + "&expiryTtl=" + expiryTtl;

    switch (type) {
        case "A":
        case "AAAA":
            var updateSvcbHints = zoneHasSvcbAutoHint(type == "A", type == "AAAA");

            formData += "&ipAddress=" + encodeURIComponent(divData.attr("data-record-ip-address")) + "&updateSvcbHints=" + updateSvcbHints;
            break;

        case "NS":
            formData += "&nameServer=" + encodeURIComponent(divData.attr("data-record-name-server")) + "&glue=" + encodeURIComponent(divData.attr("data-record-glue"));
            break;

        case "CNAME":
            formData += "&cname=" + encodeURIComponent(divData.attr("data-record-cname"));
            break;

        case "PTR":
            formData += "&ptrName=" + encodeURIComponent(divData.attr("data-record-ptr-name"));
            break;

        case "MX":
            formData += "&preference=" + divData.attr("data-record-preference") + "&exchange=" + encodeURIComponent(divData.attr("data-record-exchange"));
            break;

        case "TXT":
            formData += "&characterStringsBase64=" + encodeURIComponent(divData.attr("data-record-character-strings-base64"));
            break;

        case "RP":
            formData += "&mailbox=" + encodeURIComponent(divData.attr("data-record-mailbox")) + "&txtDomain=" + encodeURIComponent(divData.attr("data-record-txt-domain"));
            break;

        case "SRV":
            formData += "&priority=" + divData.attr("data-record-priority") + "&weight=" + divData.attr("data-record-weight") + "&port=" + divData.attr("data-record-port") + "&target=" + encodeURIComponent(divData.attr("data-record-target"));
            break;

        case "NAPTR":
            formData += "&naptrOrder=" + divData.attr("data-record-order") + "&naptrPreference=" + divData.attr("data-record-preference") + "&naptrFlags=" + encodeURIComponent(divData.attr("data-record-flags")) + "&naptrServices=" + encodeURIComponent(divData.attr("data-record-services")) + "&naptrRegexp=" + encodeURIComponent(divData.attr("data-record-regexp")) + "&naptrReplacement=" + encodeURIComponent(divData.attr("data-record-replacement"));
            break;

        case "DNAME":
            formData += "&dname=" + encodeURIComponent(divData.attr("data-record-dname"));
            break;

        case "SVCB":
        case "HTTPS":
            var svcPriority = divData.attr("data-record-svc-priority");
            var svcTargetName = divData.attr("data-record-svc-target-name");
            var svcParams = "";
            {
                var jsonSvcParams = JSON.parse(divData.attr("data-record-svc-params"));

                for (var paramKey in jsonSvcParams) {
                    if (svcParams.length == 0)
                        svcParams = paramKey + "|" + jsonSvcParams[paramKey];
                    else
                        svcParams += "|" + paramKey + "|" + jsonSvcParams[paramKey];
                }

                if (svcParams.length === 0)
                    svcParams = false;
            }

            var autoIpv4Hint = divData.attr("data-record-auto-ipv4hint");
            var autoIpv6Hint = divData.attr("data-record-auto-ipv6hint");

            formData += "&svcPriority=" + svcPriority + "&svcTargetName=" + encodeURIComponent(svcTargetName) + "&svcParams=" + encodeURIComponent(svcParams) + "&autoIpv4Hint=" + autoIpv4Hint + "&autoIpv6Hint=" + autoIpv6Hint;
            break;

        case "URI":
            formData += "&uriPriority=" + divData.attr("data-record-priority") + "&uriWeight=" + encodeURIComponent(divData.attr("data-record-weight")) + "&uri=" + encodeURIComponent(divData.attr("data-record-uri"));
            break;

        case "CAA":
            formData += "&flags=" + divData.attr("data-record-flags") + "&tag=" + encodeURIComponent(divData.attr("data-record-tag")) + "&value=" + encodeURIComponent(divData.attr("data-record-value"));
            break;

        case "ANAME":
            formData += "&aname=" + encodeURIComponent(divData.attr("data-record-aname"));
            break;

        case "FWD":
            formData += "&protocol=" + divData.attr("data-record-protocol") + "&forwarder=" + encodeURIComponent(divData.attr("data-record-forwarder"));

            var proxyType = divData.attr("data-record-proxy-type");

            formData += "&forwarderPriority=" + divData.attr("data-record-priority") + "&dnssecValidation=" + divData.attr("data-record-dnssec-validation") + "&proxyType=" + proxyType;

            switch (proxyType) {
                case "Http":
                case "Socks5":
                    formData += "&proxyAddress=" + encodeURIComponent(divData.attr("data-record-proxy-address")) + "&proxyPort=" + divData.attr("data-record-proxy-port") + "&proxyUsername=" + encodeURIComponent(divData.attr("data-record-proxy-username")) + "&proxyPassword=" + encodeURIComponent(divData.attr("data-record-proxy-password"));
                    break;
            }
            break;

        case "APP":
            formData += "&appName=" + encodeURIComponent(divData.attr("data-record-app-name")) + "&classPath=" + encodeURIComponent(divData.attr("data-record-classpath")) + "&recordData=" + encodeURIComponent(divData.attr("data-record-data"));
            break;

        default:
            formData += "&rdata=" + encodeURIComponent(divData.attr("data-record-rdata"));
            break;
    }

    btn.button("loading");

    HTTPRequest({
        url: "api/zones/records/update",
        token: sessionData.token,
        method: "POST",
        data: formData,
        processData: false,
        success: function (responseJSON) {
            btn.button("reset");

            editZoneInfo = responseJSON.response.zone;
            responseJSON.response.updatedRecord.index = recordIndex;
            editZoneRecords[recordIndex] = responseJSON.response.updatedRecord;
            editZoneFilteredRecords[index] = responseJSON.response.updatedRecord;

            var tableHtmlRow = getZoneRecordRowHtml(index, zone, responseJSON.response.zone.type, responseJSON.response.updatedRecord);
            $("#trZoneRecord" + index).replaceWith(tableHtmlRow);

            if (disable)
                showAlert("success", "Eintrag deaktiviert", "Der Eintrag ist deaktiviert.");
            else
                showAlert("success", "Eintrag aktiviert", "Der Eintrag ist aktiv.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function deleteRecord(objBtn) {
    var btn = $(objBtn);
    var index = btn.attr("data-id");
    var divData = $("#data" + index);

    var zone = $("#titleEditZone").attr("data-zone");
    var recordIndex = Number(divData.attr("data-record-index"));
    var domain = divData.attr("data-record-name");
    var type = divData.attr("data-record-type");

    if (domain === "")
        domain = ".";

    if (!confirm(type + "-Eintrag '" + domain + "' endgültig löschen?"))
        return;

    var formData = "zone=" + encodeURIComponent(zone) + "&domain=" + encodeURIComponent(domain) + "&type=" + encodeURIComponent(type);

    switch (type) {
        case "A":
        case "AAAA":
            var updateSvcbHints = zoneHasSvcbAutoHint(type == "A", type == "AAAA");

            formData += "&ipAddress=" + encodeURIComponent(divData.attr("data-record-ip-address")) + "&updateSvcbHints=" + updateSvcbHints;
            break;

        case "NS":
            formData += "&nameServer=" + encodeURIComponent(divData.attr("data-record-name-server"));
            break;

        case "PTR":
            formData += "&ptrName=" + encodeURIComponent(divData.attr("data-record-ptr-name"));
            break;

        case "MX":
            formData += "&preference=" + divData.attr("data-record-preference") + "&exchange=" + encodeURIComponent(divData.attr("data-record-exchange"));
            break;

        case "TXT":
            formData += "&characterStringsBase64=" + encodeURIComponent(divData.attr("data-record-character-strings-base64"));
            break;

        case "RP":
            formData += "&mailbox=" + encodeURIComponent(divData.attr("data-record-mailbox")) + "&txtDomain=" + encodeURIComponent(divData.attr("data-record-txt-domain"));
            break;

        case "SRV":
            formData += "&priority=" + divData.attr("data-record-priority") + "&weight=" + divData.attr("data-record-weight") + "&port=" + divData.attr("data-record-port") + "&target=" + encodeURIComponent(divData.attr("data-record-target"));
            break;

        case "NAPTR":
            formData += "&naptrOrder=" + divData.attr("data-record-order") + "&naptrPreference=" + divData.attr("data-record-preference") + "&naptrFlags=" + encodeURIComponent(divData.attr("data-record-flags")) + "&naptrServices=" + encodeURIComponent(divData.attr("data-record-services")) + "&naptrRegexp=" + encodeURIComponent(divData.attr("data-record-regexp")) + "&naptrReplacement=" + encodeURIComponent(divData.attr("data-record-replacement"));
            break;

        case "SVCB":
        case "HTTPS":
            var svcPriority = divData.attr("data-record-svc-priority");
            var svcTargetName = divData.attr("data-record-svc-target-name");
            var svcParams = "";
            {
                var jsonSvcParams = JSON.parse(divData.attr("data-record-svc-params"));

                for (var paramKey in jsonSvcParams) {
                    if (svcParams.length == 0)
                        svcParams = paramKey + "|" + jsonSvcParams[paramKey];
                    else
                        svcParams += "|" + paramKey + "|" + jsonSvcParams[paramKey];
                }

                if (svcParams.length === 0)
                    svcParams = false;
            }

            formData += "&svcPriority=" + svcPriority + "&svcTargetName=" + encodeURIComponent(svcTargetName) + "&svcParams=" + encodeURIComponent(svcParams);
            break;

        case "URI":
            formData += "&uriPriority=" + divData.attr("data-record-priority") + "&uriWeight=" + encodeURIComponent(divData.attr("data-record-weight")) + "&uri=" + encodeURIComponent(divData.attr("data-record-uri"));
            break;

        case "CAA":
            formData += "&flags=" + divData.attr("data-record-flags") + "&tag=" + encodeURIComponent(divData.attr("data-record-tag")) + "&value=" + encodeURIComponent(divData.attr("data-record-value"));
            break;

        case "ANAME":
            formData += "&aname=" + encodeURIComponent(divData.attr("data-record-aname"));
            break;

        case "FWD":
            formData += "&protocol=" + divData.attr("data-record-protocol") + "&forwarder=" + encodeURIComponent(divData.attr("data-record-forwarder"));
            break;

        default:
            var rdata = divData.attr("data-record-rdata");
            if (rdata != null)
                formData += "&rdata=" + encodeURIComponent(rdata);
    }

    btn.button("loading");

    HTTPRequest({
        url: "api/zones/records/delete",
        token: sessionData.token,
        method: "POST",
        data: formData,
        processData: false,
        success: function (responseJSON) {
            editZoneRecords.splice(recordIndex, 1);
            editZoneFilteredRecords = null;

            showEditZonePage();

            showAlert("success", "Eintrag gelöscht", "Der Eintrag wurde gelöscht.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

