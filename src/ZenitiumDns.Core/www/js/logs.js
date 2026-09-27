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

$(function () {
    $("#optQueryLogsAppName").on("change", reloadClassPath);

    $("#optQueryLogsEntriesPerPage").on("change", function () {
        localStorage.setItem("optQueryLogsEntriesPerPage", $("#optQueryLogsEntriesPerPage").val());
    });

    resetQueryLogsForm();

    $("#chkQueryLogsLiveUpdate").on("click", function () {
        if ($(this).prop("checked")) {
            $("#txtQueryLogPageNumber").prop("disabled", true);
            $("#optQueryLogsDescendingOrder").prop("disabled", true);
            $("#txtQueryLogStart").prop("disabled", true);
            $("#txtQueryLogEnd").prop("disabled", true);
            $("#btnQueryLogs").prop("disabled", true);

            $("#txtQueryLogPageNumber").val("1");
            $("#optQueryLogsDescendingOrder").val("true");
            $("#txtQueryLogStart").val("");
            $("#txtQueryLogEnd").val("");

            queryLogs(1, true);
        }
        else {
            resetQueryLogsForm();
        }
    });

    $("#chkQueryLogsLiveUpdate").prop("checked", false);
});

function resetQueryLogsForm() {
    $("#frmQueryLogs").trigger("reset");

    reloadClassPath();

    $("#txtQueryLogPageNumber").prop("disabled", false);
    $("#optQueryLogsDescendingOrder").prop("disabled", false);
    $("#txtQueryLogStart").prop("disabled", false);
    $("#txtQueryLogEnd").prop("disabled", false);
    $("#btnQueryLogs").prop("disabled", false);

    var optQueryLogsEntriesPerPage = localStorage.getItem("optQueryLogsEntriesPerPage");
    if (optQueryLogsEntriesPerPage != null)
        $("#optQueryLogsEntriesPerPage").val(optQueryLogsEntriesPerPage);
}

function reloadClassPath() {
    if (appsList == null)
        return;

    var appName = $("#optQueryLogsAppName").val();
    var optClassPaths = "";

    for (var i = 0; i < appsList.length; i++) {
        if (appsList[i].name == appName) {
            for (var j = 0; j < appsList[i].dnsApps.length; j++) {
                if (appsList[i].dnsApps[j].isQueryLogs)
                    optClassPaths += "<option>" + htmlEncode(appsList[i].dnsApps[j].classPath) + "</option>";
            }

            break;
        }
    }

    $("#optQueryLogsClassPath").html(optClassPaths);
}

function refreshLogsTab() {
    if ($("#logsTabListLogViewer").hasClass("active"))
        refreshLogFilesList();
    else if ($("#logsTabListQueryLogs").hasClass("active"))
        refreshQueryLogsTab();
}

function refreshLogFilesList(selectedFileName) {
    var lstLogFiles = $("#lstLogFiles");

    HTTPRequest({
        url: "api/logs/list",
        token: sessionData.token,
        success: function (responseJSON) {
            var logFiles = responseJSON.response.logFiles;

            var list = "<div class=\"log log-action\"><a href=\"#\" class=\"text-danger\" onclick=\"deleteAllStats(); return false;\"><span class=\"fa fa-bar-chart fa-fw\" aria-hidden=\"true\"></span>Gesamte Statistik löschen</a></div>";

            if (logFiles.length == 0) {
                list += "<div class=\"log log-empty\">Keine Protokolldateien vorhanden</div>";
            }
            else {
                list += "<div class=\"log log-action\"><a href=\"#\" class=\"text-danger\" onclick=\"deleteAllLogs(); return false;\"><span class=\"fa fa-trash-o fa-fw\" aria-hidden=\"true\"></span>Alle Protokolle löschen</a></div>";

                for (var i = 0; i < logFiles.length; i++) {
                    var logFile = logFiles[i];

                    list += "<div class=\"log\"><a href=\"#\" onclick=\"viewLog(" + jsArg(logFile.fileName) + "); return false;\"><span class=\"log-name\">" + htmlEncode(logFile.fileName) + "</span><span class=\"log-size\">" + htmlEncode(logFile.size) + "</span></a></div>";
                }
            }

            lstLogFiles.html(list);

            if (selectedFileName != null) {
                for (var i = 0; i < logFiles.length; i++) {
                    if (logFiles[i].fileName == selectedFileName) {
                        viewLog(selectedFileName);
                        return;
                    }
                }

                $("#divLogViewer").hide();
            }
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: lstLogFiles
    });
}

function viewLog(logFile) {
    var divLogViewer = $("#divLogViewer");
    var txtLogViewerTitle = $("#txtLogViewerTitle");
    var divLogViewerLoader = $("#divLogViewerLoader");
    var preLogViewerBody = $("#preLogViewerBody");

    txtLogViewerTitle.text(logFile);

    preLogViewerBody.hide();
    divLogViewerLoader.show();
    divLogViewer.show();

    HTTPRequest({
        url: "api/logs/download?fileName=" + encodeURIComponent(logFile) + "&limit=2",
        token: sessionData.token,
        isTextResponse: true,
        success: function (response) {
            divLogViewerLoader.hide();

            if (response.status != null)
                response = JSON.stringify(response, null, 2);

            preLogViewerBody.text(response);
            preLogViewerBody.show();
        },
        objLoaderPlaceholder: divLogViewerLoader
    });
}

function downloadLog(objBtn) {
    var logFile = $("#txtLogViewerTitle").text();
    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/user/createSingleUseToken",
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");

            window.open("api/logs/download?token=" + responseJSON.response.token + "&fileName=" + encodeURIComponent(logFile) + "&ts=" + (new Date().getTime()), "_blank");
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

function deleteLog() {
    var logFile = $("#txtLogViewerTitle").text();

    if (!confirm("Protokolldatei '" + logFile + "' endgültig löschen?"))
        return;

    var btn = $("#btnDeleteLog");
    btn.button("loading");

    HTTPRequest({
        url: "api/logs/delete?log=" + encodeURIComponent(logFile),
        token: sessionData.token,
        success: function (responseJSON) {
            refreshLogFilesList();

            $("#divLogViewer").hide();
            btn.button("reset");

            showAlert("success", "Protokoll gelöscht", "Die Protokolldatei wurde gelöscht.");
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

function deleteAllLogs() {
    if (!confirm("Alle Protokolldateien endgültig löschen?"))
        return;

    HTTPRequest({
        url: "api/logs/deleteAll",
        token: sessionData.token,
        success: function (responseJSON) {
            refreshLogFilesList();

            $("#divLogViewer").hide();

            showAlert("success", "Protokolle gelöscht", "Alle Protokolldateien wurden gelöscht.");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function deleteAllStats() {
    if (!confirm("Die gesamte Statistik endgültig löschen?"))
        return;

    HTTPRequest({
        url: "api/dashboard/stats/deleteAll",
        token: sessionData.token,
        success: function (responseJSON) {
            showAlert("success", "Statistik gelöscht", "Die Statistik wurde gelöscht.");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

var appsList;

function refreshQueryLogsTab(doQueryLogs) {
    var frmQueryLogs = $("#frmQueryLogs");
    var divQueryLogsLoader = $("#divQueryLogsLoader");

    var optQueryLogsAppName = $("#optQueryLogsAppName");
    var optQueryLogsClassPath = $("#optQueryLogsClassPath");

    var currentAppName = optQueryLogsAppName.val();
    var currentClassPath = optQueryLogsClassPath.val();
    var loader;

    if (appsList == null) {
        frmQueryLogs.hide();
        loader = divQueryLogsLoader;
    }
    else {
        optQueryLogsAppName.prop("disabled", true);
        optQueryLogsClassPath.prop("disabled", true);
    }

    HTTPRequest({
        url: "api/apps/list",
        token: sessionData.token,
        success: function (responseJSON) {
            var apps = responseJSON.response.apps;

            var optApps = "";
            var optClassPaths = "";

            for (var i = 0; i < apps.length; i++) {
                if (!apps[i].enabled)
                    continue;

                for (var j = 0; j < apps[i].dnsApps.length; j++) {
                    if (apps[i].dnsApps[j].isQueryLogs) {
                        optApps += "<option value=\"" + htmlEncode(apps[i].name) + "\">" + htmlEncode(getAppDisplayName(apps[i].name)) + "</option>";

                        if (currentAppName == null)
                            currentAppName = apps[i].name;

                        break;
                    }
                }
            }

            for (var i = 0; i < apps.length; i++) {
                if (apps[i].name == currentAppName) {
                    for (var j = 0; j < apps[i].dnsApps.length; j++) {
                        if (apps[i].dnsApps[j].isQueryLogs)
                            optClassPaths += "<option>" + htmlEncode(apps[i].dnsApps[j].classPath) + "</option>";
                    }

                    break;
                }
            }

            optQueryLogsAppName.html(optApps);
            optQueryLogsClassPath.html(optClassPaths);

            if (currentAppName != null)
                optQueryLogsAppName.val(currentAppName);

            if (currentClassPath != null)
                optQueryLogsClassPath.val(currentClassPath);

            if (appsList == null) {
                frmQueryLogs.show();
                loader.hide();
            }
            else {
                optQueryLogsAppName.prop("disabled", false);
                optQueryLogsClassPath.prop("disabled", false);
            }

            appsList = apps;

            if (doQueryLogs)
                queryLogs();
        },
        error: function () {
            if (appsList == null) {
                frmQueryLogs.show();
            }
            else {
                optQueryLogsAppName.prop("disabled", false);
                optQueryLogsClassPath.prop("disabled", false);
            }
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: loader
    });
}

function queryLogs(pageNumber, liveUpdate) {
    if (!liveUpdate && $("#chkQueryLogsLiveUpdate").prop("checked"))
        return;

    var btn = $("#btnQueryLogs");

    var divQueryLogsLoader = $("#divQueryLogsLoader");
    var divQueryLogsTable = $("#divQueryLogsTable");

    var name = $("#optQueryLogsAppName").val();
    if (name == null) {
        showAlert("warning", "Angabe fehlt", "Für das Abfrageprotokoll wird eine Query-Logs-App benötigt, z. B. 'Query Logs (Sqlite)' aus dem Bereich Apps.");
        $("#optQueryLogsAppName").trigger("focus");
        return false;
    }

    var classPath = $("#optQueryLogsClassPath").val();
    if (classPath == null) {
        showAlert("warning", "Angabe fehlt", "Bitte einen Klassenpfad auswählen.");
        $("#optQueryLogsClassPath").trigger("focus");
        return false;
    }

    if (pageNumber == null)
        pageNumber = $("#txtQueryLogPageNumber").val();

    var entriesPerPage = Number($("#optQueryLogsEntriesPerPage").val());
    if (entriesPerPage < 1)
        entriesPerPage = 10;

    var descendingOrder = $("#optQueryLogsDescendingOrder").val();

    if (document.getElementById("txtQueryLogStart").validity.badInput) {
        showAlert("warning", "Angabe fehlt", "Bitte ein gültiges Datum für 'Von' eingeben.");
        $("#txtQueryLogStart").trigger("focus");
        return false;
    }

    var start = $("#txtQueryLogStart").val();
    if (start != "")
        start = moment(start).toISOString();

    if (document.getElementById("txtQueryLogEnd").validity.badInput) {
        showAlert("warning", "Angabe fehlt", "Bitte ein gültiges Datum für 'Bis' eingeben.");
        $("#txtQueryLogEnd").trigger("focus");
        return false;
    }

    var end = $("#txtQueryLogEnd").val();
    if (end != "")
        end = moment(end).toISOString();

    var clientIpAddress = $("#txtQueryLogClientIpAddress").val();
    var protocol = $("#optQueryLogsProtocol").val();
    var responseType = $("#optQueryLogsResponseType").val();
    var rcode = $("#optQueryLogsResponseCode").val();
    var qname = $("#txtQueryLogQName").val();
    var qtype = $("#txtQueryLogQType").val();
    var qclass = $("#optQueryLogQClass").val();

    if (!liveUpdate) {
        divQueryLogsTable.hide();
        divQueryLogsLoader.show();

        btn.button("loading");
    }

    HTTPRequest({
        url: "api/logs/query?name=" + encodeURIComponent(name) + "&classPath=" + encodeURIComponent(classPath) + "&pageNumber=" + pageNumber + "&entriesPerPage=" + entriesPerPage + "&descendingOrder=" + descendingOrder +
            "&start=" + encodeURIComponent(start) + "&end=" + encodeURIComponent(end) + "&clientIpAddress=" + encodeURIComponent(clientIpAddress) + "&protocol=" + protocol + "&responseType=" + responseType + "&rcode=" + rcode +
            "&qname=" + encodeURIComponent(qname) + "&qtype=" + qtype + "&qclass=" + qclass,
        token: sessionData.token,
        success: function (responseJSON) {
            var tableHtml = "";

            for (var i = 0; i < responseJSON.response.entries.length; i++) {
                var trbgcolor;

                switch (responseJSON.response.entries[i].rcode.toLowerCase()) {
                    case "serverfailure":
                        trbgcolor = "rgba(217, 83, 79, 0.1)";
                        break;

                    case "nxdomain":
                        switch (responseJSON.response.entries[i].responseType.toLowerCase()) {
                            case "blocked":
                            case "upstreamblocked":
                            case "upstreamblockedcached":
                                trbgcolor = "rgba(255, 165, 0, 0.1)";
                                break;

                            default:
                                trbgcolor = "rgba(120, 120, 120, 0.1)";
                                break;
                        }

                        break;

                    case "refused":
                        trbgcolor = "rgba(91, 192, 222, 0.1)";
                        break;

                    default:
                        switch (responseJSON.response.entries[i].responseType.toLowerCase()) {
                            case "authoritative":
                                trbgcolor = "rgba(150, 150, 0, 0.1)";
                                break;

                            case "recursive":
                                trbgcolor = "rgba(23, 162, 184, 0.1)";
                                break;

                            case "cached":
                                trbgcolor = "rgba(111, 84, 153, 0.1)";
                                break;

                            case "blocked":
                            case "upstreamblocked":
                            case "upstreamblockedcached":
                                trbgcolor = "rgba(255, 165, 0, 0.1)";
                                break;

                            default:
                                trbgcolor = null;
                                break;
                        }

                        break;
                }

                tableHtml += "<tr" + (trbgcolor == null ? "" : " style=\"background-color: " + trbgcolor + ";\"") + "><td>" + responseJSON.response.entries[i].rowNumber + "</td><td>" +
                    moment(responseJSON.response.entries[i].timestamp).local().format("DD.MM.YYYY HH:mm:ss") + "</td><td style=\"word-break: break-all; min-width: 125px;\">" +
                    responseJSON.response.entries[i].clientIpAddress + "</td><td>" +
                    responseJSON.response.entries[i].protocol + "</td><td>" +
                    responseJSON.response.entries[i].responseType + (responseJSON.response.entries[i].responseRtt == null ? "" : "<div style=\"font-size: 12px;\">(" + responseJSON.response.entries[i].responseRtt.toFixed(2) + " ms)</div>") + "</td><td>" +
                    formatRcode(responseJSON.response.entries[i].rcode) + "</td><td style=\"word-break: break-all;\">" +
                    htmlEncode(responseJSON.response.entries[i].qname == "" ? "." : responseJSON.response.entries[i].qname) + "</td><td>" +
                    (responseJSON.response.entries[i].qtype == null ? "" : responseJSON.response.entries[i].qtype) + "</td><td>" +
                    (responseJSON.response.entries[i].qclass == null ? "" : responseJSON.response.entries[i].qclass) + "</td><td style=\"word-break: break-all;\">" +
                    htmlEncode(responseJSON.response.entries[i].answer) +
                    "</td><td align=\"right\"><div class=\"dropdown\"><a href=\"#\" id=\"btnQueryLogsRowOption" + i + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";

                tableHtml += "<li><a href=\"#\" data-id=\"" + i + "\" data-domain=\"" + htmlEncode(responseJSON.response.entries[i].qname) + "\" onclick=\"queryDnsServer($(this).attr('data-domain'), " + jsArg(responseJSON.response.entries[i].qtype) + "); return false;\">Mit DNS-Client abfragen</a></li>";

                switch (responseJSON.response.entries[i].responseType.toLowerCase()) {
                    case "blocked":
                    case "upstreamblocked":
                    case "upstreamblockedcached":
                        tableHtml += "<li><a href=\"#\" data-id=\"" + i + "\" data-domain=\"" + htmlEncode(responseJSON.response.entries[i].qname) + "\" onclick=\"allowDomain(this, 'btnQueryLogsRowOption'); return false;\">Domain erlauben</a></li>";
                        break;

                    default:
                        tableHtml += "<li><a href=\"#\" data-id=\"" + i + "\" data-domain=\"" + htmlEncode(responseJSON.response.entries[i].qname) + "\" onclick=\"blockDomain(this, 'btnQueryLogsRowOption'); return false;\">Domain blockieren</a></li>";
                        break;
                }

                tableHtml += "</ul></div></td></tr>";
            }

            var paginationHtml = "";

            if (responseJSON.response.pageNumber > 1) {
                paginationHtml += "<li><a href=\"#\" aria-label=\"First\" onClick=\"queryLogs(1); return false;\"><span aria-hidden=\"true\">&laquo;</span></a></li>";
                paginationHtml += "<li><a href=\"#\" aria-label=\"Zurück\" onClick=\"queryLogs(" + (responseJSON.response.pageNumber - 1) + "); return false;\"><span aria-hidden=\"true\">&lsaquo;</span></a></li>";
            }

            var pageStart = responseJSON.response.pageNumber - 5;
            if (pageStart < 1)
                pageStart = 1;

            var pageEnd = pageStart + 9;
            if (pageEnd > responseJSON.response.totalPages) {
                var endDiff = pageEnd - responseJSON.response.totalPages;
                pageEnd = responseJSON.response.totalPages;

                pageStart -= endDiff;
                if (pageStart < 1)
                    pageStart = 1;
            }

            for (var i = pageStart; i <= pageEnd; i++) {
                if (i == responseJSON.response.pageNumber)
                    paginationHtml += "<li class=\"active\"><a href=\"#\" onClick=\"queryLogs(" + i + "); return false;\">" + i + "</a></li>";
                else
                    paginationHtml += "<li><a href=\"#\" onClick=\"queryLogs(" + i + "); return false;\">" + i + "</a></li>";
            }

            if (responseJSON.response.pageNumber < responseJSON.response.totalPages) {
                paginationHtml += "<li><a href=\"#\" aria-label=\"Weiter\" onClick=\"queryLogs(" + (responseJSON.response.pageNumber + 1) + "); return false;\"><span aria-hidden=\"true\">&rsaquo;</span></a></li>";
                paginationHtml += "<li><a href=\"#\" aria-label=\"Last\" onClick=\"queryLogs(-1); return false;\"><span aria-hidden=\"true\">&raquo;</span></a></li>";
            }

            $("#tableQueryLogsBody").html(tableHtml);

            var statusHtml;

            if (responseJSON.response.entries.length > 0)
                statusHtml = responseJSON.response.entries[0].rowNumber + "-" + responseJSON.response.entries[responseJSON.response.entries.length - 1].rowNumber + " von " + responseJSON.response.totalEntries + " Einträgen (Seite " + responseJSON.response.pageNumber + " von " + responseJSON.response.totalPages + ")";
            else
                statusHtml = "0 Einträge";

            $("#tableQueryLogsTopStatus").html(statusHtml);
            $("#tableQueryLogsTopPagination").html(paginationHtml);

            $("#tableQueryLogsFooterStatus").html(statusHtml);
            $("#tableQueryLogsFooterPagination").html(paginationHtml);

            if (liveUpdate) {
                setTimeout(function () {
                    if ($("#chkQueryLogsLiveUpdate").prop("checked")) {
                        queryLogs(1, true);
                    }
                }, 2000);
            }
            else {
                btn.button("reset");
            }

            divQueryLogsLoader.hide();
            divQueryLogsTable.show();
        },
        error: function () {
            if (liveUpdate) {
                setTimeout(function () {
                    if ($("#chkQueryLogsLiveUpdate").prop("checked")) {
                        queryLogs(1, true);
                    }
                }, 2000);
            }
            else {
                btn.button("reset");
            }
        },
        invalidToken: function () {
            btn.button("reset");
            showPageLogin();
        },
        objLoaderPlaceholder: divQueryLogsLoader
    });
}

function showQueryLogs(domain, clientIp) {
    $("#frmQueryLogs").trigger("reset");
    resetQueryLogsForm();

    if (domain != null)
        $("#txtQueryLogQName").val(domain);

    if (clientIp != null)
        $("#txtQueryLogClientIpAddress").val(clientIp);

    $("#mainPanelTabListLogs a").tab("show");

    $("#logsTabListLogViewer").removeClass("active");
    $("#logsTabPaneLogViewer").removeClass("active");

    $("#logsTabListQueryLogs").addClass("active");
    $("#logsTabPaneQueryLogs").addClass("active");

    $("#modalTopStats").modal("hide");

    refreshQueryLogsTab(true);
}

function exportQueryLogsCsv(objBtn) {
    var name = $("#optQueryLogsAppName").val();
    if (name == null) {
        showAlert("warning", "Angabe fehlt", "Für das Abfrageprotokoll wird eine Query-Logs-App benötigt, z. B. 'Query Logs (Sqlite)'.");
        $("#optQueryLogsAppName").trigger("focus");
        return false;
    }

    var classPath = $("#optQueryLogsClassPath").val();
    if (classPath == null) {
        showAlert("warning", "Angabe fehlt", "Bitte einen Klassenpfad auswählen.");
        $("#optQueryLogsClassPath").trigger("focus");
        return false;
    }

    var start = $("#txtQueryLogStart").val();
    if (start != "")
        start = moment(start).toISOString();

    var end = $("#txtQueryLogEnd").val();
    if (end != "")
        end = moment(end).toISOString();

    var clientIpAddress = $("#txtQueryLogClientIpAddress").val();
    var protocol = $("#optQueryLogsProtocol").val();
    var responseType = $("#optQueryLogsResponseType").val();
    var rcode = $("#optQueryLogsResponseCode").val();
    var qname = $("#txtQueryLogQName").val();
    var qtype = $("#txtQueryLogQType").val();
    var qclass = $("#optQueryLogQClass").val();

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/user/createSingleUseToken",
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");

            window.open("api/logs/export?token=" + responseJSON.response.token + "&name=" + encodeURIComponent(name) + "&classPath=" + encodeURIComponent(classPath) +
                "&start=" + encodeURIComponent(start) + "&end=" + encodeURIComponent(end) + "&clientIpAddress=" + encodeURIComponent(clientIpAddress) +
                "&protocol=" + protocol + "&responseType=" + responseType + "&rcode=" + rcode + "&qname=" + encodeURIComponent(qname) + "&qtype=" + qtype + "&qclass=" + qclass, "_blank");
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

function formatRcode(rcode) {
    switch (String(rcode)) {
        case "NoError":
            return "NOERROR";

        case "FormatError":
            return "FORMERR";

        case "ServerFailure":
            return "SERVFAIL";

        case "NxDomain":
            return "NXDOMAIN";

        case "NotImplemented":
            return "NOTIMP";

        case "Refused":
            return "REFUSED";

        default:
            return htmlEncode(String(rcode).toUpperCase());
    }
}

