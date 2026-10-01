/*
ZenitiumDNS
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

var selfTestLastCheck = 0;

function getSelfTestStatusIcon(status) {
    switch (status) {
        case "ok":
            return "fa-check-circle";

        case "info":
            return "fa-info-circle";

        case "warning":
            return "fa-exclamation-triangle";

        default:
            return "fa-times-circle";
    }
}

function getSelfTestStatusLabel(status) {
    switch (status) {
        case "ok":
            return tr("In Ordnung");

        case "info":
            return tr("Hinweis");

        case "warning":
            return tr("Warnung");

        default:
            return tr("Fehler");
    }
}

function canRunSelfTest() {
    return (sessionData != null) && (sessionData.info != null) && (sessionData.info.permissions != null) && sessionData.info.permissions.Settings.canView;
}

var selfTestFilter = "all";
var selfTestLastResponse = null;

try {
    if (localStorage.getItem("selfTestFilter") === "problems")
        selfTestFilter = "problems";
}
catch (e) {
}

var SELFTEST_STATUS_ORDER = { "error": 0, "warning": 1, "info": 2, "ok": 3 };

function isSelfTestProblem(status) {
    return (status === "error") || (status === "warning");
}

function openSelfTestSection(section) {
    if (section == null)
        return;

    if (section.indexOf("settings:") === 0) {
        showSettingsSection("settingsTabList" + section.substring(9));
        return;
    }

    switch (section) {
        case "clients":
            $("#mainPanelTabListFilter a").tab("show");
            $("#filterTabListClients a").tab("show");
            break;

        case "apps":
            $("#mainPanelTabListApps a").tab("show");
            break;

        case "dhcp":
            $("#mainPanelTabListDhcp a").tab("show");
            refreshDhcpTab();
            break;

        case "password":
            showChangePasswordModal();
            break;
    }
}

function getSelfTestActionHtml(item) {
    if ((item.section == null) || (item.status === "ok"))
        return "";

    return "<button type=\"button\" class=\"btn btn-default btn-xs selftest-action\" data-section=\"" + htmlEncode(item.section) + "\">" + htmlEncode(tr("Öffnen")) + " <span class=\"fa fa-angle-right\" aria-hidden=\"true\"></span></button>";
}

function getSelfTestItemHtml(item, showGroup) {
    var html = "<li class=\"selftest-item selftest-" + item.status + "\"><span class=\"fa fa-fw " + getSelfTestStatusIcon(item.status) + " selftest-icon\" aria-hidden=\"true\"></span>";

    html += "<div class=\"selftest-body\"><div class=\"selftest-title\">" + (showGroup ? "<span class=\"selftest-group-label\">" + htmlEncode(item.group) + "</span> " : "") + htmlEncode(item.title) + " <span class=\"selftest-state\">" + htmlEncode(getSelfTestStatusLabel(item.status)) + "</span></div>";
    html += "<div class=\"selftest-message\">" + htmlEncode(item.message) + "</div></div>";
    html += getSelfTestActionHtml(item) + "</li>";

    return html;
}

function getSelfTestCountChips(counts) {
    var html = "";
    var statuses = ["error", "warning", "info", "ok"];

    for (var i = 0; i < statuses.length; i++) {
        var status = statuses[i];

        if (counts[status] > 0)
            html += "<span class=\"selftest-count selftest-count-" + status + "\" title=\"" + htmlEncode(getSelfTestStatusLabel(status)) + "\"><span class=\"fa " + getSelfTestStatusIcon(status) + "\" aria-hidden=\"true\"></span> " + counts[status] + "</span>";
    }

    return html;
}

function renderSelfTest(response) {
    selfTestLastResponse = response;

    var groups = [];
    var groupResults = {};
    var problems = [];

    for (var i = 0; i < response.results.length; i++) {
        var result = response.results[i];

        if (groupResults[result.group] == null) {
            groupResults[result.group] = [];
            groups.push(result.group);
        }

        groupResults[result.group].push(result);

        if (isSelfTestProblem(result.status))
            problems.push(result);
    }

    problems.sort(function (a, b) { return SELFTEST_STATUS_ORDER[a.status] - SELFTEST_STATUS_ORDER[b.status]; });

    var total = response.results.length;
    var worst = (response.errors > 0) ? "error" : ((response.warnings > 0) ? "warning" : "ok");
    var headline;

    if ((response.errors > 0) && (response.warnings > 0))
        headline = tr("{0} Fehler und {1} Warnungen", response.errors, response.warnings);
    else if (response.errors > 0)
        headline = (response.errors === 1) ? tr("Ein Fehler") : tr("{0} Fehler", response.errors);
    else if (response.warnings > 0)
        headline = (response.warnings === 1) ? tr("Eine Warnung") : tr("{0} Warnungen", response.warnings);
    else
        headline = tr("Alles in Ordnung");

    var meta = tr("Stand {0}", moment(response.runOn).local().format(tr("DD.MM.YYYY HH:mm:ss"))) + " · " + tr("{0} Prüfungen", total);

    if (response.durationMs != null)
        meta += " · " + tr("Dauer {0} s", (response.durationMs / 1000).toLocaleString(zdnsI18n.locale, { minimumFractionDigits: 1, maximumFractionDigits: 1 }));

    var summary = "<div class=\"selftest-overview selftest-overview-" + worst + "\">";
    summary += "<span class=\"fa " + getSelfTestStatusIcon(worst) + " selftest-overview-icon\" aria-hidden=\"true\"></span>";
    summary += "<div class=\"selftest-overview-text\"><div class=\"selftest-overview-title\">" + htmlEncode(headline) + "</div><div class=\"selftest-overview-meta\">" + htmlEncode(meta) + "</div></div>";
    summary += "<div class=\"btn-group btn-group-sm selftest-filter\" role=\"group\" aria-label=\"" + htmlEncode(tr("Anzeige")) + "\">";
    summary += "<button type=\"button\" class=\"btn btn-default" + (selfTestFilter === "all" ? " active" : "") + "\" data-filter=\"all\">" + htmlEncode(tr("Alle")) + " <span class=\"badge\">" + total + "</span></button>";
    summary += "<button type=\"button\" class=\"btn btn-default" + (selfTestFilter === "problems" ? " active" : "") + "\" data-filter=\"problems\">" + htmlEncode(tr("Handlungsbedarf")) + " <span class=\"badge\">" + problems.length + "</span></button>";
    summary += "</div></div>";

    $("#divSelfTestSummary").html(summary);

    var html = "";

    if (problems.length > 0) {
        html += "<section class=\"selftest-group selftest-problems\"><h3 class=\"selftest-group-title\">" + htmlEncode(tr("Handlungsbedarf")) + "</h3><ul class=\"selftest-list\">";

        for (var p = 0; p < problems.length; p++)
            html += getSelfTestItemHtml(problems[p], true);

        html += "</ul></section>";
    }
    else if (selfTestFilter === "problems") {
        html += "<p class=\"selftest-empty\"><span class=\"fa fa-check-circle\" aria-hidden=\"true\"></span> " + htmlEncode(tr("Keine Fehler und keine Warnungen.")) + "</p>";
    }

    if (selfTestFilter === "all") {
        for (var g = 0; g < groups.length; g++) {
            var items = groupResults[groups[g]];
            var counts = { "error": 0, "warning": 0, "info": 0, "ok": 0 };

            for (var k = 0; k < items.length; k++)
                counts[items[k].status]++;

            var hasProblems = (counts.error + counts.warning) > 0;

            html += "<details class=\"selftest-group selftest-details\"" + (hasProblems ? " open" : "") + "><summary class=\"selftest-group-summary\"><span class=\"selftest-group-name\">" + htmlEncode(groups[g]) + "</span><span class=\"selftest-counts\">" + getSelfTestCountChips(counts) + "</span></summary><ul class=\"selftest-list\">";

            for (var j = 0; j < items.length; j++)
                html += getSelfTestItemHtml(items[j], false);

            html += "</ul></details>";
        }
    }

    var divResults = $("#divSelfTestResults");
    divResults.html(html);

    divResults.find("button.selftest-action").on("click", function () {
        openSelfTestSection($(this).attr("data-section"));
    });

    $("#divSelfTestSummary").find("button[data-filter]").on("click", function () {
        selfTestFilter = $(this).attr("data-filter");

        try {
            localStorage.setItem("selfTestFilter", selfTestFilter);
        }
        catch (e) {
        }

        renderSelfTest(selfTestLastResponse);
    });
}

function updateDashboardHealth(response) {
    var errors = [];

    for (var i = 0; i < response.results.length; i++) {
        if (response.results[i].status === "error")
            errors.push(response.results[i]);
    }

    var divDashboardHealth = $("#divDashboardHealth");

    if (errors.length === 0) {
        divDashboardHealth.hide();
        return;
    }

    var html = "<span class=\"fa fa-times-circle dashboard-health-icon\" aria-hidden=\"true\"></span><div class=\"dashboard-health-body\"><div class=\"dashboard-health-title\">" + (errors.length === 1 ? tr("Ein schweres Problem gefunden") : tr("{0} schwere Probleme gefunden", errors.length)) + "</div><ul>";

    for (var i = 0; i < errors.length; i++)
        html += "<li><b>" + htmlEncode(errors[i].title) + ":</b> " + htmlEncode(errors[i].message) + (errors[i].section != null ? " <a href=\"#\" class=\"dashboard-health-action\" data-section=\"" + htmlEncode(errors[i].section) + "\">" + htmlEncode(tr("Öffnen")) + "</a>" : "") + "</li>";

    html += "</ul><a href=\"#\" onclick=\"showSelfTest(); return false;\">" + tr("Alle Ergebnisse im Selbsttest") + "</a></div>";

    divDashboardHealth.html(html);
    divDashboardHealth.find("a.dashboard-health-action").on("click", function () {
        openSelfTestSection($(this).attr("data-section"));
        return false;
    });
    divDashboardHealth.show();
}

function refreshSelfTest(force) {
    if (!canRunSelfTest())
        return;

    var btn = $("#btnSelfTestRun");
    var divSelfTestLoader = $("#divSelfTestLoader");

    btn.button("loading");

    if (force || ($("#divSelfTestResults").html() === "")) {
        $("#divSelfTestResults").hide();
        divSelfTestLoader.show();
    }

    HTTPRequest({
        url: "api/selftest/run" + (force ? "?refresh=true" : ""),
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");
            divSelfTestLoader.hide();
            $("#divSelfTestResults").show();

            selfTestLastCheck = Date.now();
            renderSelfTest(responseJSON.response);
            updateDashboardHealth(responseJSON.response);
        },
        error: function () {
            btn.button("reset");
            divSelfTestLoader.hide();
            $("#divSelfTestResults").show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divSelfTestLoader
    });
}

function checkDashboardHealth() {
    if (!canRunSelfTest()) {
        $("#divDashboardHealth").hide();
        return;
    }

    if ((Date.now() - selfTestLastCheck) < 60000)
        return;

    selfTestLastCheck = Date.now();

    HTTPRequest({
        url: "api/selftest/run",
        token: sessionData.token,
        success: function (responseJSON) {
            renderSelfTest(responseJSON.response);
            updateDashboardHealth(responseJSON.response);
        },
        error: function () {
            selfTestLastCheck = 0;
        },
        invalidToken: function () {
            showPageLogin();
        },
        objAlertPlaceholder: $("#divDashboardHealthAlert")
    });
}

function showSelfTest() {
    $("#mainPanelTabListSelfTest a").tab("show");
    refreshSelfTest(false);
}
