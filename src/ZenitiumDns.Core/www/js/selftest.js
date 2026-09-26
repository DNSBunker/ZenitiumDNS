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
            return "In Ordnung";

        case "info":
            return "Hinweis";

        case "warning":
            return "Warnung";

        default:
            return "Fehler";
    }
}

function canRunSelfTest() {
    return (sessionData != null) && (sessionData.info != null) && (sessionData.info.permissions != null) && sessionData.info.permissions.Settings.canView;
}

function renderSelfTest(response) {
    var groups = [];
    var groupResults = {};

    for (var i = 0; i < response.results.length; i++) {
        var result = response.results[i];

        if (groupResults[result.group] == null) {
            groupResults[result.group] = [];
            groups.push(result.group);
        }

        groupResults[result.group].push(result);
    }

    var html = "";

    for (var i = 0; i < groups.length; i++) {
        html += "<section class=\"selftest-group\"><h3 class=\"selftest-group-title\">" + htmlEncode(groups[i]) + "</h3><ul class=\"selftest-list\">";

        for (var j = 0; j < groupResults[groups[i]].length; j++) {
            var item = groupResults[groups[i]][j];

            html += "<li class=\"selftest-item selftest-" + item.status + "\"><span class=\"fa fa-fw " + getSelfTestStatusIcon(item.status) + " selftest-icon\" aria-hidden=\"true\"></span>";
            html += "<div class=\"selftest-body\"><div class=\"selftest-title\">" + htmlEncode(item.title) + " <span class=\"selftest-state\">" + getSelfTestStatusLabel(item.status) + "</span></div>";
            html += "<div class=\"selftest-message\">" + htmlEncode(item.message) + "</div></div></li>";
        }

        html += "</ul></section>";
    }

    $("#divSelfTestResults").html(html);

    var summary;

    if (response.errors > 0)
        summary = "<span class=\"status-chip status-danger\"><span class=\"fa fa-times-circle\" aria-hidden=\"true\"></span>" + response.errors + " Fehler</span>";
    else
        summary = "<span class=\"status-chip status-success\"><span class=\"fa fa-check-circle\" aria-hidden=\"true\"></span>Keine Fehler</span>";

    if (response.warnings > 0)
        summary += " <span class=\"status-chip status-warning\"><span class=\"fa fa-exclamation-triangle\" aria-hidden=\"true\"></span>" + response.warnings + (response.warnings === 1 ? " Warnung" : " Warnungen") + "</span>";

    summary += " <span class=\"selftest-time\">Stand " + moment(response.runOn).local().format("DD.MM.YYYY HH:mm:ss") + "</span>";

    $("#divSelfTestSummary").html(summary);
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

    var html = "<span class=\"fa fa-times-circle dashboard-health-icon\" aria-hidden=\"true\"></span><div class=\"dashboard-health-body\"><div class=\"dashboard-health-title\">" + (errors.length === 1 ? "Ein schweres Problem gefunden" : errors.length + " schwere Probleme gefunden") + "</div><ul>";

    for (var i = 0; i < errors.length; i++)
        html += "<li><b>" + htmlEncode(errors[i].title) + ":</b> " + htmlEncode(errors[i].message) + "</li>";

    html += "</ul><a href=\"#\" onclick=\"showSelfTest(); return false;\">Alle Ergebnisse im Selbsttest</a></div>";

    divDashboardHealth.html(html);
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
