if (moment.locales().indexOf("de") < 0) {
    moment.defineLocale("de", {
        months: "Januar_Februar_März_April_Mai_Juni_Juli_August_September_Oktober_November_Dezember".split("_"),
        monthsShort: "Jan._Feb._März_Apr._Mai_Juni_Juli_Aug._Sep._Okt._Nov._Dez.".split("_"),
        weekdays: "Sonntag_Montag_Dienstag_Mittwoch_Donnerstag_Freitag_Samstag".split("_"),
        weekdaysShort: "So._Mo._Di._Mi._Do._Fr._Sa.".split("_"),
        weekdaysMin: "So_Mo_Di_Mi_Do_Fr_Sa".split("_"),
        longDateFormat: {
            LT: "HH:mm",
            LTS: "HH:mm:ss",
            L: "DD.MM.YYYY",
            LL: "D. MMMM YYYY",
            LLL: "D. MMMM YYYY HH:mm",
            LLLL: "dddd, D. MMMM YYYY HH:mm",
            lll: "D. MMM YYYY HH:mm"
        },
        relativeTime: {
            future: "in %s",
            past: "vor %s",
            s: "ein paar Sekunden",
            ss: "%d Sekunden",
            m: "einer Minute",
            mm: "%d Minuten",
            h: "einer Stunde",
            hh: "%d Stunden",
            d: "einem Tag",
            dd: "%d Tagen",
            M: "einem Monat",
            MM: "%d Monaten",
            y: "einem Jahr",
            yy: "%d Jahren"
        },
        week: { dow: 1, doy: 4 }
    });
}
else {
    moment.locale("de");
}


var dashboardLastResponse = null;
var dashboardMainChartData = null;
var dashboardResponseTimeData = null;

var dashboardSeries = {
    "Total": { label: "Gesamt", token: "--c1" },
    "No Error": { label: "Kein Fehler", token: "--c1" },
    "NX Domain": { label: "NXDOMAIN", token: "--c4" },
    "Refused": { label: "REFUSED", token: "--c6" },
    "Server Failure": { label: "SERVFAIL", token: "--c7" },
    "Cached": { label: "Cache", token: "--c2" },
    "Recursive": { label: "Rekursiv", token: "--c3" },
    "Blocked": { label: "Blockiert", token: "--c4" },
    "Authoritative": { label: "Lokal", token: "--c5" },
    "Upstream Blocked": { label: "Upstream blockiert", token: "--c5" },
    "Dropped": { label: "Verworfen", token: "--c-neutral" },
    "Clients": { label: "Clients", token: "--c1" }
};

var dashboardChartViews = {
    overview: { series: ["Total", "Cached", "Recursive", "Blocked"], stacked: false },
    responses: { series: ["No Error", "NX Domain", "Refused", "Server Failure"], stacked: true },
    sources: { series: ["Cached", "Recursive", "Blocked", "Authoritative", "Dropped"], stacked: true },
    clients: { series: ["Clients"], stacked: false }
};

var dashboardCategoricalTokens = ["--c1", "--c2", "--c3", "--c4", "--c5", "--c6", "--c7"];

var dashboardProtocolLabels = {
    "Udp": "UDP",
    "Tcp": "TCP",
    "Tls": "DNS-over-TLS",
    "Https": "DNS-over-HTTPS",
    "Quic": "DNS-over-QUIC",
    "UdpProxy": "UDP-PROXY",
    "TcpProxy": "TCP-PROXY",
    "HttpsJson": "DNS-over-HTTPS (JSON)"
};

function formatNumber(value, decimals) {
    if (value == null || isNaN(value))
        return "0";

    if (decimals == null)
        return Number(value).toLocaleString("de-DE");

    return Number(value).toLocaleString("de-DE", { minimumFractionDigits: decimals, maximumFractionDigits: decimals });
}

function formatPercent(part, total, decimals) {
    if (decimals == null)
        decimals = 1;

    if (!total)
        return formatNumber(0, decimals) + " %";

    return formatNumber(part * 100 / total, decimals) + " %";
}

function formatMilliseconds(value) {
    if (value == null || isNaN(value))
        return "0 ms";

    if (value >= 1000)
        return formatNumber(value / 1000, 2) + " s";

    if (value >= 100)
        return formatNumber(value, 0) + " ms";

    if (value >= 10)
        return formatNumber(value, 1) + " ms";

    return formatNumber(value, 2) + " ms";
}

function getThemeValue(token) {
    return getComputedStyle(document.body).getPropertyValue(token).trim();
}

function withAlpha(color, alpha) {
    if ((color.length === 7) && (color.charAt(0) === "#")) {
        var r = parseInt(color.substring(1, 3), 16);
        var g = parseInt(color.substring(3, 5), 16);
        var b = parseInt(color.substring(5, 7), 16);

        return "rgba(" + r + ", " + g + ", " + b + ", " + alpha + ")";
    }

    return color;
}

function getDashboardSeriesInfo(key) {
    var info = dashboardSeries[key];
    if (info == null)
        return { label: key, color: getThemeValue("--c-neutral") };

    return { label: info.label, color: getThemeValue(info.token) };
}

function getDashboardChartTheme() {
    return {
        font: getThemeValue("--axis"),
        ink: getThemeValue("--ink"),
        grid: getThemeValue("--grid"),
        line: getThemeValue("--line"),
        surface: getThemeValue("--surface"),
        fontFamily: getThemeValue("--font-text")
    };
}

function applyDashboardChartTheme(chart) {
    var theme = getDashboardChartTheme();
    var options = chart.options;

    options.legend.labels.fontColor = theme.font;
    options.legend.labels.fontFamily = theme.fontFamily;
    options.legend.labels.usePointStyle = true;
    options.legend.labels.boxWidth = 8;

    options.tooltips.backgroundColor = theme.surface;
    options.tooltips.borderColor = theme.line;
    options.tooltips.borderWidth = 1;
    options.tooltips.titleFontColor = theme.ink;
    options.tooltips.bodyFontColor = theme.ink;
    options.tooltips.titleFontFamily = theme.fontFamily;
    options.tooltips.bodyFontFamily = theme.fontFamily;
    options.tooltips.xPadding = 10;
    options.tooltips.yPadding = 8;
    options.tooltips.cornerRadius = 8;
    options.tooltips.caretSize = 5;
    options.tooltips.usePointStyle = true;
    options.tooltips.multiKeyBackground = theme.surface;

    if (options.scales != null) {
        var axes = (options.scales.xAxes || []).concat(options.scales.yAxes || []);

        for (var i = 0; i < axes.length; i++) {
            axes[i].ticks.fontColor = theme.font;
            axes[i].ticks.fontFamily = theme.fontFamily;
            axes[i].ticks.padding = 8;
            axes[i].gridLines.color = theme.grid;
            axes[i].gridLines.zeroLineColor = theme.line;
            axes[i].gridLines.drawBorder = false;
            axes[i].gridLines.drawTicks = false;
        }
    }

    if (chart.config.type === "doughnut") {
        for (var j = 0; j < chart.data.datasets.length; j++)
            chart.data.datasets[j].borderColor = theme.surface;
    }
}

function updateDashboardChartTheme() {
    if (dashboardLastResponse != null)
        renderDashboardCharts(dashboardLastResponse, false);
}

function getDashboardStatsQuery(showAlerts) {
    var type = $("input[name=rdStatType]:checked").val();
    var query = "type=" + type + "&utc=true";

    if (type === "custom") {
        var txtStart = $("#dpCustomDayWiseStart").val();
        if (txtStart === null || (txtStart === "")) {
            if (showAlerts) {
                showAlert("warning", "Angabe fehlt", "Bitte einen Startzeitpunkt wählen.");
                $("#dpCustomDayWiseStart").trigger("focus");
            }

            return null;
        }

        var txtEnd = $("#dpCustomDayWiseEnd").val();
        if (txtEnd === null || (txtEnd === "")) {
            if (showAlerts) {
                showAlert("warning", "Angabe fehlt", "Bitte einen Endzeitpunkt wählen.");
                $("#dpCustomDayWiseEnd").trigger("focus");
            }

            return null;
        }

        var start = moment(txtStart);
        var end = moment(txtEnd);

        if ((end.diff(start, "days") + 1) > 7) {
            start = moment.utc(txtStart).toISOString();
            end = moment.utc(txtEnd).toISOString();
        }
        else {
            start = start.toISOString();
            end = end.toISOString();
        }

        query += "&start=" + encodeURIComponent(start) + "&end=" + encodeURIComponent(end);
    }

    return query;
}

function getDashboardPeriodSeconds() {
    switch ($("input[name=rdStatType]:checked").val()) {
        case "lastHour":
            return 3600;

        case "lastDay":
            return 86400;

        case "lastWeek":
            return 7 * 86400;

        case "lastMonth":
            return 30 * 86400;

        case "lastYear":
            return 365 * 86400;

        case "custom":
            var start = moment($("#dpCustomDayWiseStart").val());
            var end = moment($("#dpCustomDayWiseEnd").val());
            var seconds = end.diff(start, "seconds");
            return seconds > 0 ? seconds : 0;
    }

    return 0;
}

function formatDashboardLabels(labels, labelFormat) {
    var useLocalTime = (labelFormat != null) && (labelFormat.indexOf("HH") >= 0);
    var formatted = new Array(labels.length);

    for (var i = 0; i < labels.length; i++) {
        var m = moment(labels[i]);
        formatted[i] = (useLocalTime ? m.local() : m.utc()).format(labelFormat);
    }

    return formatted;
}

function getMainChartSeries(key) {
    if (dashboardMainChartData == null)
        return null;

    for (var i = 0; i < dashboardMainChartData.datasets.length; i++) {
        if (dashboardMainChartData.datasets[i].label === key)
            return dashboardMainChartData.datasets[i].data;
    }

    return null;
}

function buildMainChartData(view) {
    if (dashboardMainChartData == null)
        return { labels: [], datasets: [] };

    var viewInfo = dashboardChartViews[view] || dashboardChartViews.overview;
    var datasets = [];

    for (var i = 0; i < viewInfo.series.length; i++) {
        var key = viewInfo.series[i];
        var data = getMainChartSeries(key);
        if (data == null)
            continue;

        var info = getDashboardSeriesInfo(key);
        var isLead = (i === 0) && !viewInfo.stacked;
        var fill = viewInfo.stacked ? (datasets.length === 0 ? "origin" : "-1") : (isLead ? "origin" : false);

        datasets.push({
            label: info.label,
            data: data,
            borderColor: info.color,
            backgroundColor: withAlpha(info.color, viewInfo.stacked ? 0.32 : 0.08),
            pointBackgroundColor: info.color,
            pointBorderColor: info.color,
            borderWidth: 2,
            pointRadius: 0,
            pointHoverRadius: 4,
            pointHitRadius: 8,
            lineTension: 0.3,
            fill: fill
        });
    }

    return { labels: dashboardMainChartData.labels, datasets: datasets };
}

function getLineChartOptions(animate, valueFormatter, stacked, maxTicks) {
    return {
        maintainAspectRatio: false,
        animation: { duration: animate ? 400 : 0 },
        hover: { mode: "index", intersect: false },
        layout: { padding: { top: 4 } },
        tooltips: {
            mode: "index",
            intersect: false,
            callbacks: {
                label: function (tooltipItem, chartData) {
                    return " " + chartData.datasets[tooltipItem.datasetIndex].label + ": " + valueFormatter(tooltipItem.yLabel);
                }
            }
        },
        legend: { position: "bottom", labels: { padding: 18 } },
        scales: {
            xAxes: [{ gridLines: { display: false }, ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 12 } }],
            yAxes: [{ stacked: stacked, gridLines: {}, ticks: { beginAtZero: true, maxTicksLimit: maxTicks, callback: function (value) { return valueFormatter(value); } } }]
        }
    };
}

function renderMainChart(animate) {
    var view = $("input[name=rdMainChartView]:checked").val() || "overview";
    var viewInfo = dashboardChartViews[view] || dashboardChartViews.overview;
    var data = buildMainChartData(view);

    if (window.chartDashboardMain == null) {
        window.chartDashboardMain = new Chart(document.getElementById("canvasDashboardMain").getContext("2d"), {
            type: "line",
            data: data,
            options: getLineChartOptions(animate, function (value) { return formatNumber(value); }, viewInfo.stacked, 6)
        });
    }
    else {
        window.chartDashboardMain.data = data;
        window.chartDashboardMain.options.scales.yAxes[0].stacked = viewInfo.stacked;
        window.chartDashboardMain.options.animation.duration = animate ? 400 : 0;
    }

    window.chartDashboardMain.options.legend.display = data.datasets.length > 1;

    applyDashboardChartTheme(window.chartDashboardMain);
    window.chartDashboardMain.update();
}

function renderResponseTimeChart(animate) {
    var panel = $("#divDashboardResponseTimePanel");

    if ((dashboardResponseTimeData == null) || (dashboardMainChartData == null)) {
        panel.hide();
        return;
    }

    panel.show();

    var average = getThemeValue("--c1");
    var p95 = getThemeValue("--c2");

    var data = {
        labels: dashboardMainChartData.labels,
        datasets: [
            { label: "Durchschnitt", data: dashboardResponseTimeData.average, borderColor: average, backgroundColor: withAlpha(average, 0.08), pointBackgroundColor: average, pointBorderColor: average, borderWidth: 2, pointRadius: 0, pointHoverRadius: 4, pointHitRadius: 8, lineTension: 0.3, fill: "origin", spanGaps: true },
            { label: "95. Perzentil", data: dashboardResponseTimeData.p95, borderColor: p95, backgroundColor: p95, pointBackgroundColor: p95, pointBorderColor: p95, borderWidth: 2, borderDash: [5, 4], pointRadius: 0, pointHoverRadius: 4, pointHitRadius: 8, lineTension: 0.3, fill: false, spanGaps: true }
        ]
    };

    if (window.chartDashboardResponseTime == null) {
        window.chartDashboardResponseTime = new Chart(document.getElementById("canvasDashboardResponseTime").getContext("2d"), {
            type: "line",
            data: data,
            options: getLineChartOptions(animate, formatMilliseconds, false, 5)
        });
    }
    else {
        window.chartDashboardResponseTime.data = data;
        window.chartDashboardResponseTime.options.animation.duration = animate ? 400 : 0;
    }

    applyDashboardChartTheme(window.chartDashboardResponseTime);
    window.chartDashboardResponseTime.update();
}

function renderDoughnutChart(chartName, canvasId, labels, values, colors, animate) {
    var total = 0;

    for (var i = 0; i < values.length; i++)
        total += values[i];

    if (total == 0) {
        labels = [];
        values = [];
        colors = [];
    }

    var data = {
        labels: labels,
        datasets: [{ data: values, backgroundColor: colors, hoverBackgroundColor: colors, borderWidth: 2 }]
    };

    if (window[chartName] == null) {
        window[chartName] = new Chart(document.getElementById(canvasId).getContext("2d"), {
            type: "doughnut",
            data: data,
            options: {
                maintainAspectRatio: false,
                cutoutPercentage: 66,
                animation: { duration: animate ? 400 : 0 },
                legend: { position: "right", labels: { padding: 12 } },
                tooltips: {
                    callbacks: {
                        label: function (tooltipItem, chartData) {
                            var dataset = chartData.datasets[tooltipItem.datasetIndex];
                            var value = dataset.data[tooltipItem.index];
                            var sum = 0;

                            for (var i = 0; i < dataset.data.length; i++)
                                sum += dataset.data[i];

                            return " " + chartData.labels[tooltipItem.index] + ": " + formatNumber(value) + " (" + formatPercent(value, sum) + ")";
                        }
                    }
                }
            }
        });
    }
    else {
        window[chartName].data = data;
        window[chartName].options.animation.duration = animate ? 400 : 0;
    }

    applyDashboardChartTheme(window[chartName]);
    window[chartName].update();

    var container = $("#" + canvasId).parent();
    var overlay = container.children(".chart-empty");

    if (total > 0) {
        overlay.remove();
    }
    else if (overlay.length == 0) {
        container.append("<div class=\"chart-empty\">Keine Daten im gewählten Zeitraum</div>");
    }
}

function renderDashboardDoughnuts(response, animate) {
    {
        var chartData = response.queryResponseChartData;
        var order = dashboardChartViews.sources.series;
        var entries = [];

        for (var i = 0; i < chartData.labels.length; i++)
            entries.push({ key: chartData.labels[i], value: chartData.datasets[0].data[i] });

        entries.sort(function (a, b) {
            var ia = order.indexOf(a.key);
            var ib = order.indexOf(b.key);
            return (ia < 0 ? order.length : ia) - (ib < 0 ? order.length : ib);
        });

        var labels = [];
        var values = [];
        var colors = [];

        for (var j = 0; j < entries.length; j++) {
            var info = getDashboardSeriesInfo(entries[j].key);
            labels.push(info.label);
            values.push(entries[j].value);
            colors.push(info.color);
        }

        renderDoughnutChart("chartDashboardPie", "canvasDashboardPie", labels, values, colors, animate);
    }

    {
        var chartData2 = response.queryTypeChartData;
        var labels2 = [];
        var colors2 = [];

        for (var k = 0; k < chartData2.labels.length; k++) {
            var isOthers = chartData2.labels[k] === "Others";
            labels2.push(isOthers ? "Andere" : chartData2.labels[k]);
            colors2.push(getThemeValue(isOthers || (k >= dashboardCategoricalTokens.length) ? "--c-neutral" : dashboardCategoricalTokens[k]));
        }

        renderDoughnutChart("chartDashboardPie2", "canvasDashboardPie2", labels2, chartData2.datasets[0].data, colors2, animate);
    }

    {
        var chartData3 = response.protocolTypeChartData;
        var labels3 = [];
        var colors3 = [];

        for (var m = 0; m < chartData3.labels.length; m++) {
            var protocolLabel = dashboardProtocolLabels[chartData3.labels[m]];
            labels3.push(protocolLabel == null ? chartData3.labels[m] : protocolLabel);
            colors3.push(getThemeValue(m < dashboardCategoricalTokens.length ? dashboardCategoricalTokens[m] : "--c-neutral"));
        }

        renderDoughnutChart("chartDashboardPie3", "canvasDashboardPie3", labels3, chartData3.datasets[0].data, colors3, animate);
    }
}

function getStatsRowHtml(seriesKey, value, total, showShare) {
    var share = total ? (value * 100 / total) : 0;
    var html = "<tr><td class=\"stats-label\">" + htmlEncode(getDashboardSeriesInfo(seriesKey).label);

    if (showShare)
        html += "<div class=\"share-bar\"><div style=\"width: " + Math.min(100, share).toFixed(2) + "%;\"></div></div>";

    html += "</td><td class=\"stats-number\">" + formatNumber(value) + "</td><td class=\"stats-share\">" + (showShare ? formatPercent(value, total) : "") + "</td></tr>";

    return html;
}

function renderDashboardStatsTables(stats) {
    var total = stats.totalQueries;

    $("#tableStatsQueries").html(
        getStatsRowHtml("Total", total, total, false) +
        getStatsRowHtml("Clients", stats.totalClients, total, false) +
        getStatsRowHtml("Dropped", stats.totalDropped, total, true)
    );

    $("#tableStatsResponses").html(
        getStatsRowHtml("No Error", stats.totalNoError, total, true) +
        getStatsRowHtml("NX Domain", stats.totalNxDomain, total, true) +
        getStatsRowHtml("Refused", stats.totalRefused, total, true) +
        getStatsRowHtml("Server Failure", stats.totalServerFailure, total, true)
    );

    $("#tableStatsSources").html(
        getStatsRowHtml("Cached", stats.totalCached, total, true) +
        getStatsRowHtml("Recursive", stats.totalRecursive, total, true) +
        getStatsRowHtml("Blocked", stats.totalBlocked, total, true) +
        getStatsRowHtml("Authoritative", stats.totalAuthoritative, total, true)
    );
}

var dashboardKpiStates = {
    good: { icon: "fa-check", text: "Normal" },
    warn: { icon: "fa-exclamation", text: "Erhöht" },
    bad: { icon: "fa-times", text: "Kritisch" }
};

function setKpi(id, value, sub, level, stateText) {
    var state = $("#" + id + "State");
    state.removeClass("state-good state-warn state-bad");

    if (level != null) {
        var info = dashboardKpiStates[level];
        state.addClass("state-" + level).html("<span class=\"fa " + info.icon + "\" aria-hidden=\"true\"></span>" + htmlEncode(stateText == null ? info.text : stateText));
    }
    else {
        state.html("");
    }

    $("#" + id).text(value);
    $("#" + id + "Sub").text(sub == null ? "" : sub);
}

function renderSparkline(id, values) {
    var svg = document.getElementById(id + "Spark");
    if (svg == null)
        return;

    if (values == null) {
        svg.style.visibility = "hidden";
        return;
    }

    svg.style.visibility = "";

    var max = 0;
    var count = 0;

    for (var i = 0; i < values.length; i++) {
        if ((values[i] != null) && !isNaN(values[i])) {
            count++;

            if (values[i] > max)
                max = values[i];
        }
    }

    if ((count < 2) || (max <= 0)) {
        svg.innerHTML = "<line class=\"spark-empty\" x1=\"0\" y1=\"22\" x2=\"100\" y2=\"22\"></line>";
        return;
    }

    var step = 100 / (values.length - 1);
    var line = "";
    var area = "";
    var segmentStart = null;
    var lastX = 0;

    for (var j = 0; j < values.length; j++) {
        var v = values[j];

        if ((v == null) || isNaN(v)) {
            if (segmentStart != null) {
                area += "L" + lastX.toFixed(2) + ",24L" + segmentStart.toFixed(2) + ",24Z";
                segmentStart = null;
            }

            continue;
        }

        var x = j * step;
        var y = 22 - (v / max) * 20;
        var point = x.toFixed(2) + "," + y.toFixed(2);

        if (segmentStart == null) {
            line += "M" + point;
            area += "M" + point;
            segmentStart = x;
        }
        else {
            line += "L" + point;
            area += "L" + point;
        }

        lastX = x;
    }

    if (segmentStart != null)
        area += "L" + lastX.toFixed(2) + ",24L" + segmentStart.toFixed(2) + ",24Z";

    svg.innerHTML = "<path class=\"spark-area\" d=\"" + area + "\"></path><path class=\"spark-line\" d=\"" + line + "\"></path>";
}

function getRatioSeries(numeratorKey, denominatorKeys) {
    var numerator = getMainChartSeries(numeratorKey);
    if (numerator == null)
        return null;

    var denominators = [];

    for (var i = 0; i < denominatorKeys.length; i++) {
        var series = getMainChartSeries(denominatorKeys[i]);
        if (series == null)
            return null;

        denominators.push(series);
    }

    var result = new Array(numerator.length);

    for (var j = 0; j < numerator.length; j++) {
        var sum = 0;

        for (var k = 0; k < denominators.length; k++)
            sum += denominators[k][j];

        result[j] = sum > 0 ? numerator[j] * 100 / sum : null;
    }

    return result;
}

function renderDashboardKpis(response) {
    var stats = response.stats;
    var live = response.live;
    var total = stats.totalQueries;

    var periodSeconds = getDashboardPeriodSeconds();
    var periodQps = periodSeconds > 0 ? total / periodSeconds : 0;

    setKpi("divKpiQps", formatNumber(live.queriesPerSecond, live.queriesPerSecond < 10 ? 2 : 1), "letzte 5 Minuten, Ø Zeitraum " + formatNumber(periodQps, periodQps < 10 ? 2 : 1) + "/s", null);
    renderSparkline("divKpiQps", getMainChartSeries("Total"));

    if (live.count > 0) {
        var latencyLevel = live.median > 300 ? "bad" : (live.median > 80 ? "warn" : "good");
        setKpi("divKpiLatency", formatMilliseconds(live.median), "p95 " + formatMilliseconds(live.p95) + ", p99 " + formatMilliseconds(live.p99), latencyLevel, latencyLevel === "bad" ? "Hoch" : null);
    }
    else {
        setKpi("divKpiLatency", "–", "keine Anfragen in den letzten 5 Minuten", null);
    }

    renderSparkline("divKpiLatency", dashboardResponseTimeData == null ? null : dashboardResponseTimeData.average);

    var cacheBase = stats.totalCached + stats.totalRecursive;
    var cacheRate = cacheBase > 0 ? stats.totalCached * 100 / cacheBase : 0;
    var cacheLevel = cacheBase === 0 ? null : (cacheRate < 40 ? "bad" : (cacheRate < 70 ? "warn" : "good"));
    var cacheStateText = cacheLevel === "good" ? "Gut" : (cacheLevel === "warn" ? "Mittel" : "Niedrig");
    var cacheSub = (live.count > 0) ? ("Cache Ø " + formatMilliseconds(live.cachedAverage) + ", rekursiv Ø " + formatMilliseconds(live.recursiveAverage)) : "Cache-Antworten im Verhältnis zu rekursiven";
    setKpi("divKpiCacheHit", formatNumber(cacheRate, 1) + " %", cacheSub, cacheLevel, cacheStateText);
    renderSparkline("divKpiCacheHit", getRatioSeries("Cached", ["Cached", "Recursive"]));

    var failureRate = total > 0 ? stats.totalServerFailure * 100 / total : 0;
    var failureLevel = total === 0 ? null : (failureRate > 5 ? "bad" : (failureRate > 1 ? "warn" : "good"));
    setKpi("divKpiFailure", formatNumber(failureRate, 2) + " %", formatNumber(stats.totalServerFailure) + " fehlgeschlagene Anfragen", failureLevel);
    renderSparkline("divKpiFailure", getRatioSeries("Server Failure", ["Total"]));

    setKpi("divKpiBlocked", formatPercent(stats.totalBlocked, total, 1), formatNumber(stats.totalBlocked) + " blockierte Anfragen", null);
    renderSparkline("divKpiBlocked", getRatioSeries("Blocked", ["Total"]));

    setKpi("divKpiClients", formatNumber(stats.totalClients), "im gewählten Zeitraum", null);
    renderSparkline("divKpiClients", getMainChartSeries("Clients"));
}

function renderDashboardStatus(serverStatus) {
    if (serverStatus == null) {
        $("#divDashboardStatus").html("");
        return;
    }

    var items = [];

    if (serverStatus.enableBlocking)
        items.push({ cls: "success", icon: "fa-shield", text: "Blockierung aktiv" });
    else if (serverStatus.temporaryDisableBlockingTill != null)
        items.push({ cls: "warning", icon: "fa-pause", text: "Blockierung pausiert bis " + moment(serverStatus.temporaryDisableBlockingTill).local().format("HH:mm") });
    else
        items.push({ cls: "default", icon: "fa-shield", text: "Blockierung aus" });

    items.push(serverStatus.dnssecValidation ? { cls: "success", icon: "fa-lock", text: "DNSSEC-Validierung an" } : { cls: "default", icon: "fa-unlock", text: "DNSSEC-Validierung aus" });

    if (serverStatus.ipv6Mode === "Disabled")
        items.push({ cls: "default", icon: "fa-globe", text: "IPv6 ausgehend deaktiviert" });
    else if (serverStatus.ipv6UpstreamAvailable)
        items.push({ cls: "success", icon: "fa-globe", text: "IPv6 ausgehend aktiv" });
    else
        items.push({ cls: "warning", icon: "fa-globe", text: "IPv6 ausgesetzt" + (serverStatus.ipv6UpstreamUnavailableUntil != null ? " bis " + moment(serverStatus.ipv6UpstreamUnavailableUntil).local().format("HH:mm") : "") + ", nur IPv4" });

    items.push(serverStatus.forwarding ? { cls: "info", icon: "fa-share", text: "Auflösung über Forwarder" } : { cls: "info", icon: "fa-sitemap", text: "Rekursive Auflösung ab Root" });

    items.push({ cls: "default", icon: "fa-clock-o", text: "Läuft seit " + moment.duration(serverStatus.uptimeSeconds, "seconds").humanize() });

    var html = "";

    for (var i = 0; i < items.length; i++)
        html += "<span class=\"status-chip status-" + items[i].cls + "\"><span class=\"fa " + items[i].icon + "\" aria-hidden=\"true\"></span>" + htmlEncode(items[i].text) + "</span>";

    $("#divDashboardStatus").html(html);
}

function getTopShareHtml(value, total) {
    var share = total ? (value * 100 / total) : 0;
    return "<div class=\"share-bar share-bar-thin\"><div style=\"width: " + Math.min(100, share).toFixed(2) + "%;\"></div></div>";
}

function getTopDomainName(item) {
    if (item.nameIdn != null)
        return item.nameIdn;

    return item.name === "" ? "." : item.name;
}

function getTopMenuToggleHtml(id) {
    return "<td class=\"top-menu\"><div class=\"dropdown\"><a href=\"#\" id=\"" + id + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"false\" aria-label=\"Aktionen\"><span class=\"fa fa-ellipsis-v\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
}

function renderTopClients(tbody, topClients, total, idPrefix) {
    if (topClients.length < 1) {
        tbody.html("<tr><td colspan=\"3\" class=\"text-center text-muted\">Keine Anfragen im gewählten Zeitraum</td></tr>");
        return;
    }

    var html = "";

    for (var i = 0; i < topClients.length; i++) {
        var item = topClients[i];

        html += "<tr" + (item.rateLimited ? " class=\"rate-limited\"" : "") + "><td class=\"top-name\">" + htmlEncode(item.name) + (item.rateLimited ? " <span class=\"label label-warning\">gebremst</span>" : "");

        if ((item.domain != null) && (item.domain !== ""))
            html += "<div class=\"top-sub\">" + htmlEncode(item.domain) + "</div>";

        html += getTopShareHtml(item.hits, total) + "</td><td class=\"top-hits\">" + formatNumber(item.hits) + "<div class=\"top-sub\">" + formatPercent(item.hits, total) + "</div></td>";
        html += getTopMenuToggleHtml(idPrefix + i);
        html += "<li><a href=\"#\" data-id=\"" + i + "\" onclick=\"showQueryLogs(null, " + jsArg(item.name) + "); return false;\">Abfrageprotokoll anzeigen</a></li>";
        html += "</ul></div></td></tr>";
    }

    tbody.html(html);
}

function renderTopDomains(tbody, topDomains, total, idPrefix, blocked, alertPlaceholderId) {
    if (topDomains.length < 1) {
        tbody.html("<tr><td colspan=\"3\" class=\"text-center text-muted\">" + (blocked ? "Keine blockierten Anfragen im gewählten Zeitraum" : "Keine Anfragen im gewählten Zeitraum") + "</td></tr>");
        return;
    }

    var alertArg = alertPlaceholderId == null ? "" : ", '" + alertPlaceholderId + "'";
    var html = "";

    for (var i = 0; i < topDomains.length; i++) {
        var item = topDomains[i];

        html += "<tr><td class=\"top-name\">" + htmlEncode(getTopDomainName(item)) + getTopShareHtml(item.hits, total) + "</td><td class=\"top-hits\">" + formatNumber(item.hits) + "<div class=\"top-sub\">" + formatPercent(item.hits, total) + "</div></td>";
        html += getTopMenuToggleHtml(idPrefix + i);
        html += "<li><a href=\"#\" data-id=\"" + i + "\" onclick=\"showQueryLogs(" + jsArg(item.name) + ", null); return false;\">Abfrageprotokoll anzeigen</a></li>";
        html += "<li><a href=\"#\" data-id=\"" + i + "\" onclick=\"queryDnsServer(" + jsArg(item.name) + ", null); return false;\">Mit DNS-Client abfragen</a></li>";

        if (blocked)
            html += "<li><a href=\"#\" data-id=\"" + i + "\" data-domain=\"" + htmlEncode(item.name) + "\" onclick=\"allowDomain(this, " + jsArg(idPrefix) + "" + alertArg + "); return false;\">Domain erlauben</a></li>";
        else
            html += "<li><a href=\"#\" data-id=\"" + i + "\" data-domain=\"" + htmlEncode(item.name) + "\" onclick=\"blockDomain(this, " + jsArg(idPrefix) + "" + alertArg + "); return false;\">Domain blockieren</a></li>";

        html += "</ul></div></td></tr>";
    }

    tbody.html(html);
}

function renderDashboardCharts(response, animate) {
    renderMainChart(animate);
    renderResponseTimeChart(animate);
    renderDashboardDoughnuts(response, animate);
}

function refreshDashboard(hideLoader) {
    if (!$("#mainPanelTabPaneDashboard").hasClass("active"))
        return;

    if (hideLoader == null)
        hideLoader = false;

    var query = getDashboardStatsQuery(!hideLoader);
    if (query == null)
        return;

    var divDashboardLoader = $("#divDashboardLoader");
    var divDashboard = $("#divDashboard");

    if (!hideLoader) {
        divDashboard.hide();
        divDashboardLoader.show();
    }

    HTTPRequest({
        url: "api/dashboard/stats/get?" + query,
        token: sessionData.token,
        success: function (responseJSON) {
            var response = responseJSON.response;
            var animate = !hideLoader;

            if (!hideLoader) {
                divDashboardLoader.hide();
                divDashboard.show();
            }

            dashboardLastResponse = response;

            dashboardMainChartData = {
                labels: formatDashboardLabels(response.mainChartData.labels, response.mainChartData.labelFormat),
                datasets: response.mainChartData.datasets
            };

            dashboardResponseTimeData = response.responseTimeChartData == null ? null : response.responseTimeChartData;

            renderDashboardStatus(response.serverStatus);
            renderDashboardKpis(response);
            renderDashboardStatsTables(response.stats);

            $("#divDashboardStatsZones").text(formatNumber(response.stats.zones));
            $("#divDashboardStatsCachedEntries").text(formatNumber(response.stats.cachedEntries));
            $("#divDashboardStatsAllowedZones").text(formatNumber(response.stats.allowedZones));
            $("#divDashboardStatsBlockedZones").text(formatNumber(response.stats.blockedZones));
            $("#divDashboardStatsAllowListZones").text(formatNumber(response.stats.allowListZones));
            $("#divDashboardStatsBlockListZones").text(formatNumber(response.stats.blockListZones));

            renderDashboardCharts(response, animate);

            renderTopClients($("#tableTopClients"), response.topClients, response.stats.totalQueries, "btnDashboardTopClientsRowOption");
            renderTopDomains($("#tableTopDomains"), response.topDomains, response.stats.totalQueries, "btnDashboardTopDomainsRowOption", false, null);
            renderTopDomains($("#tableTopBlockedDomains"), response.topBlockedDomains, response.stats.totalBlocked, "btnDashboardTopBlockedDomainsRowOption", true, null);

            $("#lblDashboardUpdated").text("Stand " + moment().format("HH:mm:ss"));
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divDashboardLoader,
        dontHideAlert: hideLoader
    });
}

function showTopStats(statsType, limit) {
    var query = getDashboardStatsQuery(true);
    if (query == null)
        return;

    var divTopStatsAlert = $("#divTopStatsAlert");
    var divTopStatsLoader = $("#divTopStatsLoader");

    $("#tableTopStatsClients").hide();
    $("#tableTopStatsDomains").hide();
    $("#tableTopStatsBlockedDomains").hide();
    divTopStatsLoader.show();

    switch (statsType) {
        case "TopClients":
            $("#lblTopStatsTitle").text("Top " + formatNumber(limit) + " Clients");
            break;

        case "TopDomains":
            $("#lblTopStatsTitle").text("Top " + formatNumber(limit) + " Domains");
            break;

        case "TopBlockedDomains":
            $("#lblTopStatsTitle").text("Top " + formatNumber(limit) + " blockierte Domains");
            break;
    }

    $("#modalTopStats").modal("show");

    HTTPRequest({
        url: "api/dashboard/stats/getTop?" + query + "&statsType=" + statsType + "&limit=" + limit,
        token: sessionData.token,
        success: function (responseJSON) {
            divTopStatsLoader.hide();

            var response = responseJSON.response;

            if (response.topClients != null) {
                var clientsTotal = 0;
                for (var i = 0; i < response.topClients.length; i++)
                    clientsTotal += response.topClients[i].hits;

                renderTopClients($("#tbodyTopStatsClients"), response.topClients, clientsTotal, "btnTopStatsClientsRowOption");
                $("#tfootTopStatsClients").text(response.topClients.length > 0 ? formatNumber(response.topClients.length) + " Clients" : "");
                $("#tableTopStatsClients").show();
            }
            else if (response.topDomains != null) {
                var domainsTotal = 0;
                for (var j = 0; j < response.topDomains.length; j++)
                    domainsTotal += response.topDomains[j].hits;

                renderTopDomains($("#tbodyTopStatsDomains"), response.topDomains, domainsTotal, "btnTopStatsDomainsRowOption", false, "divTopStatsAlert");
                $("#tfootTopStatsDomains").text(response.topDomains.length > 0 ? formatNumber(response.topDomains.length) + " Domains" : "");
                $("#tableTopStatsDomains").show();
            }
            else if (response.topBlockedDomains != null) {
                var blockedTotal = 0;
                for (var k = 0; k < response.topBlockedDomains.length; k++)
                    blockedTotal += response.topBlockedDomains[k].hits;

                renderTopDomains($("#tbodyTopStatsBlockedDomains"), response.topBlockedDomains, blockedTotal, "btnTopStatsBlockedDomainsRowOption", true, "divTopStatsAlert");
                $("#tfootTopStatsBlockedDomains").text(response.topBlockedDomains.length > 0 ? formatNumber(response.topBlockedDomains.length) + " Domains" : "");
                $("#tableTopStatsBlockedDomains").show();
            }

            $("#divTopStatsData").animate({ scrollTop: 0 }, "fast");
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divTopStatsLoader,
        objAlertPlaceholder: divTopStatsAlert
    });
}

$(function () {
    $("input[type=radio][name=rdStatType]").on("change", function () {
        var type = $("input[name=rdStatType]:checked").val();
        if (type === "custom") {
            $("#divCustomDayWise").show();

            if ($("#dpCustomDayWiseStart").val() === "") {
                $("#dpCustomDayWiseStart").trigger("focus");
                return;
            }

            if ($("#dpCustomDayWiseEnd").val() === "") {
                $("#dpCustomDayWiseEnd").trigger("focus");
                return;
            }
        }
        else {
            $("#divCustomDayWise").hide();
        }

        refreshDashboard();
    });

    $("#btnCustomDayWise").on("click", function () {
        refreshDashboard();
    });

    $("input[type=radio][name=rdMainChartView]").on("change", function () {
        renderMainChart(true);
    });

    $("#mainPanelTabListDashboard a").on("shown.bs.tab", function () {
        refreshDashboard(true);
    });

    if (document.fonts != null)
        document.fonts.ready.then(updateDashboardChartTheme);
});
