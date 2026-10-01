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

var dhcpSettingsData = null;
var dhcpLeasesData = null;

$(function () {
    $("#dhcpTabListStatus a").on("shown.bs.tab", function () {
        refreshDhcpStatus();
    });

    $("#dhcpTabListLeases a").on("shown.bs.tab", function () {
        refreshDhcpLeases();
    });

    $("#dhcpTabListSettings a").on("shown.bs.tab", function () {
        if (dhcpSettingsData == null)
            refreshDhcpSettings();
    });

    $("#dhcpTabListExpert a").on("shown.bs.tab", function () {
        if (dhcpSettingsData == null)
            refreshDhcpSettings();
    });


    $("#chkDhcpSimpleEnabled").on("change", updateDhcpSimpleState);
    $("input[name=rdoDhcpPriority]").on("change", updateDhcpPriorityState);
    $("#chkDhcpPingCheck").on("change", function () { $("#txtDhcpPingTimeout").prop("disabled", !$("#chkDhcpPingCheck").prop("checked")); });
    $("#chkDhcpRogueDetection").on("change", function () { $("#txtDhcpRogueInterval").prop("disabled", !$("#chkDhcpRogueDetection").prop("checked")); });
    $("#chkDhcpRegisterDns").on("change", function () { $("#txtDhcpDnsTtl").prop("disabled", !$("#chkDhcpRegisterDns").prop("checked")); });
    $("#optDhcpInterface").on("change", updateDhcpGatewayHint);
});

function canModifyDhcp() {
    return (sessionData != null) && (sessionData.info.permissions.DhcpServer != null) && sessionData.info.permissions.DhcpServer.canModify;
}

function canDeleteDhcp() {
    return (sessionData != null) && (sessionData.info.permissions.DhcpServer != null) && sessionData.info.permissions.DhcpServer.canDelete;
}

function refreshDhcpTab() {
    dhcpSettingsData = null;

    var active = $("#mainPanelTabPaneDhcp .sub-nav li.active").attr("id");

    if (active === "dhcpTabListLeases")
        refreshDhcpLeases();
    else if ((active === "dhcpTabListSettings") || (active === "dhcpTabListExpert"))
        refreshDhcpSettings();
    else
        refreshDhcpStatus();
}

function formatDhcpTime(value) {
    if (value == null)
        return "–";

    if (value === "infinite")
        return tr("unbegrenzt");

    return moment(value).local().format(tr("DD.MM.YYYY HH:mm")) + " <span class=\"text-muted\">(" + htmlEncode(moment(value).fromNow()) + ")</span>";
}

function refreshDhcpStatus() {
    var div = $("#divDhcpStatus");

    HTTPRequest({
        url: "api/dhcp/status",
        token: sessionData.token,
        success: function (responseJSON) {
            renderDhcpStatus(responseJSON.response);
        },
        error: function () {
            div.html("");
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: div
    });
}

function renderDhcpStatus(status) {
    var div = $("#divDhcpStatus");
    var html = "";
    var state;

    $("#btnDhcpProbe").toggle(canModifyDhcp());

    if (!status.enabled)
        state = "<span class=\"label label-default\">" + htmlEncode(tr("ausgeschaltet")) + "</span>";
    else if (status.errors.length > 0)
        state = "<span class=\"label label-danger\">" + htmlEncode(tr("Konfigurationsfehler")) + "</span>";
    else if (!status.serving)
        state = "<span class=\"label label-info\">" + htmlEncode(tr("bereit, antwortet nicht")) + "</span>";
    else if (status.offersPaused)
        state = "<span class=\"label label-warning\">" + htmlEncode(tr("nur Verlängerungen")) + "</span>";
    else
        state = "<span class=\"label label-success\">" + htmlEncode(tr("aktiv")) + "</span>";

    html += "<div class=\"dhcp-status-cards\">";
    html += "<div class=\"dhcp-card\"><div class=\"dhcp-card-title\">" + htmlEncode(tr("Zustand")) + "</div><div class=\"dhcp-card-value\">" + state + "</div></div>";
    html += "<div class=\"dhcp-card\"><div class=\"dhcp-card-title\">" + htmlEncode(tr("Adressen belegt")) + "</div><div class=\"dhcp-card-value\">" + formatNumber(status.poolUsed) + " / " + formatNumber(status.poolSize) + "</div></div>";
    html += "<div class=\"dhcp-card\"><div class=\"dhcp-card-title\">" + htmlEncode(tr("Aktive Leases")) + "</div><div class=\"dhcp-card-value\">" + formatNumber(status.activeLeases) + "</div></div>";

    html += "</div>";

    if (status.errors.length > 0) {
        html += "<div class=\"alert alert-danger\"><b>" + htmlEncode(tr("Die Konfiguration enthält Fehler, der DHCP-Server antwortet nicht:")) + "</b><ul>";

        for (var i = 0; i < status.errors.length; i++)
            html += "<li>" + (status.errors[i].line > 0 ? htmlEncode(tr("Zeile {0}: ", status.errors[i].line)) : "") + htmlEncode(status.errors[i].message) + "</li>";

        html += "</ul></div>";
    }

    if (status.enabled && status.offersPaused)
        html += "<div class=\"alert alert-warning\">" + htmlEncode(tr("Ein anderer DHCP-Server ist aktiv. In der Priorität Reserve verlängert dieser Server nur noch bestehende Leases.")) + "</div>";

    if (status.enabled && !status.unicastAvailable)
        html += "<div class=\"alert alert-info\">" + htmlEncode(tr("Antworten an Geräte ohne Adresse gehen per Broadcast, weil kein Rohsocket geöffnet werden kann ({0}). Das funktioniert mit fast allen Geräten; für Unicast braucht der Dienst die Berechtigung CAP_NET_RAW.", status.unicastError)) + "</div>";

    html += "<h4 class=\"dhcp-heading\">" + htmlEncode(tr("Andere DHCP-Server im Netz")) + "</h4>";

    if (status.foreignServers.length === 0) {
        var probeText = status.lastProbe == null ? tr("Noch keine Suche durchgeführt.") : tr("Keine gefunden, letzte Suche {0}.", moment(status.lastProbe).fromNow());
        html += "<p class=\"text-muted\">" + htmlEncode(probeText) + "</p>";
    }
    else {
        html += "<table class=\"table table-condensed\"><thead><tr><th>" + tr("Server") + "</th><th>" + tr("Schnittstelle") + "</th><th>" + tr("Erkannt durch") + "</th><th>" + tr("Zuletzt gesehen") + "</th><th>" + tr("Angebotene Adresse") + "</th></tr></thead><tbody>";

        for (var j = 0; j < status.foreignServers.length; j++) {
            var server = status.foreignServers[j];
            html += "<tr><td><code>" + htmlEncode(server.address) + "</code></td><td>" + htmlEncode(server.interface) + "</td><td>" + htmlEncode(server.source === "probe" ? tr("eigene Suche") : tr("Anfragen der Geräte")) + "</td><td>" + formatDhcpTime(server.lastSeen) + "</td><td>" + htmlEncode(server.offeredAddress || "–") + "</td></tr>";
        }

        html += "</tbody></table>";

        if (canModifyDhcp())
            html += "<button type=\"button\" class=\"btn btn-default btn-xs\" onclick=\"clearDhcpForeignServers(this);\">" + htmlEncode(tr("Liste leeren")) + "</button>";
    }

    if (status.lastProbeError != null)
        html += "<p class=\"text-warning\">" + htmlEncode(tr("Die Suche konnte nicht auf allen Schnittstellen senden: {0}", status.lastProbeError)) + "</p>";

    html += "<h4 class=\"dhcp-heading\">" + htmlEncode(tr("Schnittstellen")) + "</h4>";

    if (status.listeners.length === 0) {
        html += "<p class=\"text-muted\">" + htmlEncode(status.enabled ? tr("Keine passende Schnittstelle mit IPv4-Adresse gefunden.") : tr("Der DHCP-Server ist ausgeschaltet.")) + "</p>";
    }
    else {
        html += "<table class=\"table table-condensed\"><thead><tr><th>" + tr("Schnittstelle") + "</th><th>" + tr("Adressen") + "</th><th>" + tr("Status") + "</th></tr></thead><tbody>";

        for (var k = 0; k < status.listeners.length; k++) {
            var listener = status.listeners[k];
            html += "<tr><td>" + htmlEncode(listener.interface) + "</td><td>" + htmlEncode(listener.addresses.join(", ")) + "</td><td>" + (listener.listening ? "<span class=\"label label-success\">" + htmlEncode(tr("lauscht")) + "</span>" : "<span class=\"label label-danger\">" + htmlEncode(tr("Fehler")) + "</span> " + htmlEncode(listener.error || "")) + "</td></tr>";
        }

        html += "</tbody></table>";
    }

    var c = status.counters;
    html += "<h4 class=\"dhcp-heading\">" + htmlEncode(tr("Nachrichten seit dem Start")) + "</h4>";
    html += "<table class=\"table table-condensed dhcp-counters\"><tbody><tr>" +
        "<td>DISCOVER <b>" + formatNumber(c.discover) + "</b></td><td>OFFER <b>" + formatNumber(c.offer) + "</b></td><td>REQUEST <b>" + formatNumber(c.request) + "</b></td><td>ACK <b>" + formatNumber(c.ack) + "</b></td><td>NAK <b>" + formatNumber(c.nak) + "</b></td></tr><tr>" +
        "<td>DECLINE <b>" + formatNumber(c.decline) + "</b></td><td>RELEASE <b>" + formatNumber(c.release) + "</b></td><td>INFORM <b>" + formatNumber(c.inform) + "</b></td><td>" + htmlEncode(tr("Konflikte")) + " <b>" + formatNumber(c.conflicts) + "</b></td><td>" + htmlEncode(tr("Pool erschöpft")) + " <b>" + formatNumber(c.poolExhausted) + "</b></td></tr><tr>" +
        "<td>" + htmlEncode(tr("Ignoriert")) + " <b>" + formatNumber(c.ignored) + "</b></td><td>" + htmlEncode(tr("Fehlerhaft")) + " <b>" + formatNumber(c.malformed) + "</b></td><td>" + htmlEncode(tr("Gedrosselt")) + " <b>" + formatNumber(c.rateLimited + c.busy) + "</b></td><td>" + htmlEncode(tr("Empfangen")) + " <b>" + formatNumber(c.received) + "</b></td><td>" + htmlEncode(tr("Gesendet")) + " <b>" + formatNumber(c.sent) + "</b></td></tr></tbody></table>";

    div.html(html);
}

function probeDhcp(element) {
    var btn = $(element).button("loading");

    HTTPRequest({
        url: "api/dhcp/probe",
        method: "POST",
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");
            renderDhcpStatus(responseJSON.response);
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function clearDhcpForeignServers(element) {
    var btn = $(element).button("loading");

    HTTPRequest({
        url: "api/dhcp/foreign/clear",
        method: "POST",
        token: sessionData.token,
        success: function () {
            refreshDhcpStatus();
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function refreshDhcpLeases() {
    var div = $("#divDhcpLeases");

    HTTPRequest({
        url: "api/dhcp/leases/list",
        token: sessionData.token,
        success: function (responseJSON) {
            dhcpLeasesData = responseJSON.response.leases;
            renderDhcpLeases();
        },
        error: function () {
            div.html("");
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: div
    });
}

function getDhcpLeaseStateLabel(lease) {
    switch (lease.state) {
        case "bound":
            return "<span class=\"label label-success\">" + htmlEncode(tr("aktiv")) + "</span>";

        case "released":
            return "<span class=\"label label-default\">" + htmlEncode(tr("freigegeben")) + "</span>";

        case "expired":
            return "<span class=\"label label-default\">" + htmlEncode(tr("abgelaufen")) + "</span>";

        case "declined":
            return "<span class=\"label label-danger\">" + htmlEncode(tr("Konflikt")) + "</span>";

        default:
            return "<span class=\"label label-default\">" + htmlEncode(lease.state) + "</span>";
    }
}

function renderDhcpLeases() {
    var div = $("#divDhcpLeases");

    if (dhcpLeasesData == null)
        return;

    var filter = $("#txtDhcpLeaseFilter").val().trim().toLowerCase();
    var html = "";
    var shown = 0;

    for (var i = 0; i < dhcpLeasesData.length; i++) {
        var lease = dhcpLeasesData[i];

        if ((filter !== "") && ((lease.address + " " + lease.hardwareAddress + " " + lease.hostName + " " + lease.clientHostName + " " + lease.vendorClass).toLowerCase().indexOf(filter) < 0))
            continue;

        shown++;

        var actions = "";

        if ((lease.state !== "declined") && !lease.reserved && canModifyDhcp())
            actions += "<button type=\"button\" class=\"btn btn-default btn-xs\" onclick=\"reserveDhcpLease(" + jsArg(lease.address) + ", this);\">" + htmlEncode(tr("Reservieren")) + "</button> ";

        if (canDeleteDhcp())
            actions += "<button type=\"button\" class=\"btn btn-danger btn-xs\" onclick=\"deleteDhcpLease(" + jsArg(lease.address) + ", this);\">" + htmlEncode(tr("Löschen")) + "</button>";

        var name = lease.hostName;
        if ((lease.clientHostName !== "") && (lease.clientHostName !== lease.hostName))
            name += (name === "" ? "" : " ") + "<span class=\"text-muted\">(" + htmlEncode(lease.clientHostName) + ")</span>";
        else
            name = htmlEncode(name);

        html += "<tr><td><code>" + htmlEncode(lease.address) + "</code>" + (lease.reserved ? " <span class=\"label label-info\">" + htmlEncode(tr("reserviert")) + "</span>" : "") + "</td>" +
            "<td><code>" + htmlEncode(lease.hardwareAddress) + "</code></td>" +
            "<td>" + name + "</td>" +
            "<td class=\"dhcp-vendor\">" + htmlEncode(lease.vendorClass) + "</td>" +
            "<td>" + getDhcpLeaseStateLabel(lease) + "</td>" +
            "<td>" + formatDhcpTime(lease.expires) + "</td>" +
            "<td class=\"text-right\" style=\"white-space: nowrap;\">" + actions + "</td></tr>";
    }

    if (shown === 0) {
        div.html("<p class=\"text-muted\">" + htmlEncode(dhcpLeasesData.length === 0 ? tr("Noch keine Leases vergeben.") : tr("Kein Lease passt zur Suche.")) + "</p>");
        return;
    }

    div.html("<table class=\"table table-condensed dhcp-leases-table\"><thead><tr><th>" + tr("IP-Adresse") + "</th><th>" + tr("MAC-Adresse") + "</th><th>" + tr("Name") + "</th><th>" + tr("Hersteller") + "</th><th>" + tr("Status") + "</th><th>" + tr("Gültig bis") + "</th><th></th></tr></thead><tbody>" + html + "</tbody></table>");
}

function deleteDhcpLease(address, element) {
    if (!confirm(tr("Lease für {0} löschen? Die Adresse wird wieder frei; das Gerät behält sie, bis es sein Lease erneuert und eine Absage bekommt.", address)))
        return;

    var btn = $(element).button("loading");

    HTTPRequest({
        url: "api/dhcp/leases/delete",
        method: "POST",
        data: "address=" + encodeURIComponent(address),
        token: sessionData.token,
        success: function () {
            refreshDhcpLeases();
            showAlert("success", tr("Gelöscht"), tr("Das Lease für {0} wurde gelöscht.", address));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function reserveDhcpLease(address, element) {
    var btn = $(element).button("loading");

    HTTPRequest({
        url: "api/dhcp/leases/reserve",
        method: "POST",
        data: "address=" + encodeURIComponent(address),
        token: sessionData.token,
        success: function () {
            dhcpSettingsData = null;
            refreshDhcpLeases();
            showAlert("success", tr("Reserviert"), tr("{0} ist jetzt fest für dieses Gerät reserviert.", address));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function refreshDhcpSettings(onLoaded) {
    HTTPRequest({
        url: "api/dhcp/settings/get",
        token: sessionData.token,
        success: function (responseJSON) {
            dhcpSettingsData = responseJSON.response;
            loadDhcpSettings();

            if (onLoaded != null)
                onLoaded();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objAlertPlaceholder: $("#divDhcpSettingsAlert")
    });
}

function loadDhcpSettings() {
    var data = dhcpSettingsData;
    var settings = data.settings;

    var options = "<option value=\"\">" + htmlEncode(tr("automatisch")) + "</option>";
    var foundInterface = settings.interface === "";

    for (var i = 0; i < data.interfaces.length; i++) {
        var iface = data.interfaces[i];
        options += "<option value=\"" + htmlEncode(iface.name) + "\">" + htmlEncode(iface.name + " (" + iface.addresses.join(", ") + ")") + "</option>";

        if (iface.name === settings.interface)
            foundInterface = true;
    }

    if (!foundInterface)
        options += "<option value=\"" + htmlEncode(settings.interface) + "\">" + htmlEncode(settings.interface + " (" + tr("nicht vorhanden") + ")") + "</option>";

    $("#optDhcpInterface").html(options).val(settings.interface);

    $("#chkDhcpEnabled").prop("checked", settings.enabled);
    $("#chkDhcpSimpleEnabled").prop("checked", settings.simpleEnabled);
    $("#txtDhcpRangeStart").val(settings.rangeStart);
    $("#txtDhcpRangeEnd").val(settings.rangeEnd);
    $("#txtDhcpNetmask").val(settings.netmask);
    $("#txtDhcpGateway").val(settings.gateway);
    $("#txtDhcpDnsServers").val(settings.dnsServers.join(" "));
    $("#txtDhcpDomain").val(settings.domain);
    $("#txtDhcpLeaseTime").val(settings.leaseTime);
    $("#chkDhcpAuthoritative").prop("checked", settings.authoritative);

    $("#tbodyDhcpReservations").html("");
    for (var j = 0; j < settings.reservations.length; j++)
        addDhcpReservationRow(settings.reservations[j].mac, settings.reservations[j].address, settings.reservations[j].hostName);

    $("input[name=rdoDhcpPriority][value=" + settings.priority + "]").prop("checked", true);
    $("#txtDhcpResponseDelay").val(settings.responseDelayMs);
    $("#txtDhcpMinSecs").val(settings.minSecs);
    $("#chkDhcpPingCheck").prop("checked", settings.pingCheck).trigger("change");
    $("#txtDhcpPingTimeout").val(settings.pingTimeoutMs);
    $("#chkDhcpRogueDetection").prop("checked", settings.rogueDetection).trigger("change");
    $("#txtDhcpRogueInterval").val(settings.rogueProbeIntervalSeconds);
    $("#chkDhcpRegisterDns").prop("checked", settings.registerDns).trigger("change");
    $("#txtDhcpDnsTtl").val(settings.dnsTtl);

    $("#txtDhcpExpert").val(settings.expert);
    $("#preDhcpGenerated").text(data.generated === "" ? tr("(keine – einfache Einstellungen ausgeschaltet oder leer)") : data.generated);
    $("#divDhcpExpertResult").html("");

    var names = "";
    for (var k = 0; k < data.options.length; k++) {
        var option = data.options[k];
        names += "<span class=\"dhcp-option-name" + (option.managed ? " managed" : "") + "\" title=\"" + htmlEncode(option.type) + "\"><b>" + option.code + "</b> " + htmlEncode(option.name) + "</span> ";
    }

    $("#divDhcpOptionNames").html("<p><b>" + htmlEncode(tr("Optionsnamen für option:<name>")) + "</b> " + htmlEncode(tr("(ausgegraut: vom Server verwaltet)")) + "</p>" + names);

    var modify = canModifyDhcp();
    $("#dhcpTabPaneSettings :input, #dhcpTabPaneExpert textarea").prop("disabled", !modify);
    $("#btnSaveDhcpSettings, #dhcpTabPaneExpert .btn-primary").toggle(modify);
    $("#btnValidateDhcpExpert").prop("disabled", false);

    updateDhcpSimpleState();
    updateDhcpPriorityState();
    updateDhcpGatewayHint();

    if (modify) {
        $("#txtDhcpPingTimeout").prop("disabled", !settings.pingCheck);
        $("#txtDhcpRogueInterval").prop("disabled", !settings.rogueDetection);
        $("#txtDhcpDnsTtl").prop("disabled", !settings.registerDns);
    }

    if (data.errors.length > 0)
        showDhcpErrors(data.errors, $("#divDhcpSettingsAlert"));
    else
        hideAlert($("#divDhcpSettingsAlert"));
}

function updateDhcpSimpleState() {
    $(".dhcp-simple").toggleClass("settings-section-inactive", !$("#chkDhcpSimpleEnabled").prop("checked"));
}

function updateDhcpPriorityState() {
    $(".dhcp-priority-delayed").toggle($("input[name=rdoDhcpPriority]:checked").val() === "delayed");
}

function updateDhcpGatewayHint() {
    var hint = "";

    if (dhcpSettingsData != null) {
        var selected = $("#optDhcpInterface").val();

        for (var i = 0; i < dhcpSettingsData.interfaces.length; i++) {
            var iface = dhcpSettingsData.interfaces[i];

            if (((selected === "") || (selected === iface.name)) && (iface.gateway != null)) {
                hint = tr("erkannt: {0}", iface.gateway);
                break;
            }
        }
    }

    $("#lblDhcpGatewayHint").text(hint);
}

function addDhcpReservationRow(mac, address, hostName) {
    var row = "<tr><td><input type=\"text\" class=\"form-control input-sm dhcp-res-mac\" placeholder=\"aa:bb:cc:dd:ee:ff\" value=\"" + htmlEncode(mac) + "\"></td>" +
        "<td><input type=\"text\" class=\"form-control input-sm dhcp-res-ip\" placeholder=\"192.168.1.20\" value=\"" + htmlEncode(address) + "\"></td>" +
        "<td><input type=\"text\" class=\"form-control input-sm dhcp-res-name\" placeholder=\"" + htmlEncode(tr("optional")) + "\" value=\"" + htmlEncode(hostName) + "\"></td>" +
        "<td class=\"text-right\"><button type=\"button\" class=\"btn btn-default btn-sm\" onclick=\"$(this).closest('tr').remove();\" aria-label=\"" + htmlEncode(tr("Entfernen")) + "\">&times;</button></td></tr>";

    $("#tbodyDhcpReservations").append(row);
}

function collectDhcpSettings() {
    var reservations = [];

    $("#tbodyDhcpReservations tr").each(function () {
        var mac = $(this).find(".dhcp-res-mac").val().trim();
        var address = $(this).find(".dhcp-res-ip").val().trim();
        var hostName = $(this).find(".dhcp-res-name").val().trim();

        if ((mac !== "") || (address !== "") || (hostName !== ""))
            reservations.push({ mac: mac, address: address, hostName: hostName });
    });

    var dns = $("#txtDhcpDnsServers").val().trim();

    return {
        configVersion: dhcpSettingsData == null ? 0 : dhcpSettingsData.settings.configVersion,
        enabled: $("#chkDhcpEnabled").prop("checked"),
        simpleEnabled: $("#chkDhcpSimpleEnabled").prop("checked"),
        interface: $("#optDhcpInterface").val() || "",
        rangeStart: $("#txtDhcpRangeStart").val().trim(),
        rangeEnd: $("#txtDhcpRangeEnd").val().trim(),
        netmask: $("#txtDhcpNetmask").val().trim(),
        gateway: $("#txtDhcpGateway").val().trim(),
        dnsServers: dns === "" ? [] : dns.split(/[\s,]+/),
        domain: $("#txtDhcpDomain").val().trim(),
        leaseTime: $("#txtDhcpLeaseTime").val().trim(),
        authoritative: $("#chkDhcpAuthoritative").prop("checked"),
        reservations: reservations,
        expert: $("#txtDhcpExpert").val(),
        priority: $("input[name=rdoDhcpPriority]:checked").val() || "primary",
        responseDelayMs: parseInt($("#txtDhcpResponseDelay").val(), 10) || 0,
        minSecs: parseInt($("#txtDhcpMinSecs").val(), 10) || 0,
        pingCheck: $("#chkDhcpPingCheck").prop("checked"),
        pingTimeoutMs: parseInt($("#txtDhcpPingTimeout").val(), 10) || 500,
        rogueDetection: $("#chkDhcpRogueDetection").prop("checked"),
        rogueProbeIntervalSeconds: parseInt($("#txtDhcpRogueInterval").val(), 10) || 300,
        registerDns: $("#chkDhcpRegisterDns").prop("checked"),
        dnsTtl: parseInt($("#txtDhcpDnsTtl").val(), 10) || 0
    };
}

function showDhcpErrors(errors, placeholder) {
    var html = "<div class=\"alert alert-danger\"><button type=\"button\" class=\"close\" data-dismiss=\"alert\">&times;</button><strong>" + htmlEncode(tr("Fehler in der DHCP-Konfiguration")) + "</strong><ul class=\"dhcp-errors\">";

    for (var i = 0; i < errors.length; i++)
        html += "<li>" + (errors[i].line > 0 ? "<b>" + htmlEncode(tr("Zeile {0}", errors[i].line)) + "</b>: " : "") + htmlEncode(errors[i].message) + "</li>";

    html += "</ul></div>";

    placeholder.html(html);
}

function saveDhcpSettings(element) {
    if (dhcpSettingsData == null)
        return;

    var settings = collectDhcpSettings();
    var btn = $(element).button("loading");
    var placeholder = $(element).closest(".tab-pane").attr("id") === "dhcpTabPaneExpert" ? $("#divDhcpExpertResult") : $("#divDhcpSettingsAlert");

    HTTPRequest({
        url: "api/dhcp/settings/set",
        method: "POST",
        data: "settings=" + encodeURIComponent(JSON.stringify(settings)),
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");

            if (!responseJSON.response.saved) {
                showDhcpErrors(responseJSON.response.errors, placeholder);
                return;
            }

            refreshDhcpSettings(function () {
                showAlert("success", tr("Gespeichert"), tr("Die DHCP-Einstellungen wurden gespeichert."), placeholder);
            });
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            showPageLogin();
        },
        objAlertPlaceholder: placeholder
    });
}

function validateDhcpExpert(element) {
    var btn = $(element).button("loading");
    var settings = collectDhcpSettings();

    HTTPRequest({
        url: "api/dhcp/settings/validate",
        method: "POST",
        data: "settings=" + encodeURIComponent(JSON.stringify(settings)),
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");

            var response = responseJSON.response;
            $("#preDhcpGenerated").text(response.generated === "" ? tr("(keine – einfache Einstellungen ausgeschaltet oder leer)") : response.generated);

            if (response.errors.length > 0)
                showDhcpErrors(response.errors, $("#divDhcpExpertResult"));
            else
                showAlert("success", tr("Keine Fehler"), tr("Erkannt: Adressbereiche {0}, Geräteeinträge {1}, Optionen {2}.", response.ranges, response.hosts, response.options), $("#divDhcpExpertResult"));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            showPageLogin();
        },
        objAlertPlaceholder: $("#divDhcpExpertResult")
    });
}
