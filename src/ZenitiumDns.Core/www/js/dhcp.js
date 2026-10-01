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
var dhcpLeases6Data = null;
var dhcpLeaseProfiles = null;
var knownDevices = null;
var knownDevicesLoaded = 0;
var knownDevicesByAddress = {};
var knownDevicesByMac = {};

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
    $("#optDhcpInterface").on("change", function () {
        updateDhcpGatewayHint();
        updateDhcpIpv6State();
    });
    $("#optDhcpIpv6Mode").on("change", updateDhcpIpv6State);
});

function canModifyDhcp() {
    return (sessionData != null) && (sessionData.info.permissions.DhcpServer != null) && sessionData.info.permissions.DhcpServer.canModify;
}

function canViewDevices() {
    if (sessionData == null)
        return false;

    var p = sessionData.info.permissions;
    return ((p.DhcpServer != null) && p.DhcpServer.canView) || ((p.Settings != null) && p.Settings.canView);
}

function loadKnownDevices(callback, force) {
    if (!force && (knownDevices != null) && (Date.now() - knownDevicesLoaded < 60000)) {
        if (callback != null)
            callback();

        return;
    }

    if (!canViewDevices()) {
        if (callback != null)
            callback();

        return;
    }

    HTTPRequest({
        url: "api/dhcp/devices",
        token: sessionData.token,
        success: function (responseJSON) {
            knownDevices = responseJSON.response.devices;
            knownDevicesLoaded = Date.now();
            knownDevicesByAddress = {};
            knownDevicesByMac = {};

            for (var i = 0; i < knownDevices.length; i++) {
                var device = knownDevices[i];
                var addresses = device.ipv4.concat(device.ipv6);

                for (var j = 0; j < addresses.length; j++)
                    knownDevicesByAddress[addresses[j]] = device;

                if (device.mac != null)
                    knownDevicesByMac[device.mac] = device;
            }

            if (callback != null)
                callback();
        },
        error: function () {
            if (callback != null)
                callback();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objAlertPlaceholder: $("<div>")
    });
}

function getKnownDeviceLabel(device) {
    if (device == null)
        return "";

    if (device.hostName !== "")
        return device.hostName;

    return device.mac || "";
}

function assignClientProfile(identifier, profile, onDone) {
    HTTPRequest({
        url: "api/settings/clients/assign",
        method: "POST",
        data: "identifier=" + encodeURIComponent(identifier) + "&profile=" + encodeURIComponent(profile),
        token: sessionData.token,
        success: function () {
            knownDevicesLoaded = 0;

            if (onDone != null)
                onDone(true);
        },
        error: function () {
            if (onDone != null)
                onDone(false);
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function renderProfileSelect(cssClass, profiles, selected, dataAttributes) {
    var html = "<select class=\"form-control input-sm " + cssClass + "\"" + (dataAttributes || "") + ">";
    html += "<option value=\"\">" + htmlEncode(tr("Standard")) + "</option>";

    for (var i = 0; i < profiles.length; i++)
        html += "<option value=\"" + htmlEncode(profiles[i].name) + "\"" + (profiles[i].name === selected ? " selected" : "") + ">" + htmlEncode(profiles[i].name) + "</option>";

    return html + "</select>";
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

    html += renderDhcpIpv6Status(status.ipv6);

    div.html(html);
}

function describeRaFlags(managed, other) {
    if (managed)
        return tr("DHCPv6 mit Adressen (M)");

    if (other)
        return tr("DHCPv6 nur für Einstellungen (O)");

    return tr("nur SLAAC");
}

function renderDhcpIpv6Status(ipv6) {
    if (ipv6 == null)
        return "";

    var configured = (ipv6.listeners.length > 0) || (ipv6.routerAdvertisements.length > 0);

    if (!configured && (ipv6.foreignRouters.length === 0) && (ipv6.foreignServers.length === 0))
        return "";

    var html = "<h4 class=\"dhcp-heading\">IPv6</h4>";
    var i;

    if (configured) {
        html += "<div class=\"dhcp-status-cards\">";
        html += "<div class=\"dhcp-card\"><div class=\"dhcp-card-title\">" + htmlEncode(tr("Aktive DHCPv6-Leases")) + "</div><div class=\"dhcp-card-value\">" + formatNumber(ipv6.activeLeases) + "</div></div>";
        html += "<div class=\"dhcp-card\"><div class=\"dhcp-card-title\">" + htmlEncode(tr("Router Advertisements gesendet")) + "</div><div class=\"dhcp-card-value\">" + formatNumber(ipv6.counters.raSent) + "</div></div>";
        html += "</div>";
    }

    if (ipv6.routerAdvertisements.length > 0) {
        html += "<table class=\"table table-condensed\"><thead><tr><th>" + tr("Schnittstelle") + "</th><th>" + tr("Ankündigung") + "</th><th>" + tr("Präfixe") + "</th><th>" + tr("DNS-Server") + "</th><th>" + tr("Zuletzt gesendet") + "</th></tr></thead><tbody>";

        for (i = 0; i < ipv6.routerAdvertisements.length; i++) {
            var ra = ipv6.routerAdvertisements[i];

            if (!ra.active) {
                html += "<tr><td>" + htmlEncode(ra.interface) + "</td><td colspan=\"4\"><span class=\"label label-danger\">" + htmlEncode(tr("Fehler")) + "</span> " + htmlEncode(ra.error || "") + "</td></tr>";
                continue;
            }

            var prefixes = [];
            for (var p = 0; p < ra.prefixes.length; p++)
                prefixes.push("<code>" + htmlEncode(ra.prefixes[p].prefix) + "</code>" + (ra.prefixes[p].slaac ? " <span class=\"text-muted\">SLAAC</span>" : ""));

            var flags = htmlEncode(describeRaFlags(ra.managed, ra.other));

            if (ra.routerLifetime > 0)
                flags += "<br><span class=\"text-muted\">" + htmlEncode(tr("als Standard-Router")) + "</span>";

            html += "<tr><td>" + htmlEncode(ra.interface) + "</td><td>" + flags + "</td><td>" + (prefixes.length === 0 ? "–" : prefixes.join("<br>")) + "</td><td>" + htmlEncode(ra.dnsServers.join(", ")) + (ra.searchDomains.length > 0 ? "<br><span class=\"text-muted\">" + htmlEncode(ra.searchDomains.join(", ")) + "</span>" : "") + "</td><td>" + formatDhcpTime(ra.lastSent) + "</td></tr>";
        }

        html += "</tbody></table>";
    }

    var listenerErrors = [];
    for (i = 0; i < ipv6.listeners.length; i++) {
        if (!ipv6.listeners[i].listening)
            listenerErrors.push(ipv6.listeners[i].interface + ": " + (ipv6.listeners[i].error || ""));
    }

    if (listenerErrors.length > 0)
        html += "<div class=\"alert alert-warning\"><b>" + htmlEncode(tr("DHCPv6 ist auf diesen Schnittstellen nicht aktiv:")) + "</b><ul><li>" + listenerErrors.map(htmlEncode).join("</li><li>") + "</li></ul></div>";

    html += "<h5 class=\"dhcp-subheading\">" + htmlEncode(tr("Andere IPv6-Router im Netz")) + "</h5>";

    if (ipv6.foreignRouters.length === 0) {
        html += "<p class=\"text-muted\">" + htmlEncode(tr("Keine Router Advertisements anderer Geräte empfangen.")) + "</p>";
    }
    else {
        var ownDns = {};
        for (i = 0; i < ipv6.routerAdvertisements.length; i++) {
            var own = ipv6.routerAdvertisements[i].dnsServers || [];
            for (var d = 0; d < own.length; d++)
                ownDns[own[d]] = true;
        }

        var foreignDns = false;

        html += "<table class=\"table table-condensed\"><thead><tr><th>" + tr("Router") + "</th><th>" + tr("Schnittstelle") + "</th><th>" + tr("Ankündigung") + "</th><th>" + tr("Präfixe") + "</th><th>" + tr("DNS-Server") + "</th><th>" + tr("Zuletzt gesehen") + "</th></tr></thead><tbody>";

        for (i = 0; i < ipv6.foreignRouters.length; i++) {
            var router = ipv6.foreignRouters[i];

            for (var k = 0; k < router.dnsServers.length; k++) {
                if (!ownDns[router.dnsServers[k]])
                    foreignDns = true;
            }

            html += "<tr><td><code>" + htmlEncode(router.address) + "</code></td><td>" + htmlEncode(router.interface) + "</td><td>" + htmlEncode(describeRaFlags(router.managed, router.other)) + (router.routerLifetime > 0 ? "<br><span class=\"text-muted\">" + htmlEncode(tr("Standard-Router")) + "</span>" : "") + "</td><td>" + (router.prefixes.length === 0 ? "–" : router.prefixes.map(htmlEncode).join("<br>")) + "</td><td>" + (router.dnsServers.length === 0 ? "–" : router.dnsServers.map(htmlEncode).join("<br>")) + "</td><td>" + formatDhcpTime(router.lastSeen) + "</td></tr>";
        }

        html += "</tbody></table>";

        if (foreignDns)
            html += "<div class=\"alert alert-warning\">" + htmlEncode(tr("Ein anderer Router kündigt eigene DNS-Server an. Geräte können diese statt ZenitiumDNS fragen, dann greifen Filter und Gerätenamen von hier nicht. Abhilfe: im Router die DNS-Ankündigung (RDNSS) abschalten oder auf die Adresse dieses Servers setzen.")) + "</div>";
    }

    if (ipv6.foreignServers.length > 0) {
        html += "<h5 class=\"dhcp-subheading\">" + htmlEncode(tr("Andere DHCPv6-Server")) + "</h5>";
        html += "<table class=\"table table-condensed\"><thead><tr><th>" + tr("Server-DUID") + "</th><th>" + tr("Schnittstelle") + "</th><th>" + tr("Zuletzt gesehen") + "</th></tr></thead><tbody>";

        for (i = 0; i < ipv6.foreignServers.length; i++)
            html += "<tr><td><code>" + htmlEncode(ipv6.foreignServers[i].serverId) + "</code></td><td>" + htmlEncode(ipv6.foreignServers[i].interface) + "</td><td>" + formatDhcpTime(ipv6.foreignServers[i].lastSeen) + "</td></tr>";

        html += "</tbody></table>";
    }

    if (configured) {
        var c = ipv6.counters;
        html += "<table class=\"table table-condensed dhcp-counters\"><tbody><tr>" +
            "<td>SOLICIT <b>" + formatNumber(c.solicit) + "</b></td><td>ADVERTISE <b>" + formatNumber(c.advertise) + "</b></td><td>REQUEST <b>" + formatNumber(c.request) + "</b></td><td>REPLY <b>" + formatNumber(c.reply) + "</b></td><td>RENEW <b>" + formatNumber(c.renew) + "</b></td></tr><tr>" +
            "<td>REBIND <b>" + formatNumber(c.rebind) + "</b></td><td>RELEASE <b>" + formatNumber(c.release) + "</b></td><td>DECLINE <b>" + formatNumber(c.decline) + "</b></td><td>CONFIRM <b>" + formatNumber(c.confirm) + "</b></td><td>INFORMATION-REQUEST <b>" + formatNumber(c.informationRequest) + "</b></td></tr><tr>" +
            "<td>" + htmlEncode(tr("Router Solicitations")) + " <b>" + formatNumber(c.routerSolicitations) + "</b></td><td>" + htmlEncode(tr("Keine Adresse frei")) + " <b>" + formatNumber(c.noAddresses) + "</b></td><td>" + htmlEncode(tr("Über Relay")) + " <b>" + formatNumber(c.relayed) + "</b></td><td>" + htmlEncode(tr("Ignoriert")) + " <b>" + formatNumber(c.ignored) + "</b></td><td>" + htmlEncode(tr("Fehlerhaft")) + " <b>" + formatNumber(c.malformed) + "</b></td></tr></tbody></table>";
    }

    return html;
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
            dhcpLeases6Data = responseJSON.response.leases6 || [];
            dhcpLeaseProfiles = { profiles: responseJSON.response.profiles || [], canAssign: responseJSON.response.canAssignProfiles === true };
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

function getDhcpLeaseActions(lease, canReserve) {
    var actions = "";

    if (canReserve && (lease.state !== "declined") && !lease.reserved && canModifyDhcp())
        actions += "<button type=\"button\" class=\"btn btn-default btn-xs\" onclick=\"reserveDhcpLease(" + jsArg(lease.address) + ", this);\">" + htmlEncode(tr("Reservieren")) + "</button> ";

    if (canDeleteDhcp())
        actions += "<button type=\"button\" class=\"btn btn-danger btn-xs\" onclick=\"deleteDhcpLease(" + jsArg(lease.address) + ", this);\">" + htmlEncode(tr("Löschen")) + "</button>";

    return actions;
}

function getDhcpLeaseProfileCell(lease) {
    var mac = lease.hardwareAddress;
    var direct = (lease.profile != null) && (lease.profileBy === mac);
    var indirect = (lease.profile != null) && !direct ? htmlEncode(tr("{0} über {1}", lease.profile, lease.profileBy)) : "";

    if (!dhcpLeaseProfiles.canAssign || (mac === "")) {
        if (lease.profile == null)
            return "<span class=\"text-muted\">" + htmlEncode(tr("Standard")) + "</span>";

        return direct ? htmlEncode(lease.profile) : indirect;
    }

    return renderProfileSelect("dhcp-lease-profile", dhcpLeaseProfiles.profiles, direct ? lease.profile : "", " data-mac=\"" + htmlEncode(mac) + "\" onchange=\"changeDhcpLeaseProfile(this);\"") + (indirect !== "" ? "<div class=\"dhcp-profile-note\">" + indirect + "</div>" : "");
}

function changeDhcpLeaseProfile(select) {
    var element = $(select).prop("disabled", true);
    var mac = element.attr("data-mac");
    var profile = element.val();

    assignClientProfile(mac, profile, function (ok) {
        refreshDhcpLeases();

        if (ok)
            showAlert("success", tr("Profil zugewiesen"), profile === "" ? tr("{0} nutzt jetzt die Standardeinstellungen.", mac) : tr("{0} nutzt jetzt das Profil {1}, über IPv4 und IPv6.", mac, profile));
    });
}

function getDhcpLeaseClientIdNote(lease) {
    if (lease.duid != null)
        return "<div class=\"dhcp-lease-id\" title=\"" + htmlEncode(tr("Client-ID nach RFC 4361 mit derselben DUID wie bei DHCPv6")) + "\">DUID " + htmlEncode(lease.duid) + "</div>";

    if ((lease.clientId != null) && (lease.clientId !== "01:" + lease.hardwareAddress))
        return "<div class=\"dhcp-lease-id\">" + htmlEncode(tr("Client-ID {0}", lease.clientId)) + "</div>";

    return "";
}

function getDhcpLeaseName(lease) {
    var name = htmlEncode(lease.hostName);

    if ((lease.clientHostName !== "") && (lease.clientHostName !== lease.hostName))
        name += (name === "" ? "" : " ") + "<span class=\"text-muted\">(" + htmlEncode(lease.clientHostName) + ")</span>";

    return name;
}

function renderDhcpLeases() {
    var div = $("#divDhcpLeases");

    if (dhcpLeasesData == null)
        return;

    var filter = $("#txtDhcpLeaseFilter").val().trim().toLowerCase();
    var html = "";
    var html6 = "";
    var shown = 0;
    var shown6 = 0;
    var i;
    var lease;
    var profileColumn = (dhcpLeaseProfiles != null) && (dhcpLeaseProfiles.profiles.length > 0);
    var profileHeader = profileColumn ? "<th>" + tr("Profil") + "</th>" : "";

    for (i = 0; i < dhcpLeasesData.length; i++) {
        lease = dhcpLeasesData[i];

        if ((filter !== "") && ((lease.address + " " + lease.hardwareAddress + " " + lease.hostName + " " + lease.clientHostName + " " + lease.vendorClass).toLowerCase().indexOf(filter) < 0))
            continue;

        shown++;

        html += "<tr><td><code>" + htmlEncode(lease.address) + "</code>" + (lease.reserved ? " <span class=\"label label-info\">" + htmlEncode(tr("reserviert")) + "</span>" : "") + "</td>" +
            "<td><code>" + htmlEncode(lease.hardwareAddress) + "</code>" + getDhcpLeaseClientIdNote(lease) + "</td>" +
            "<td>" + getDhcpLeaseName(lease) + "</td>" +
            "<td class=\"dhcp-vendor\">" + htmlEncode(lease.vendorClass) + "</td>" +
            (profileColumn ? "<td class=\"dhcp-profile-cell\">" + getDhcpLeaseProfileCell(lease) + "</td>" : "") +
            "<td>" + getDhcpLeaseStateLabel(lease) + "</td>" +
            "<td>" + formatDhcpTime(lease.expires) + "</td>" +
            "<td class=\"text-right\" style=\"white-space: nowrap;\">" + getDhcpLeaseActions(lease, true) + "</td></tr>";
    }

    var leases6 = dhcpLeases6Data || [];

    for (i = 0; i < leases6.length; i++) {
        lease = leases6[i];

        if ((filter !== "") && ((lease.address + " " + lease.hardwareAddress + " " + lease.duid + " " + lease.hostName + " " + lease.clientHostName).toLowerCase().indexOf(filter) < 0))
            continue;

        shown6++;

        var client = lease.hardwareAddress !== "" ? "<code>" + htmlEncode(lease.hardwareAddress) + "</code>" : "<code class=\"dhcp-duid\" title=\"DUID\">" + htmlEncode(lease.duid) + "</code>";

        html6 += "<tr><td><code>" + htmlEncode(lease.address) + "</code>" + (lease.reserved ? " <span class=\"label label-info\">" + htmlEncode(tr("reserviert")) + "</span>" : "") + "</td>" +
            "<td>" + client + "</td>" +
            "<td>" + getDhcpLeaseName(lease) + "</td>" +
            "<td>" + htmlEncode(lease.interface) + "</td>" +
            (profileColumn ? "<td class=\"dhcp-profile-cell\">" + getDhcpLeaseProfileCell(lease) + "</td>" : "") +
            "<td>" + getDhcpLeaseStateLabel(lease) + "</td>" +
            "<td>" + formatDhcpTime(lease.expires) + "</td>" +
            "<td class=\"text-right\" style=\"white-space: nowrap;\">" + getDhcpLeaseActions(lease, lease.hardwareAddress !== "") + "</td></tr>";
    }

    if ((shown === 0) && (shown6 === 0)) {
        div.html("<p class=\"text-muted\">" + htmlEncode((dhcpLeasesData.length === 0) && (leases6.length === 0) ? tr("Noch keine Leases vergeben.") : tr("Kein Lease passt zur Suche.")) + "</p>");
        return;
    }

    var output = "";

    if (shown > 0)
        output += "<table class=\"table table-condensed dhcp-leases-table\"><thead><tr><th>" + tr("IP-Adresse") + "</th><th>" + tr("MAC-Adresse") + "</th><th>" + tr("Name") + "</th><th>" + tr("Hersteller") + "</th>" + profileHeader + "<th>" + tr("Status") + "</th><th>" + tr("Gültig bis") + "</th><th></th></tr></thead><tbody>" + html + "</tbody></table>";

    if (shown6 > 0)
        output += "<h4 class=\"dhcp-heading\">" + htmlEncode(tr("DHCPv6")) + "</h4><table class=\"table table-condensed dhcp-leases-table\"><thead><tr><th>" + tr("IPv6-Adresse") + "</th><th>" + tr("MAC-Adresse oder DUID") + "</th><th>" + tr("Name") + "</th><th>" + tr("Schnittstelle") + "</th>" + profileHeader + "<th>" + tr("Status") + "</th><th>" + tr("Gültig bis") + "</th><th></th></tr></thead><tbody>" + html6 + "</tbody></table>";

    div.html(output);
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
        options += "<option value=\"" + htmlEncode(iface.name) + "\">" + htmlEncode(iface.name + " (" + (iface.addresses.length > 0 ? iface.addresses.join(", ") : tr("nur IPv6")) + ")") + "</option>";

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
    $("#optDhcpIpv6Mode").val(settings.ipv6Mode || "off");
    $("#txtDhcpIpv6RangeStart").val(settings.ipv6RangeStart);
    $("#txtDhcpIpv6RangeEnd").val(settings.ipv6RangeEnd);
    $("#optDhcpIpv6Router").val(settings.ipv6Router || "auto");

    $("#tbodyDhcpReservations").html("");
    $(".dhcp-res-profile-col").toggle(getDhcpReservationProfiles().length > 0);

    for (var j = 0; j < settings.reservations.length; j++)
        addDhcpReservationRow(settings.reservations[j].mac, settings.reservations[j].address, settings.reservations[j].address6 || "", settings.reservations[j].hostName, findDhcpReservationProfile(settings.reservations[j]));

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
    onDhcpExpertLoaded();

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
    updateDhcpIpv6State();

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

function updateDhcpIpv6State() {
    var mode = $("#optDhcpIpv6Mode").val() || "off";
    var help;

    switch (mode) {
        case "slaac":
            help = tr("Geräte bilden ihre Adressen selbst und erfahren den DNS-Server per Router Advertisement (RDNSS) und DHCPv6 ohne Adressvergabe. Funktioniert mit allen Systemen, auch mit Android.");
            break;

        case "both":
            help = tr("Wie SLAAC, zusätzlich vergibt DHCPv6 Adressen aus dem Bereich, die unter dem Gerätenamen im DNS stehen. Android nutzt nur die SLAAC-Adresse.");
            break;

        case "stateful":
            help = tr("Nur DHCPv6 vergibt Adressen. Android unterstützt das nicht und bekommt von hier keine IPv6-Adresse, nur den DNS-Server.");
            break;

        default:
            help = tr("Der Server sendet keine Router Advertisements und beantwortet kein DHCPv6.");
            break;
    }

    $("#lblDhcpIpv6ModeHelp").text(help);
    $(".dhcp-ipv6-on").toggle(mode !== "off");
    $(".dhcp-ipv6-range").toggle((mode === "both") || (mode === "stateful"));

    var info = "";

    if ((mode !== "off") && (dhcpSettingsData != null)) {
        var selected = $("#optDhcpInterface").val() || "";

        if (selected === "") {
            info = "<p class=\"text-warning\">" + htmlEncode(tr("Für IPv6 oben eine Schnittstelle wählen.")) + "</p>";
        }
        else {
            var found = null;
            var list = dhcpSettingsData.interfaces6 || [];

            for (var i = 0; i < list.length; i++) {
                if (list[i].name === selected) {
                    found = list[i];
                    break;
                }
            }

            if ((found == null) || (found.prefixes.length === 0)) {
                info = "<p class=\"text-warning\">" + htmlEncode(tr("Die Schnittstelle {0} hat keine globale oder ULA-IPv6-Adresse. Ohne Präfix sendet der Server dort keine Router Advertisements; sobald eine Adresse da ist, startet er von selbst.", selected)) + "</p>";
            }
            else {
                var prefixes = [];
                for (var j = 0; j < found.prefixes.length; j++)
                    prefixes.push("<code>" + htmlEncode(found.prefixes[j]) + "</code>");

                info = "<p class=\"help-block-text\">" + htmlEncode(tr("Erkannte Präfixe:")) + " " + prefixes.join(", ") + "</p>";

                if (found.forwarding)
                    info += "<p class=\"help-block-text\">" + htmlEncode(tr("Dieser Rechner leitet IPv6 weiter; bei Automatisch kündigt er sich als Standard-Router an.")) + "</p>";
            }
        }
    }

    $("#divDhcpIpv6Prefixes").html(info);
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

function getDhcpReservationProfiles() {
    return (dhcpSettingsData != null) && (dhcpSettingsData.profiles != null) && dhcpSettingsData.canAssignProfiles ? dhcpSettingsData.profiles : [];
}

function normalizeDhcpMac(mac) {
    var value = (mac || "").trim().toLowerCase().replace(/-/g, ":");
    return /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(value) ? value : null;
}

function getDhcpReservationIdentifier(mac, address) {
    var normalized = normalizeDhcpMac(mac);

    if (normalized != null)
        return normalized;

    return (address || "").trim() !== "" ? address.trim() : null;
}

function findDhcpReservationProfile(reservation) {
    var identifier = getDhcpReservationIdentifier(reservation.mac, reservation.address);
    var profiles = getDhcpReservationProfiles();

    if (identifier == null)
        return "";

    for (var i = 0; i < profiles.length; i++) {
        if (profiles[i].identifiers.indexOf(identifier) >= 0)
            return profiles[i].name;
    }

    return "";
}

function addDhcpReservationRow(mac, address, address6, hostName, profile) {
    var row = "<tr><td><input type=\"text\" class=\"form-control input-sm dhcp-res-mac\" placeholder=\"aa:bb:cc:dd:ee:ff\" value=\"" + htmlEncode(mac) + "\"></td>" +
        "<td><input type=\"text\" class=\"form-control input-sm dhcp-res-ip\" placeholder=\"192.168.1.20\" value=\"" + htmlEncode(address) + "\"></td>" +
        "<td><input type=\"text\" class=\"form-control input-sm dhcp-res-ip6\" placeholder=\"::20\" value=\"" + htmlEncode(address6) + "\"></td>" +
        "<td><input type=\"text\" class=\"form-control input-sm dhcp-res-name\" placeholder=\"" + htmlEncode(tr("optional")) + "\" value=\"" + htmlEncode(hostName) + "\"></td>" +
        (getDhcpReservationProfiles().length > 0 ? "<td>" + renderProfileSelect("dhcp-res-profile", getDhcpReservationProfiles(), profile || "", " data-initial=\"" + htmlEncode(profile || "") + "\"") + "</td>" : "") +
        "<td class=\"text-right\"><button type=\"button\" class=\"btn btn-default btn-sm\" onclick=\"$(this).closest('tr').remove();\" aria-label=\"" + htmlEncode(tr("Entfernen")) + "\">&times;</button></td></tr>";

    $("#tbodyDhcpReservations").append(row);
}

function collectDhcpSettings() {
    var reservations = [];

    $("#tbodyDhcpReservations tr").each(function () {
        var mac = $(this).find(".dhcp-res-mac").val().trim();
        var address = $(this).find(".dhcp-res-ip").val().trim();
        var address6 = $(this).find(".dhcp-res-ip6").val().trim();
        var hostName = $(this).find(".dhcp-res-name").val().trim();

        if ((mac !== "") || (address !== "") || (address6 !== "") || (hostName !== ""))
            reservations.push({ mac: mac, address: address, address6: address6, hostName: hostName });
    });

    var dns = $("#txtDhcpDnsServers").val().trim();

    return {
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
        dnsTtl: parseInt($("#txtDhcpDnsTtl").val(), 10) || 0,
        ipv6Mode: $("#optDhcpIpv6Mode").val() || "off",
        ipv6RangeStart: $("#txtDhcpIpv6RangeStart").val().trim(),
        ipv6RangeEnd: $("#txtDhcpIpv6RangeEnd").val().trim(),
        ipv6Router: $("#optDhcpIpv6Router").val() || "auto"
    };
}

function applyDhcpReservationProfiles(onDone) {
    var changes = [];

    $("#tbodyDhcpReservations tr").each(function () {
        var select = $(this).find(".dhcp-res-profile");

        if (select.length === 0)
            return;

        var selected = select.val() || "";
        var initial = select.attr("data-initial") || "";

        if (selected === initial)
            return;

        var identifier = getDhcpReservationIdentifier($(this).find(".dhcp-res-mac").val(), $(this).find(".dhcp-res-ip").val());

        if (identifier != null)
            changes.push({ identifier: identifier, profile: selected });
    });

    var done = 0;

    function next() {
        if (changes.length === 0) {
            onDone(done);
            return;
        }

        var change = changes.shift();

        assignClientProfile(change.identifier, change.profile, function (ok) {
            if (ok)
                done++;

            next();
        });
    }

    next();
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

            applyDhcpReservationProfiles(function (assigned) {
                refreshDhcpSettings(function () {
                    showAlert("success", tr("Gespeichert"), assigned > 0 ? tr("Die DHCP-Einstellungen wurden gespeichert, {0} Profilzuordnungen geändert.", assigned) : tr("Die DHCP-Einstellungen wurden gespeichert."), placeholder);
                });
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
            applyDhcpExpertErrors(response.errors);

            if (response.errors.length > 0)
                showDhcpErrors(response.errors, $("#divDhcpExpertResult"));
            else
                showAlert("success", tr("Keine Fehler"), tr("Erkannt: Adressbereiche {0}, Geräteeinträge {1}, Optionen {2}.", response.ranges + response.ranges6, response.hosts, response.options), $("#divDhcpExpertResult"));
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
