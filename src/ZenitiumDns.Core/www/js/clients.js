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

var clientProfilesData = null;

$(function () {
    $("#filterTabListClients a").on("shown.bs.tab", function () {
        refreshClientProfiles();
    });

    $("#txtClientProfileIdentifiers").on("input", updateClientProfileUsage);

    $("#optClientProfileDevice").on("change", function () {
        var value = $("#optClientProfileDevice").val();

        if (value === "")
            return;

        var text = $("#txtClientProfileIdentifiers").val();
        var lines = text.split(/[\r\n]+/);

        if (lines.indexOf(value) < 0) {
            if ((text.length > 0) && (text.charAt(text.length - 1) !== "\n"))
                text += "\n";

            $("#txtClientProfileIdentifiers").val(text + value + "\n").trigger("input");
        }

        $("#optClientProfileDevice").val("");
    });

    $("#chkClientProfileBlockingEnabled").on("change", function () {
        var enabled = $("#chkClientProfileBlockingEnabled").prop("checked");

        $("#chkClientProfileUseDefaultLists").prop("disabled", !enabled);
        $("#txtClientProfileBlockListUrls").prop("disabled", !enabled);
        $("#optClientProfileQuickBlockList").prop("disabled", !enabled);
    });

    $("#optClientProfileQuickBlockList").on("change", function () {
        var selected = $("#optClientProfileQuickBlockList").val();

        if ((selected === "blank") || (typeof quickBlockLists === "undefined") || (quickBlockLists == null))
            return;

        for (var i = 0; i < quickBlockLists.length; i++) {
            if (quickBlockLists[i].name !== selected)
                continue;

            var existing = $("#txtClientProfileBlockListUrls").val();
            var added = existing;

            if ((added.length > 0) && (added.charAt(added.length - 1) !== "\n"))
                added += "\n";

            for (var j = 0; j < quickBlockLists[i].urls.length; j++) {
                var url = quickBlockLists[i].urls[j];

                if (existing.indexOf(url) < 0)
                    added += url + "\n";
            }

            $("#txtClientProfileBlockListUrls").val(added);
            break;
        }

        $("#optClientProfileQuickBlockList").val("blank");
    });
});

function loadClientProfileQuickBlockLists() {
    var html = "<option value=\"blank\" selected></option>";

    if ((typeof quickBlockLists !== "undefined") && (quickBlockLists != null)) {
        var currentGroup = null;

        for (var i = 0; i < quickBlockLists.length; i++) {
            var group = quickBlockLists[i].group == null ? null : quickBlockLists[i].group;

            if (group !== currentGroup) {
                if (currentGroup !== null)
                    html += "</optgroup>";

                if (group !== null)
                    html += "<optgroup label=\"" + htmlEncode(tr(group)) + "\">";

                currentGroup = group;
            }

            html += "<option value=\"" + htmlEncode(quickBlockLists[i].name) + "\">" + htmlEncode(tr(quickBlockLists[i].name)) + "</option>";
        }

        if (currentGroup !== null)
            html += "</optgroup>";
    }

    $("#optClientProfileQuickBlockList").html(html);
}

function refreshClientProfiles() {
    var div = $("#divClientProfiles");

    HTTPRequest({
        url: "api/settings/clients/list",
        token: sessionData.token,
        success: function (responseJSON) {
            clientProfilesData = responseJSON.response;
            renderClientProfiles();
            loadKnownDevices(renderClientProfiles);
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

function describeClientProfileBlocking(profile) {
    if (!profile.blockingEnabled)
        return "<span class=\"label label-danger\">" + htmlEncode(tr("Keine Blockierung")) + "</span>";

    var lists = profile.blockListUrls.length;

    if (profile.useDefaultLists) {
        if (lists === 0)
            return htmlEncode(tr("Standardlisten"));

        return htmlEncode(tr("Standardlisten + {0} eigene", lists));
    }

    if (lists === 0)
        return "<span class=\"label label-warning\">" + htmlEncode(tr("Keine Listen")) + "</span>";

    return htmlEncode(tr("Nur {0} eigene", lists));
}

function renderClientProfiles() {
    var div = $("#divClientProfiles");
    var canModify = sessionData.info.permissions.Settings.canModify;
    var profiles = clientProfilesData.profiles;

    $("#btnAddClientProfile").toggle(canModify);

    if (profiles.length === 0) {
        div.html("<p class=\"text-muted\">" + htmlEncode(tr("Noch keine Clientprofile angelegt. Ohne Profil gelten für alle Geräte die Standard-Blocklisten.")) + "</p>");
        return;
    }

    var html = "<table class=\"table table-condensed client-profiles-table\"><thead><tr><th>" + tr("Name") + "</th><th>" + tr("Kennungen") + "</th><th>" + tr("Blockierung") + "</th><th></th></tr></thead><tbody>";

    for (var i = 0; i < profiles.length; i++) {
        var profile = profiles[i];
        var identifiers = "";

        for (var j = 0; j < profile.identifiers.length; j++) {
            var identifier = profile.identifiers[j];
            var device = knownDevicesByMac[identifier] || knownDevicesByAddress[identifier];
            var deviceName = device != null ? device.hostName : "";

            identifiers += "<span class=\"client-profile-identifier\"><code>" + htmlEncode(identifier) + "</code>" + (deviceName !== "" ? " <span class=\"text-muted\">" + htmlEncode(deviceName) + "</span>" : "") + "</span> ";
        }

        if (identifiers === "")
            identifiers = "<span class=\"text-muted\">" + htmlEncode(tr("keine")) + "</span>";

        html += "<tr><td><strong>" + htmlEncode(profile.name) + "</strong></td>" +
            "<td class=\"client-profile-identifiers\">" + identifiers + "</td>" +
            "<td>" + describeClientProfileBlocking(profile) + "</td>" +
            "<td class=\"text-right\" style=\"white-space: nowrap;\">" +
            (canModify ? "<button type=\"button\" class=\"btn btn-default btn-xs\" onclick=\"showClientProfileModal(" + jsArg(profile.name) + ");\">" + tr("Bearbeiten") + "</button> " +
                "<button type=\"button\" class=\"btn btn-danger btn-xs\" onclick=\"deleteClientProfile(" + jsArg(profile.name) + ", this);\">" + tr("Löschen") + "</button>" : "") +
            "</td></tr>";
    }

    html += "</tbody></table>";
    div.html(html);
}

function findClientProfile(name) {
    if ((clientProfilesData == null) || (name == null))
        return null;

    for (var i = 0; i < clientProfilesData.profiles.length; i++) {
        if (clientProfilesData.profiles[i].name === name)
            return clientProfilesData.profiles[i];
    }

    return null;
}

function showClientProfileModal(name) {
    var profile = findClientProfile(name);

    hideAlert($("#divClientProfileAlert"));
    loadClientProfileQuickBlockLists();

    $("#lblClientProfileTitle").text(profile == null ? tr("Clientprofil hinzufügen") : tr("Clientprofil bearbeiten"));
    $("#txtClientProfileOriginalName").val(profile == null ? "" : profile.name);
    $("#txtClientProfileName").val(profile == null ? "" : profile.name);
    $("#txtClientProfileIdentifiers").val(profile == null ? "" : profile.identifiers.join("\n"));
    $("#chkClientProfileBlockingEnabled").prop("checked", profile == null ? true : profile.blockingEnabled);
    $("#chkClientProfileUseDefaultLists").prop("checked", profile == null ? true : profile.useDefaultLists);
    $("#txtClientProfileBlockListUrls").val(profile == null ? "" : profile.blockListUrls.join("\n"));
    $("#chkClientProfileBlockingEnabled").trigger("change");

    updateClientProfileUsage();
    renderClientProfileDeviceOptions();
    loadKnownDevices(renderClientProfileDeviceOptions);

    $("#modalClientProfile").modal("show");

    setTimeout(function () {
        $("#txtClientProfileName").trigger("focus");
    }, 500);
}

function renderClientProfileDeviceOptions() {
    var select = $("#optClientProfileDevice");
    var devices = knownDevices || [];

    if (devices.length === 0) {
        select.hide();
        return;
    }

    var html = "<option value=\"\">" + htmlEncode(tr("Bekanntes Gerät hinzufügen …")) + "</option>";

    for (var i = 0; i < devices.length; i++) {
        var device = devices[i];
        var value = device.mac != null ? device.mac : (device.ipv4.length > 0 ? device.ipv4[0] : (device.ipv6.length > 0 ? device.ipv6[0] : null));

        if (value == null)
            continue;

        var label = (device.hostName !== "" ? device.hostName + " – " : "") + value + (device.mac != null && device.ipv4.length > 0 ? " (" + device.ipv4.join(", ") + ")" : "") + (device.profile != null ? " · " + tr("Profil {0}", device.profile) : "");
        html += "<option value=\"" + htmlEncode(value) + "\">" + htmlEncode(label) + "</option>";
    }

    select.html(html).show();
}

function updateClientProfileUsage() {
    var div = $("#divClientProfileUsage");
    var lines = $("#txtClientProfileIdentifiers").val().split(/[\r\n,]+/);
    var clientIds = [];

    for (var i = 0; i < lines.length; i++) {
        var value = lines[i].trim().toLowerCase();

        if (/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(value))
            clientIds.push(value);
    }

    if ((clientIds.length === 0) || (clientProfilesData == null)) {
        div.html("<span class=\"text-muted\">" + htmlEncode(tr("Geräte werden über IP- oder MAC-Adresse erkannt. Mit einer ClientID erscheinen hier die Adressen für verschlüsseltes DNS.")) + "</span>");
        return;
    }

    var hostName = clientProfilesData.tlsHostName || clientProfilesData.serverDomain;
    var wildcardDomains = clientProfilesData.tlsWildcardDomains || [];
    var html = "";

    for (var j = 0; j < clientIds.length; j++) {
        var id = clientIds[j];

        if (clientProfilesData.enableDnsOverHttps) {
            var port = clientProfilesData.dnsOverHttpsPort;
            html += "<div><strong>DoH</strong> <code>https://" + htmlEncode(hostName) + (port === 443 ? "" : ":" + port) + "/dns-query/" + htmlEncode(id) + "</code></div>";
        }

        if ((clientProfilesData.enableDnsOverTls || clientProfilesData.enableDnsOverQuic) && (wildcardDomains.length > 0))
            html += "<div><strong>" + (clientProfilesData.enableDnsOverTls && clientProfilesData.enableDnsOverQuic ? "DoT/DoQ" : (clientProfilesData.enableDnsOverTls ? "DoT" : "DoQ")) + "</strong> <code>" + htmlEncode(id + "." + wildcardDomains[0]) + "</code></div>";
    }

    if (clientProfilesData.enableDnsOverTls || clientProfilesData.enableDnsOverQuic) {
        if (!clientProfilesData.hasTlsCertificate)
            html += "<div class=\"text-warning\">" + htmlEncode(tr("Für DNS-over-TLS und DNS-over-QUIC ist kein Zertifikat eingerichtet.")) + "</div>";
        else if (wildcardDomains.length === 0)
            html += "<div class=\"text-warning\">" + htmlEncode(tr("DNS-over-TLS und DNS-over-QUIC erkennen die ClientID am Servernamen und brauchen dafür ein Wildcard-Zertifikat (*.{0}). Das eingerichtete Zertifikat hat keinen Wildcard-Eintrag, deshalb funktioniert die ClientID derzeit nur über DNS-over-HTTPS.", hostName)) + "</div>";
    }

    if (html === "")
        html = "<span class=\"text-muted\">" + htmlEncode(tr("ClientIDs wirken nur über DNS-over-HTTPS, DNS-over-TLS oder DNS-over-QUIC. Diese Protokolle sind derzeit ausgeschaltet.")) + "</span>";

    div.html(html);
}

function saveClientProfile() {
    var name = $("#txtClientProfileName").val().trim();

    if (name === "") {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte einen Namen für das Profil eingeben."), $("#divClientProfileAlert"));
        $("#txtClientProfileName").trigger("focus");
        return;
    }

    var btn = $("#btnSaveClientProfile").button("loading");

    var data = "originalName=" + encodeURIComponent($("#txtClientProfileOriginalName").val()) +
        "&name=" + encodeURIComponent(name) +
        "&identifiers=" + encodeURIComponent($("#txtClientProfileIdentifiers").val()) +
        "&blockingEnabled=" + $("#chkClientProfileBlockingEnabled").prop("checked") +
        "&useDefaultLists=" + $("#chkClientProfileUseDefaultLists").prop("checked") +
        "&blockListUrls=" + encodeURIComponent($("#txtClientProfileBlockListUrls").val());

    HTTPRequest({
        url: "api/settings/clients/set",
        method: "POST",
        data: data,
        processData: false,
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");
            $("#modalClientProfile").modal("hide");

            refreshClientProfiles();
            showAlert("success", tr("Gespeichert"), tr("Clientprofil '{0}' wurde gespeichert.", name));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            showPageLogin();
        },
        objAlertPlaceholder: $("#divClientProfileAlert")
    });
}

function deleteClientProfile(name, element) {
    if (!confirm(tr("Clientprofil '{0}' löschen? Die Geräte nutzen danach wieder die Standard-Blocklisten.", name)))
        return;

    var btn = $(element).button("loading");

    HTTPRequest({
        url: "api/settings/clients/delete?name=" + encodeURIComponent(name),
        token: sessionData.token,
        success: function () {
            refreshClientProfiles();
            showAlert("success", tr("Gelöscht"), tr("Clientprofil '{0}' wurde gelöscht.", name));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}
