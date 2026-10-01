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

var dhcpExpertView = "list";
var dhcpExpertErrors = {};
var dhcpExpertGeneralErrors = [];
var dhcpExpertValidateTimer = null;
var dhcpExpertValidateSeq = 0;
var dhcpEntryEditor = null;

var DHCP_SWITCHES = [
    ["dhcp-authoritative", "Autoritativ: falsche Anfragen sofort abweisen, unbekannte Leases übernehmen"],
    ["dhcp-rapid-commit", "Rapid Commit: Adresse in zwei statt vier Nachrichten vergeben"],
    ["dhcp-sequential-ip", "Adressen der Reihe nach vergeben statt nach MAC-Adresse verteilt"],
    ["dhcp-ignore-clid", "Client-ID ignorieren, Geräte nur an der MAC-Adresse erkennen"],
    ["dhcp-no-override", "Felder file und sname nicht für lange Optionen nutzen"],
    ["bootp-dynamic", "BOOTP-Geräten auch Adressen aus dem Bereich geben"],
    ["no-ping", "Adressen vor dem Vergeben nicht anpingen"],
    ["enable-ra", "Router Advertisements für alle IPv6-Bereiche senden"]
];

var DHCP_TAG_KINDS = [
    ["dhcp-vendorclass", "Herstellerklasse (Option 60) enthält"],
    ["dhcp-userclass", "Benutzerklasse (Option 77) enthält"],
    ["dhcp-mac", "MAC-Adresse passt auf Muster"],
    ["dhcp-match", "Anfrage enthält Option"],
    ["dhcp-circuitid", "Relay: Circuit-ID ist"],
    ["dhcp-remoteid", "Relay: Remote-ID ist"],
    ["dhcp-subscrid", "Relay: Subscriber-ID ist"]
];

var DHCP_OPTION_INFO = {
    "netmask": "Netzmaske",
    "time-offset": "Zeitzonen-Versatz in Sekunden",
    "router": "Standard-Gateway",
    "time-server": "Zeitserver (RFC 868)",
    "dns-server": "DNS-Server",
    "hostname": "Hostname",
    "domain-name": "Domainname",
    "root-path": "Root-Pfad",
    "ip-forward-enable": "IP-Weiterleitung",
    "default-ttl": "Standard-TTL",
    "mtu": "MTU",
    "broadcast": "Broadcast-Adresse",
    "static-route": "Statische Routen (klassenbezogen)",
    "nis-domain": "NIS-Domain",
    "nis-server": "NIS-Server",
    "ntp-server": "NTP-Server",
    "vendor-encap": "Herstellerspezifische Daten",
    "netbios-ns": "WINS-Server",
    "netbios-nodetype": "NetBIOS-Knotentyp",
    "netbios-scope": "NetBIOS-Bereich",
    "T1": "Erneuerungszeit T1",
    "T2": "Neubindungszeit T2",
    "vendor-class": "Herstellerklasse",
    "tftp-server": "TFTP-Server",
    "bootfile-name": "Startdatei",
    "smtp-server": "SMTP-Server",
    "pop3-server": "POP3-Server",
    "client-arch": "Client-Architektur",
    "posix-timezone": "Zeitzone (POSIX)",
    "tzdb-timezone": "Zeitzone (tzdb)",
    "ipv6-only": "Nur IPv6 bevorzugen (RFC 8925)",
    "captive-portal": "Captive-Portal-URL",
    "domain-search": "Suchdomänen",
    "sip-server": "SIP-Server",
    "classless-static-route": "Klassenlose statische Routen",
    "tftp-server-address": "TFTP-Serveradressen",
    "ms-classless-static-route": "Statische Routen (Microsoft)",
    "wpad": "Proxy-Autokonfiguration (WPAD)",
    "sip-server-domain": "SIP-Server-Domains",
    "sntp-server": "SNTP-Server",
    "information-refresh-time": "Auffrischungszeit",
    "bootfile-url": "Boot-URL",
    "bootfile-param": "Boot-Parameter",
    "aftr-name": "AFTR-Name (DS-Lite)",
    "nis+-server": "NIS+-Server",
    "nis+-domain": "NIS+-Domain",
    "user-class": "Benutzerklasse",
    "vendor-opts": "Herstellerspezifische Optionen"
};

var DHCP_COMMON_OPTIONS = [3, 6, 15, 119, 42, 121, 26, 44, 66, 67, 114, 252, 100, 101, 108];
var DHCP_COMMON_OPTIONS6 = [23, 24, 56, 31, 32, 59, 64];

$(function () {
    try {
        var stored = localStorage.getItem("dhcpExpertView");

        if ((stored === "list") || (stored === "text"))
            dhcpExpertView = stored;
    }
    catch (e) {
    }

    $("#txtDhcpExpert").on("input", function () {
        updateDhcpExpertUnsaved();
        scheduleDhcpExpertValidation();
    });

    $("#divDhcpEntryForm").on("input change", ":input", function () {
        updateDhcpEntryPreview();
    });

    applyDhcpExpertView();
});

function setDhcpExpertView(view) {
    dhcpExpertView = view;

    try {
        localStorage.setItem("dhcpExpertView", view);
    }
    catch (e) {
    }

    applyDhcpExpertView();
}

function applyDhcpExpertView() {
    var list = dhcpExpertView === "list";

    $("#btnDhcpExpertViewList").toggleClass("active", list).attr("aria-pressed", list ? "true" : "false");
    $("#btnDhcpExpertViewText").toggleClass("active", !list).attr("aria-pressed", list ? "false" : "true");
    $("#divDhcpExpertList").toggle(list);
    $("#divDhcpExpertText").toggle(!list);

    if (list)
        renderDhcpExpertList();
}

function onDhcpExpertLoaded() {
    dhcpExpertErrors = {};
    dhcpExpertGeneralErrors = [];
    $("#divDhcpExpertAdd").toggle(canModifyDhcp());
    applyDhcpExpertView();
    updateDhcpExpertUnsaved();

    if ((dhcpSettingsData != null) && (dhcpSettingsData.errors.length > 0))
        applyDhcpExpertErrors(dhcpSettingsData.errors);
}

function getDhcpExpertLines() {
    var text = $("#txtDhcpExpert").val() || "";

    if (text === "")
        return [];

    var lines = text.replace(/\r/g, "").split("\n");

    if (lines[lines.length - 1] === "")
        lines.pop();

    return lines;
}

function setDhcpExpertLines(lines) {
    while ((lines.length > 0) && (lines[lines.length - 1].trim() === ""))
        lines.pop();

    $("#txtDhcpExpert").val(lines.length === 0 ? "" : lines.join("\n") + "\n");
    dhcpExpertErrors = {};
    renderDhcpExpertList();
    updateDhcpExpertUnsaved();
    scheduleDhcpExpertValidation();
}

function updateDhcpExpertUnsaved() {
    var saved = (dhcpSettingsData == null) ? "" : (dhcpSettingsData.settings.expert || "");
    var current = $("#txtDhcpExpert").val() || "";

    $("#lblDhcpExpertUnsaved").toggle(saved.replace(/\s+$/, "") !== current.replace(/\s+$/, ""));
}

function scheduleDhcpExpertValidation() {
    if (dhcpExpertValidateTimer != null)
        clearTimeout(dhcpExpertValidateTimer);

    dhcpExpertValidateTimer = setTimeout(function () {
        dhcpExpertValidateTimer = null;
        runDhcpExpertValidation();
    }, 700);
}

function runDhcpExpertValidation() {
    if ((dhcpSettingsData == null) || (sessionData == null))
        return;

    var seq = ++dhcpExpertValidateSeq;

    HTTPRequest({
        url: "api/dhcp/settings/validate",
        method: "POST",
        data: "settings=" + encodeURIComponent(JSON.stringify(collectDhcpSettings())),
        token: sessionData.token,
        success: function (responseJSON) {
            if (seq !== dhcpExpertValidateSeq)
                return;

            applyDhcpExpertErrors(responseJSON.response.errors);
        },
        error: function () {
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function applyDhcpExpertErrors(errors) {
    dhcpExpertErrors = {};
    dhcpExpertGeneralErrors = [];

    for (var i = 0; i < errors.length; i++) {
        if (errors[i].line > 0) {
            if (dhcpExpertErrors[errors[i].line] == null)
                dhcpExpertErrors[errors[i].line] = [];

            dhcpExpertErrors[errors[i].line].push(errors[i].message);
        }
        else {
            dhcpExpertGeneralErrors.push(errors[i].message);
        }
    }

    if (dhcpExpertView === "list")
        renderDhcpExpertList();
}

function stripDhcpComment(line) {
    var inQuotes = false;

    for (var i = 0; i < line.length; i++) {
        var c = line.charAt(i);

        if (c === "\"")
            inQuotes = !inQuotes;
        else if ((c === "#") && !inQuotes && ((i === 0) || /\s/.test(line.charAt(i - 1))))
            return line.substring(0, i);
    }

    return line;
}

function tokenizeDhcpValue(value) {
    var tokens = [];
    var current = "";
    var quoted = false;
    var inQuotes = false;

    for (var i = 0; i < value.length; i++) {
        var c = value.charAt(i);

        if (inQuotes) {
            if ((c === "\\") && (i + 1 < value.length) && ((value.charAt(i + 1) === "\"") || (value.charAt(i + 1) === "\\"))) {
                current += value.charAt(++i);
                continue;
            }

            if (c === "\"") {
                inQuotes = false;
                continue;
            }

            current += c;
            continue;
        }

        if (c === "\"") {
            inQuotes = true;
            quoted = true;
            continue;
        }

        if (c === ",") {
            tokens.push({ text: quoted ? current : current.trim(), quoted: quoted });
            current = "";
            quoted = false;
            continue;
        }

        current += c;
    }

    tokens.push({ text: quoted ? current : current.trim(), quoted: quoted });
    return tokens;
}

function quoteDhcpText(value) {
    return "\"" + value.replace(/\\/g, "\\\\").replace(/"/g, "\\\"") + "\"";
}

function isDhcpIPv4(text) {
    var parts = text.split(".");

    if (parts.length !== 4)
        return false;

    for (var i = 0; i < 4; i++) {
        if (!/^\d{1,3}$/.test(parts[i]) || (parseInt(parts[i], 10) > 255))
            return false;
    }

    return true;
}

function isDhcpMac(text) {
    return /^(\d+-)?([0-9a-f*]{1,2}[:-]){1,19}[0-9a-f*]{1,2}$/i.test(text) && (text.indexOf(":") >= 0 || text.indexOf("-") >= 0) && !isDhcpIPv4(text);
}

function looksLikeDhcpLeaseTime(text) {
    return /^(infinite|\d+[smhdw]?)$/i.test(text);
}

function readDhcpTagTokens(tokens, start, result) {
    var i = start;

    while (i < tokens.length) {
        var t = tokens[i];

        if (t.quoted)
            break;

        var lower = t.text.toLowerCase();

        if (lower.indexOf("tag:") === 0)
            result.conditions.push(t.text.substring(4));
        else if (lower.indexOf("set:") === 0)
            result.setTags.push(t.text.substring(4));
        else if (lower.indexOf("net:") === 0)
            result.setTags.push(t.text.substring(4));
        else
            break;

        i++;
    }

    return i;
}

function parseDhcpLine(raw) {
    var result = { raw: raw, kind: "raw", key: "", value: "", tokens: [], conditions: [], setTags: [] };
    var trimmed = raw.trim();

    if (trimmed === "") {
        result.kind = "blank";
        return result;
    }

    if (trimmed.charAt(0) === "#") {
        result.kind = "comment";
        result.comment = trimmed.substring(1).trim();
        return result;
    }

    var text = stripDhcpComment(raw).trim();
    var eq = text.indexOf("=");

    if (eq < 0) {
        result.key = text.toLowerCase();
    }
    else {
        result.key = text.substring(0, eq).trim().toLowerCase();
        result.value = text.substring(eq + 1).trim();
    }

    if (result.key.indexOf("--") === 0)
        result.key = result.key.substring(2);

    result.tokens = result.value === "" ? [] : tokenizeDhcpValue(result.value);

    var tokens = result.tokens;
    var i;

    switch (result.key) {
        case "dhcp-range":
            i = readDhcpTagTokens(tokens, 0, result);

            if (i >= tokens.length)
                return result;

            result.start = tokens[i].text;
            i++;

            if (result.start.indexOf(":") >= 0) {
                result.kind = "range6";
                result.prefixLength = "";
                result.mode = "";
                result.offLink = false;

                if ((i < tokens.length) && (tokens[i].text.toLowerCase() === "static")) {
                    result.mode = "static";
                    i++;
                }
                else if ((i < tokens.length) && (tokens[i].text.indexOf(":") >= 0) && (tokens[i].text.toLowerCase().indexOf("constructor:") !== 0)) {
                    result.end = tokens[i].text;
                    i++;
                }

                for (; i < tokens.length; i++) {
                    var tv = tokens[i].text;
                    var tl = tv.toLowerCase();

                    if (tl.indexOf("constructor:") === 0)
                        result.ctorIface = tv.substring(12);
                    else if ((tl === "ra-only") || (tl === "ra-stateless") || (tl === "slaac") || (tl === "ra-names"))
                        result.mode = tl === "ra-names" ? "slaac" : tl;
                    else if (tl === "off-link")
                        result.offLink = true;
                    else if (tl === "ra-advrouter")
                        continue;
                    else if (/^\d{1,3}$/.test(tv) && (result.prefixLength === ""))
                        result.prefixLength = tv;
                    else if (looksLikeDhcpLeaseTime(tv))
                        result.lease = tv;
                    else
                        result.unknown = true;
                }

                return result;
            }

            result.kind = "range4";

            if ((i < tokens.length) && (tokens[i].text.toLowerCase() === "static")) {
                result.staticOnly = true;
                i++;
            }
            else if ((i < tokens.length) && isDhcpIPv4(tokens[i].text)) {
                result.end = tokens[i].text;
                i++;
            }

            if ((i < tokens.length) && isDhcpIPv4(tokens[i].text)) {
                result.netmask = tokens[i].text;
                i++;

                if ((i < tokens.length) && isDhcpIPv4(tokens[i].text)) {
                    result.broadcast = tokens[i].text;
                    i++;
                }
            }

            if ((i < tokens.length) && looksLikeDhcpLeaseTime(tokens[i].text)) {
                result.lease = tokens[i].text;
                i++;
            }

            if (i < tokens.length)
                result.unknown = true;

            return result;

        case "dhcp-host":
            result.kind = "host";
            result.macs = [];
            result.ids = [];

            for (i = 0; i < tokens.length; i++) {
                var t = tokens[i];
                var v = t.text;
                var l = v.toLowerCase();

                if (v === "")
                    continue;

                if (!t.quoted && (l.indexOf("set:") === 0 || l.indexOf("net:") === 0))
                    result.setTags.push(v.substring(4));
                else if (!t.quoted && l.indexOf("tag:") === 0)
                    result.conditions.push(v.substring(4));
                else if (!t.quoted && l.indexOf("id:") === 0)
                    result.ids.push(v.substring(3));
                else if (!t.quoted && l === "ignore")
                    result.ignore = true;
                else if (!t.quoted && v.charAt(0) === "[")
                    result.ipv6 = v.replace(/^\[|\]$/g, "");
                else if (!t.quoted && isDhcpIPv4(v))
                    result.ipv4 = v;
                else if (!t.quoted && isDhcpMac(v))
                    result.macs.push(v);
                else if (!t.quoted && looksLikeDhcpLeaseTime(v) && /\d/.test(v.charAt(0)) || (l === "infinite"))
                    result.lease = v;
                else if (result.name == null)
                    result.name = v;
                else
                    result.unknown = true;
            }

            return result;

        case "dhcp-option":
        case "dhcp-option-force":
            result.kind = "option";
            result.force = result.key === "dhcp-option-force";
            i = readDhcpTagTokens(tokens, 0, result);

            while (i < tokens.length) {
                var ol = tokens[i].text.toLowerCase();

                if (!tokens[i].quoted && ((ol.indexOf("encap:") === 0) || (ol.indexOf("vi-encap:") === 0) || (ol.indexOf("vendor:") === 0))) {
                    result.advanced = true;
                    i++;
                    continue;
                }

                break;
            }

            if (i >= tokens.length)
                return result;

            var spec = tokens[i].text.trim();
            i++;

            if (spec.toLowerCase().indexOf("option6:") === 0) {
                result.kind = "option6";
                result.optionName = spec.substring(8);
            }
            else if (spec.toLowerCase().indexOf("option:") === 0) {
                result.optionName = spec.substring(7);
            }
            else {
                result.optionName = spec;
            }

            result.values = [];
            result.anyQuoted = false;

            for (; i < tokens.length; i++) {
                result.values.push(tokens[i].text);
                result.anyQuoted = result.anyQuoted || tokens[i].quoted;
            }

            return result;

        case "dhcp-vendorclass":
        case "dhcp-userclass":
        case "dhcp-mac":
        case "dhcp-match":
        case "dhcp-circuitid":
        case "dhcp-remoteid":
        case "dhcp-subscrid":
            result.kind = "tag";
            i = readDhcpTagTokens(tokens, 0, result);

            if ((result.key === "dhcp-vendorclass") && (i < tokens.length) && (tokens[i].text.toLowerCase().indexOf("enterprise:") === 0)) {
                result.enterprise = tokens[i].text.substring(11);
                i++;
            }

            if (result.key === "dhcp-match") {
                if (i < tokens.length) {
                    result.matchOption = tokens[i].text;
                    i++;
                }
            }

            if (i < tokens.length) {
                result.matchValue = tokens[i].text;
                i++;
            }

            if (i < tokens.length)
                result.unknown = true;

            return result;

        case "dhcp-ignore":
        case "dhcp-ignore-names":
        case "dhcp-generate-names":
        case "dhcp-broadcast":
            result.kind = result.key === "dhcp-ignore" ? "ignore" : "taglist";
            readDhcpTagTokens(tokens, 0, result);
            return result;

        case "dhcp-boot":
            result.kind = "boot";
            i = readDhcpTagTokens(tokens, 0, result);
            result.file = i < tokens.length ? tokens[i].text : "";
            result.serverName = i + 1 < tokens.length ? tokens[i + 1].text : "";
            result.serverAddress = i + 2 < tokens.length ? tokens[i + 2].text : "";

            if (i + 3 < tokens.length)
                result.unknown = true;

            return result;

        case "domain":
            result.kind = "domain";
            result.domain = tokens.length > 0 ? tokens[0].text : "";
            result.local = false;
            result.network = "";

            for (i = 1; i < tokens.length; i++) {
                if (tokens[i].text.toLowerCase() === "local")
                    result.local = true;
                else
                    result.network = result.network === "" ? tokens[i].text : result.network + "," + tokens[i].text;
            }

            return result;

        case "ra-param":
            result.kind = "ra";
            result.iface = tokens.length > 0 ? tokens[0].text : "";
            result.mtu = "";
            result.preference = "";
            result.interval = "";
            result.lifetime = "";
            i = 1;

            if ((i < tokens.length) && (tokens[i].text.toLowerCase().indexOf("mtu:") === 0)) {
                result.mtu = tokens[i].text.substring(4);
                i++;
            }

            if ((i < tokens.length) && ((tokens[i].text.toLowerCase() === "high") || (tokens[i].text.toLowerCase() === "low"))) {
                result.preference = tokens[i].text.toLowerCase();
                i++;
            }

            if (i < tokens.length) {
                result.interval = tokens[i].text;
                i++;
            }

            if (i < tokens.length) {
                result.lifetime = tokens[i].text;
                i++;
            }

            return result;

        case "dhcp-lease-max":
        case "interface":
        case "except-interface":
            result.kind = "switch";
            return result;

        default:
            for (var s = 0; s < DHCP_SWITCHES.length; s++) {
                if (DHCP_SWITCHES[s][0] === result.key) {
                    result.kind = "switch";
                    return result;
                }
            }

            return result;
    }
}

function formatDhcpTags(conditions) {
    var parts = [];

    for (var i = 0; i < conditions.length; i++) {
        var tag = conditions[i];

        if (tag.charAt(0) === "!")
            parts.push(tr("nicht {0}", tag.substring(1)));
        else
            parts.push(tag);
    }

    return parts.join(", ");
}

function getDhcpOptionDefinition(name, v6) {
    if (dhcpSettingsData == null)
        return null;

    var list = v6 ? (dhcpSettingsData.options6 || []) : (dhcpSettingsData.options || []);
    var lower = String(name).toLowerCase();

    for (var i = 0; i < list.length; i++) {
        if ((list[i].name.toLowerCase() === lower) || (String(list[i].code) === lower))
            return list[i];
    }

    return null;
}

function describeDhcpOptionName(def, fallback) {
    if (def == null)
        return tr("Option {0}", fallback);

    var info = DHCP_OPTION_INFO[def.name];
    return (info != null ? tr(info) + " " : "") + "(" + def.name + ", " + def.code + ")";
}

function formatDhcpOptionValues(values) {
    var shown = [];

    for (var i = 0; i < values.length; i++) {
        var v = values[i];

        if ((v === "0.0.0.0") || (v === "[::]") || (v === "::"))
            shown.push(tr("dieser Server"));
        else
            shown.push(v);
    }

    return shown.join(", ");
}

function describeDhcpLine(p) {
    var title;
    var details = [];
    var badge;
    var e = htmlEncode;

    switch (p.kind) {
        case "comment":
            return { badge: tr("Kommentar"), title: e(p.comment), details: "" };

        case "range4":
            badge = "IPv4";
            title = p.staticOnly ? e(tr("Nur reservierte Adressen im Netz von {0}", p.start)) : e(tr("Adressbereich {0} bis {1}", p.start, p.end || "?"));

            if (p.netmask)
                details.push(tr("Netzmaske {0}", p.netmask));

            if (p.lease)
                details.push(tr("Lease {0}", p.lease));

            break;

        case "range6":
            badge = "IPv6";

            var modes = {
                "": tr("DHCPv6-Adressen"),
                "slaac": tr("SLAAC und DHCPv6-Adressen"),
                "ra-stateless": tr("SLAAC, DNS per DHCPv6"),
                "ra-only": tr("nur SLAAC"),
                "static": tr("nur reservierte Adressen")
            };

            if ((p.mode === "ra-only") || (p.mode === "ra-stateless"))
                title = p.ctorIface ? e(tr("Präfixe von {0}", p.ctorIface)) : e(tr("Präfix von {0}", p.start));
            else
                title = e(tr("IPv6-Bereich {0} bis {1}", p.start, p.end || p.start)) + (p.ctorIface ? " " + e(tr("auf {0}", p.ctorIface)) : "");

            details.push(modes[p.mode] || p.mode);

            if (p.prefixLength)
                details.push("/" + p.prefixLength);

            if (p.offLink)
                details.push(tr("nicht im Netz (off-link)"));

            if (p.lease)
                details.push(tr("Lease {0}", p.lease));

            break;

        case "host":
            badge = tr("Gerät");
            var who = p.macs.concat(p.ids.map(function (id) { return "id:" + id; }));

            if (p.ignore) {
                title = e(tr("{0} nicht beantworten", who.length > 0 ? who.join(", ") : (p.name || "?")));
            }
            else {
                var targets = [];

                if (p.ipv4)
                    targets.push(p.ipv4);

                if (p.ipv6)
                    targets.push(p.ipv6);

                title = e(who.length > 0 ? who.join(", ") : tr("Gerät mit Namen {0}", p.name || "?")) + (targets.length > 0 ? " → " + e(targets.join(", ")) : "");

                if (p.name && (who.length > 0))
                    details.push(tr("Name {0}", p.name));
            }

            if (p.lease)
                details.push(tr("Lease {0}", p.lease));

            break;

        case "option":
        case "option6":
            badge = p.kind === "option6" ? tr("Option v6") : tr("Option");
            var def = getDhcpOptionDefinition(p.optionName || "", p.kind === "option6");

            if ((p.values || []).length === 0 || ((p.values.length === 1) && (p.values[0] === "") && !p.anyQuoted))
                title = e(tr("{0} nicht senden", describeDhcpOptionName(def, p.optionName)));
            else
                title = e(describeDhcpOptionName(def, p.optionName)) + " = <b>" + e(formatDhcpOptionValues(p.values)) + "</b>";

            if (p.force)
                details.push(tr("immer senden"));

            if (p.advanced)
                details.push(tr("gekapselt oder herstellerspezifisch"));

            break;

        case "tag":
            badge = tr("Gruppe");
            var kindLabel = p.key;

            for (var k = 0; k < DHCP_TAG_KINDS.length; k++) {
                if (DHCP_TAG_KINDS[k][0] === p.key)
                    kindLabel = tr(DHCP_TAG_KINDS[k][1]);
            }

            title = e(tr("Tag {0}", p.setTags.join(", ") || "?")) + ": " + e(kindLabel) + " <b>" + e((p.matchOption ? p.matchOption + (p.matchValue ? " = " : "") : "") + (p.matchValue || "")) + "</b>";
            break;

        case "ignore":
            badge = tr("Regel");
            title = e(tr("Geräte mit Tag {0} nicht beantworten", formatDhcpTags(p.conditions)));
            break;

        case "taglist":
            badge = tr("Regel");
            var taglistTitles = { "dhcp-ignore-names": "Hostnamen der Geräte ignorieren", "dhcp-generate-names": "Namen aus der MAC-Adresse bilden", "dhcp-broadcast": "Antworten per Broadcast senden" };
            title = e(tr(taglistTitles[p.key]));

            if (p.conditions.length > 0)
                details.push(tr("für Tag {0}", formatDhcpTags(p.conditions)));

            break;

        case "boot":
            badge = "PXE";
            title = e(tr("Startdatei {0}", p.file || "?"));

            if (p.serverAddress || p.serverName)
                details.push(tr("Server {0}", [p.serverName, p.serverAddress].filter(function (x) { return x; }).join(" / ")));

            break;

        case "domain":
            badge = tr("Domain");
            title = e(p.domain) + (p.network ? " " + e(tr("für {0}", p.network)) : "");

            if (p.local)
                details.push(tr("unbekannte Namen beantwortet der Server selbst"));

            break;

        case "ra":
            badge = "RA";
            title = e(tr("Router Advertisements auf {0}", p.iface));

            if (p.interval)
                details.push(tr("alle {0} s", p.interval));

            if (p.lifetime !== "")
                details.push(p.lifetime === "0" ? tr("kein Standard-Router") : tr("Router-Lebensdauer {0} s", p.lifetime));

            if (p.preference)
                details.push(p.preference === "high" ? tr("hohe Priorität") : tr("niedrige Priorität"));

            if (p.mtu)
                details.push("MTU " + p.mtu);

            break;

        case "switch":
            badge = tr("Schalter");
            title = e(getDhcpSwitchTitle(p));
            break;

        default:
            badge = tr("Zeile");
            title = "<code>" + e(p.raw.trim()) + "</code>";
            break;
    }

    if ((p.conditions || []).length > 0 && (p.kind !== "ignore") && (p.kind !== "taglist"))
        details.push(tr("nur für Tag {0}", formatDhcpTags(p.conditions)));

    if ((p.setTags || []).length > 0 && (p.kind !== "tag"))
        details.push(tr("setzt Tag {0}", p.setTags.join(", ")));

    if (p.unknown)
        details.push(tr("enthält Angaben, die nur als Text bearbeitet werden können"));

    return { badge: badge, title: title, details: e(details.join(" · ")) };
}

function getDhcpSwitchTitle(p) {
    for (var i = 0; i < DHCP_SWITCHES.length; i++) {
        if (DHCP_SWITCHES[i][0] === p.key)
            return tr(DHCP_SWITCHES[i][1]);
    }

    switch (p.key) {
        case "dhcp-lease-max":
            return tr("Höchstens {0} Leases", p.value);

        case "interface":
            return tr("Nur auf Schnittstelle {0}", p.value);

        case "except-interface":
            return tr("Nicht auf Schnittstelle {0}", p.value);
    }

    return p.key;
}

function getDhcpEditorType(p) {
    switch (p.kind) {
        case "range4":
        case "range6":
        case "host":
        case "option":
        case "option6":
        case "tag":
        case "ignore":
        case "boot":
        case "domain":
        case "ra":
            return p.unknown || p.advanced ? "raw" : p.kind;

        case "switch":
            return "switches";

        default:
            return "raw";
    }
}

function renderDhcpExpertList() {
    var div = $("#divDhcpExpertList");
    var lines = getDhcpExpertLines();
    var modify = canModifyDhcp();
    var html = "";
    var count = 0;

    if (dhcpExpertGeneralErrors.length > 0)
        html += "<div class=\"alert alert-danger\"><ul class=\"dhcp-errors\"><li>" + dhcpExpertGeneralErrors.map(htmlEncode).join("</li><li>") + "</li></ul></div>";

    var rows = "";

    for (var i = 0; i < lines.length; i++) {
        var p = parseDhcpLine(lines[i]);

        if (p.kind === "blank")
            continue;

        count++;

        var d = describeDhcpLine(p);
        var errors = dhcpExpertErrors[i + 1] || [];
        var actions = "";

        if (modify) {
            actions += "<button type=\"button\" class=\"btn btn-default btn-xs\" onclick=\"openDhcpEntryEditor(null, " + i + ");\">" + htmlEncode(tr("Bearbeiten")) + "</button> ";
            actions += "<button type=\"button\" class=\"btn btn-default btn-xs\" onclick=\"moveDhcpExpertLine(" + i + ", -1);\" aria-label=\"" + htmlEncode(tr("Nach oben")) + "\" title=\"" + htmlEncode(tr("Nach oben")) + "\">&uarr;</button> ";
            actions += "<button type=\"button\" class=\"btn btn-default btn-xs\" onclick=\"moveDhcpExpertLine(" + i + ", 1);\" aria-label=\"" + htmlEncode(tr("Nach unten")) + "\" title=\"" + htmlEncode(tr("Nach unten")) + "\">&darr;</button> ";
            actions += "<button type=\"button\" class=\"btn btn-default btn-xs\" onclick=\"deleteDhcpExpertLine(" + i + ");\" aria-label=\"" + htmlEncode(tr("Entfernen")) + "\" title=\"" + htmlEncode(tr("Entfernen")) + "\">&times;</button>";
        }

        rows += "<tr class=\"dhcp-expert-row" + (errors.length > 0 ? " has-error" : "") + (p.kind === "comment" ? " is-comment" : "") + "\">" +
            "<td class=\"dhcp-expert-badge\"><span class=\"label label-default\">" + htmlEncode(d.badge) + "</span><div class=\"dhcp-expert-lineno\">" + (i + 1) + "</div></td>" +
            "<td><div class=\"dhcp-expert-title\">" + d.title + "</div>" + (d.details !== "" ? "<div class=\"dhcp-expert-detail\">" + d.details + "</div>" : "") +
            ((p.kind !== "comment") && (p.kind !== "raw") ? "<code class=\"dhcp-expert-raw\">" + htmlEncode(lines[i].trim()) + "</code>" : "") +
            (errors.length > 0 ? "<div class=\"dhcp-expert-error\">" + errors.map(htmlEncode).join("<br>") + "</div>" : "") + "</td>" +
            "<td class=\"dhcp-expert-actions\">" + actions + "</td></tr>";
    }

    if (count === 0)
        html += "<p class=\"text-muted dhcp-expert-empty\">" + htmlEncode(modify ? tr("Noch keine eigenen Einträge. Über „Neuer Eintrag“ lassen sich Bereiche, Reservierungen, Optionen und Regeln per Auswahl anlegen; die Ansicht Text zeigt dieselbe Konfiguration als dnsmasq-Zeilen.") : tr("Keine eigenen Einträge.")) + "</p>";
    else
        html += "<table class=\"table table-condensed dhcp-expert-table\"><tbody>" + rows + "</tbody></table>";

    div.html(html);
}

function moveDhcpExpertLine(index, direction) {
    var lines = getDhcpExpertLines();
    var target = index + direction;

    while ((target >= 0) && (target < lines.length) && (lines[target].trim() === ""))
        target += direction;

    if ((target < 0) || (target >= lines.length))
        return;

    var line = lines[index];
    lines[index] = lines[target];
    lines[target] = line;
    setDhcpExpertLines(lines);
}

function deleteDhcpExpertLine(index) {
    var lines = getDhcpExpertLines();
    lines.splice(index, 1);
    setDhcpExpertLines(lines);
}

function getDhcpKnownTags() {
    var tags = {};
    var lines = getDhcpExpertLines();
    var i;

    tags["known"] = true;
    tags["bootp"] = true;
    tags["simple"] = true;

    for (i = 0; i < lines.length; i++) {
        var p = parseDhcpLine(lines[i]);

        for (var j = 0; j < (p.setTags || []).length; j++)
            tags[p.setTags[j]] = true;
    }

    if (dhcpSettingsData != null) {
        for (i = 0; i < dhcpSettingsData.interfaces.length; i++)
            tags[dhcpSettingsData.interfaces[i].name] = true;
    }

    return Object.keys(tags).sort();
}

function getDhcpInterfaceNames(v6) {
    var names = [];

    if (dhcpSettingsData == null)
        return names;

    var list = v6 ? (dhcpSettingsData.interfaces6 || []) : dhcpSettingsData.interfaces;

    for (var i = 0; i < list.length; i++)
        names.push(list[i].name);

    return names;
}

function dhcpFormRow(label, control, help, extraClass) {
    return "<div class=\"form-group" + (extraClass ? " " + extraClass : "") + "\"><label class=\"col-sm-3 control-label\">" + htmlEncode(label) + "</label><div class=\"col-sm-8\">" + control + "</div>" + (help ? "<div class=\"col-sm-offset-3 col-sm-8 help-block-text\">" + htmlEncode(help) + "</div>" : "") + "</div>";
}

function dhcpInput(id, value, placeholder, width, list) {
    return "<input id=\"" + id + "\" type=\"text\" class=\"form-control\" style=\"" + (width ? "width: " + width + "; display: inline-block;" : "") + "\" value=\"" + htmlEncode(value == null ? "" : value) + "\" placeholder=\"" + htmlEncode(placeholder || "") + "\" autocomplete=\"off\" spellcheck=\"false\"" + (list ? " list=\"" + list + "\"" : "") + ">";
}

function dhcpSelect(id, options, selected, width) {
    var html = "<select id=\"" + id + "\" class=\"form-control\" style=\"" + (width ? "max-width: " + width + ";" : "") + "\">";

    for (var i = 0; i < options.length; i++) {
        if (options[i].group != null) {
            html += "<optgroup label=\"" + htmlEncode(options[i].group) + "\">";

            for (var j = 0; j < options[i].items.length; j++)
                html += "<option value=\"" + htmlEncode(options[i].items[j][0]) + "\"" + (String(options[i].items[j][0]) === String(selected) ? " selected" : "") + ">" + htmlEncode(options[i].items[j][1]) + "</option>";

            html += "</optgroup>";
            continue;
        }

        html += "<option value=\"" + htmlEncode(options[i][0]) + "\"" + (String(options[i][0]) === String(selected) ? " selected" : "") + ">" + htmlEncode(options[i][1]) + "</option>";
    }

    return html + "</select>";
}

function dhcpCheckbox(id, checked, label) {
    return "<div class=\"checkbox\"><label><input id=\"" + id + "\" type=\"checkbox\"" + (checked ? " checked" : "") + "> " + htmlEncode(label) + "</label></div>";
}

function dhcpDatalist(id, values) {
    var html = "<datalist id=\"" + id + "\">";

    for (var i = 0; i < values.length; i++)
        html += "<option value=\"" + htmlEncode(values[i]) + "\"></option>";

    return html + "</datalist>";
}

function dhcpVal(id) {
    var v = $("#" + id).val();
    return v == null ? "" : String(v).trim();
}

function dhcpTagConditionRow(conditions) {
    return dhcpFormRow(tr("Nur für Tags"), dhcpInput("txtDhcpEntryConditions", conditions.join(", "), tr("leer = alle Geräte"), "320px", "dlDhcpEntryTags"), tr("Mehrere Tags mit Komma trennen; alle müssen gesetzt sein. Ein vorangestelltes ! verneint, etwa !gaeste."));
}

function dhcpSetTagRow(setTags, help) {
    return dhcpFormRow(tr("Setzt Tag"), dhcpInput("txtDhcpEntrySetTag", setTags.join(", "), tr("optional, etwa gaeste"), "220px", "dlDhcpEntryTags"), help || tr("Geräte aus diesem Eintrag bekommen das Tag; Optionen und Regeln mit „Nur für Tags“ greifen dann für sie."));
}

function dhcpLeaseRow(lease) {
    return dhcpFormRow(tr("Lease-Dauer"), dhcpInput("txtDhcpEntryLease", lease, tr("Standard"), "120px", "dlDhcpEntryLease"), tr("Etwa 30m, 12h, 7d oder infinite; leer gilt der Standard."));
}

function readDhcpTagList(id, prefix) {
    var parts = [];
    var raw = dhcpVal(id);

    if (raw === "")
        return parts;

    var items = raw.split(/[\s,]+/);

    for (var i = 0; i < items.length; i++) {
        if (items[i] === "")
            continue;

        if (!/^!?[A-Za-z0-9_.-]{1,64}$/.test(items[i]))
            throw tr("„{0}“ ist kein gültiges Tag.", items[i]);

        if ((prefix === "set:") && (items[i].charAt(0) === "!"))
            throw tr("Ein gesetztes Tag kann nicht verneint werden.");

        parts.push(prefix + items[i]);
    }

    return parts;
}

function joinDhcpLine(key, parts) {
    var filtered = [];

    for (var i = 0; i < parts.length; i++) {
        if (parts[i] != null)
            filtered.push(parts[i]);
    }

    return filtered.length === 0 ? key : key + "=" + filtered.join(",");
}

function getDhcpOptionTypeLabel(type) {
    switch (type) {
        case "Address": return tr("eine Adresse");
        case "AddressList": return tr("Adressen");
        case "AddressPairList": return tr("Adresspaare");
        case "Text": return tr("Text");
        case "TextList": return tr("Texte");
        case "Domain": return tr("Domain");
        case "DomainList": return tr("Domains");
        case "UInt8": case "UInt16": case "UInt32": case "Int32": return tr("Zahl");
        case "Boolean": return tr("Ja/Nein");
        case "UInt16List": return tr("Zahlen");
        case "ClasslessRoutes": return tr("Routen");
        case "NtpServer": return tr("NTP-Server");
        default: return tr("Hex oder Text");
    }
}

function renderDhcpOptionPicker(v6, selectedName) {
    var list = v6 ? (dhcpSettingsData.options6 || []) : (dhcpSettingsData.options || []);
    var common = v6 ? DHCP_COMMON_OPTIONS6 : DHCP_COMMON_OPTIONS;
    var commonItems = [];
    var allItems = [];
    var selected = "";
    var i;

    for (i = 0; i < list.length; i++) {
        var def = list[i];

        if (def.managed)
            continue;

        var label = def.code + "  " + def.name + (DHCP_OPTION_INFO[def.name] ? " – " + tr(DHCP_OPTION_INFO[def.name]) : "");

        if ((selectedName != null) && ((def.name.toLowerCase() === String(selectedName).toLowerCase()) || (String(def.code) === String(selectedName))))
            selected = def.name;

        if (common.indexOf(def.code) >= 0)
            commonItems.push([def.name, label]);

        allItems.push([def.name, label]);
    }

    commonItems.sort(function (a, b) { return common.indexOf(getDhcpOptionDefinition(a[0], v6).code) - common.indexOf(getDhcpOptionDefinition(b[0], v6).code); });

    if ((selectedName != null) && (selectedName !== "") && (selected === ""))
        selected = "#";

    var options = [{ group: tr("Häufig"), items: commonItems }, { group: tr("Alle Optionen"), items: allItems }, { group: tr("Sonstige"), items: [["#", tr("Andere Nummer…")]] }];

    var html = dhcpFormRow(tr("Option"), dhcpSelect("optDhcpEntryOption", options, selected === "" ? (commonItems.length > 0 ? commonItems[0][0] : "") : selected, "520px"));
    html += dhcpFormRow(tr("Nummer"), dhcpInput("txtDhcpEntryOptionCode", selected === "#" ? selectedName : "", v6 ? "1–65535" : "1–254", "120px"), null, "dhcp-entry-option-code");
    html += "<div id=\"divDhcpEntryOptionValue\"></div>";
    return html;
}

function getSelectedDhcpOptionDefinition(v6) {
    var name = $("#optDhcpEntryOption").val();

    if (name === "#")
        return { code: dhcpVal("txtDhcpEntryOptionCode"), name: null, type: v6 ? "Guess" : "Guess" };

    return getDhcpOptionDefinition(name, v6);
}

function renderDhcpOptionValueEditor(v6, values, anyQuoted) {
    var def = getSelectedDhcpOptionDefinition(v6);
    var type = def == null ? "Guess" : def.type;
    var html = "";
    var server = v6 ? "[::]" : "0.0.0.0";
    var rest = [];
    var hasServer = false;
    var i;

    values = values || [];

    for (i = 0; i < values.length; i++) {
        if ((values[i] === server) || (v6 && ((values[i] === "::") || (values[i] === "[::]"))))
            hasServer = true;
        else
            rest.push(values[i]);
    }

    $(".dhcp-entry-option-code").toggle($("#optDhcpEntryOption").val() === "#");

    var help = tr("Wert: {0}.", getDhcpOptionTypeLabel(type));

    switch (type) {
        case "Address":
        case "AddressList":
        case "NtpServer":
            html += dhcpFormRow(tr("Wert"), dhcpCheckbox("chkDhcpEntryServerAddress", hasServer, tr("Adresse dieses Servers im jeweiligen Netz")) + dhcpInput("txtDhcpEntryValue", rest.map(function (v) { return v.replace(/^\[|\]$/g, ""); }).join(", "), type === "Address" ? (v6 ? "2001:db8::1" : "192.168.1.1") : (v6 ? "2001:db8::1, 2001:db8::2" : "192.168.1.1, 192.168.1.2"), "420px"), type === "Address" ? help : tr("Weitere Adressen mit Komma trennen."));
            break;

        case "Boolean":
            html += dhcpFormRow(tr("Wert"), dhcpSelect("txtDhcpEntryValue", [["1", tr("Ja")], ["0", tr("Nein")]], values.length > 0 ? values[0] : "1", "140px"));
            break;

        case "UInt8":
        case "UInt16":
        case "UInt32":
        case "Int32":
            html += dhcpFormRow(tr("Wert"), dhcpInput("txtDhcpEntryValue", values.join(","), "0", "160px"), help);
            break;

        case "ClasslessRoutes":
        case "AddressPairList":
            var pairs = "";

            for (i = 0; i + 1 < values.length; i += 2)
                pairs += values[i] + " " + values[i + 1] + "\n";

            html += dhcpFormRow(tr("Routen"), "<textarea id=\"txtDhcpEntryValue\" class=\"form-control\" rows=\"4\" spellcheck=\"false\" placeholder=\"" + htmlEncode(type === "ClasslessRoutes" ? "10.0.0.0/8 192.168.1.1" : "10.0.0.0 192.168.1.1") + "\">" + htmlEncode(pairs) + "</textarea>", type === "ClasslessRoutes" ? tr("Eine Route pro Zeile: Zielnetz mit Präfix, dann das Gateway.") : tr("Ein Paar pro Zeile: zwei Adressen mit Leerzeichen getrennt."));
            break;

        case "Text":
        case "Domain":
        case "TextList":
        case "DomainList":
        case "UInt16List":
            html += dhcpFormRow(tr("Wert"), dhcpInput("txtDhcpEntryValue", values.join(", "), "", "420px"), ((type === "DomainList") || (type === "TextList") || (type === "UInt16List")) ? tr("Mehrere Werte mit Komma trennen.") : help);
            break;

        default:
            html += dhcpFormRow(tr("Wert"), dhcpInput("txtDhcpEntryValue", values.map(function (v) { return anyQuoted ? quoteDhcpText(v) : v; }).join(","), "01:02:03", "420px"), tr("Hexadezimal als 01:02:03, Text in Anführungszeichen, Adressen direkt."));
            break;
    }

    html += dhcpFormRow("", dhcpCheckbox("chkDhcpEntryEmpty", (values.length === 1) && (values[0] === "") && !anyQuoted, tr("Option nicht senden (unterdrückt einen Wert aus den einfachen Einstellungen)")));

    $("#divDhcpEntryOptionValue").html(html);
    $("#divDhcpEntryOptionValue").data("type", type);
}

function readDhcpOptionValues(v6) {
    var type = $("#divDhcpEntryOptionValue").data("type") || "Guess";

    if ($("#chkDhcpEntryEmpty").prop("checked"))
        return [""];

    var values = [];
    var raw = dhcpVal("txtDhcpEntryValue");
    var i;

    switch (type) {
        case "Address":
        case "AddressList":
        case "NtpServer":
            if ($("#chkDhcpEntryServerAddress").prop("checked"))
                values.push(v6 ? "[::]" : "0.0.0.0");

            var items = raw === "" ? [] : raw.split(/[\s,]+/);

            for (i = 0; i < items.length; i++) {
                if (items[i] === "")
                    continue;

                values.push(v6 && (items[i].indexOf(":") >= 0) ? "[" + items[i].replace(/^\[|\]$/g, "") + "]" : items[i]);
            }

            if ((type === "Address") && (values.length > 1))
                throw tr("Diese Option nimmt genau eine Adresse.");

            break;

        case "ClasslessRoutes":
        case "AddressPairList":
            var rows = raw.split(/\n/);

            for (i = 0; i < rows.length; i++) {
                var parts = rows[i].trim().split(/[\s,]+/);

                if ((parts.length === 1) && (parts[0] === ""))
                    continue;

                if (parts.length !== 2)
                    throw tr("Zeile {0}: Zielnetz und Gateway mit Leerzeichen trennen.", i + 1);

                values.push(parts[0], parts[1]);
            }

            break;

        case "Text":
            values.push(quoteDhcpText(raw));
            break;

        case "TextList":
            var texts = raw.split(",");

            for (i = 0; i < texts.length; i++)
                values.push(quoteDhcpText(texts[i].trim()));

            break;

        case "Domain":
        case "DomainList":
        case "UInt16List":
            var list = raw.split(/[\s,]+/);

            for (i = 0; i < list.length; i++) {
                if (list[i] !== "")
                    values.push(list[i]);
            }

            break;

        default:
            if (raw !== "")
                values.push(raw);

            break;
    }

    if (values.length === 0)
        throw tr("Bitte einen Wert angeben oder „Option nicht senden“ wählen.");

    return values;
}

var DHCP_ENTRY_TYPES = {
    "range4": {
        title: "IPv4-Adressbereich",
        intro: "Adressen, die der Server an Geräte vergibt. Für Netze hinter einem DHCP-Relay ist die Netzmaske Pflicht.",
        render: function (p) {
            var html = dhcpFormRow(tr("Art"), dhcpSelect("optDhcpEntryRangeKind", [["dynamic", tr("Bereich für alle Geräte")], ["static", tr("Nur reservierte Adressen in diesem Netz")]], p.staticOnly ? "static" : "dynamic", "360px"));
            html += dhcpFormRow(tr("Adressen"), dhcpInput("txtDhcpEntryStart", p.start, "192.168.10.100", "160px") + " <span class=\"unit dhcp-entry-range-end\">" + htmlEncode(tr("bis")) + "</span> " + dhcpInput("txtDhcpEntryEnd", p.end, "192.168.10.200", "160px"));
            html += dhcpFormRow(tr("Netzmaske"), dhcpInput("txtDhcpEntryNetmask", p.netmask, tr("aus der Schnittstelle"), "160px"), tr("Leer übernimmt das Präfix der Schnittstelle; Pflicht für Netze hinter einem Relay."));
            html += dhcpLeaseRow(p.lease);
            html += dhcpSetTagRow(p.setTags);
            html += dhcpTagConditionRow(p.conditions);
            return html;
        },
        read: function () {
            var staticOnly = $("#optDhcpEntryRangeKind").val() === "static";
            var start = dhcpVal("txtDhcpEntryStart");
            var end = dhcpVal("txtDhcpEntryEnd");
            var netmask = dhcpVal("txtDhcpEntryNetmask");
            var lease = dhcpVal("txtDhcpEntryLease");

            if (!isDhcpIPv4(start))
                throw tr("Bitte eine gültige Startadresse angeben.");

            if (!staticOnly && !isDhcpIPv4(end))
                throw tr("Bitte eine gültige Endadresse angeben.");

            if ((netmask !== "") && !isDhcpIPv4(netmask))
                throw tr("Die Netzmaske ist ungültig.");

            var parts = readDhcpTagList("txtDhcpEntryConditions", "tag:").concat(readDhcpTagList("txtDhcpEntrySetTag", "set:"));
            parts.push(start, staticOnly ? "static" : end);

            if (netmask !== "")
                parts.push(netmask);

            if (lease !== "")
                parts.push(lease);

            return joinDhcpLine("dhcp-range", parts);
        },
        update: function () {
            var staticOnly = $("#optDhcpEntryRangeKind").val() === "static";
            $("#txtDhcpEntryEnd, .dhcp-entry-range-end").toggle(!staticOnly);
        }
    },

    "range6": {
        title: "IPv6-Bereich oder Präfix",
        intro: "Mit einer Schnittstelle als Quelle kommen die Präfixe von ihr und folgen Wechseln des Anbieters; angegeben wird nur der hintere Teil der Adressen. Ein festes Präfix bedient auch Netze hinter einem DHCPv6-Relay.",
        render: function (p) {
            var source = p.ctorIface != null || p.start == null ? "iface" : "fixed";
            var ifaces = getDhcpInterfaceNames(true);
            var ifaceOptions = [];

            for (var i = 0; i < ifaces.length; i++)
                ifaceOptions.push([ifaces[i], ifaces[i]]);

            if ((p.ctorIface != null) && (ifaces.indexOf(p.ctorIface) < 0))
                ifaceOptions.push([p.ctorIface, p.ctorIface]);

            var html = dhcpFormRow(tr("Vergabe"), dhcpSelect("optDhcpEntryMode", [["ra-stateless", tr("SLAAC, DNS-Server per Router Advertisement und DHCPv6 (empfohlen)")], ["slaac", tr("SLAAC und zusätzlich DHCPv6-Adressen")], ["", tr("Nur DHCPv6-Adressen")], ["ra-only", tr("Nur SLAAC, kein DHCPv6")], ["static", tr("Nur reservierte Adressen")]], p.start == null ? "ra-stateless" : p.mode, "520px"));
            html += dhcpFormRow(tr("Präfix"), dhcpSelect("optDhcpEntrySource", [["iface", tr("von einer Schnittstelle")], ["fixed", tr("fest angegeben")]], source, "260px"));
            html += dhcpFormRow(tr("Schnittstelle"), dhcpSelect("optDhcpEntryIface", ifaceOptions, p.ctorIface || (ifaces.length > 0 ? ifaces[0] : ""), "260px"), tr("Endet der Name auf *, gilt der Eintrag für alle passenden Schnittstellen; das geht nur in der Ansicht Text."), "dhcp-entry-iface");
            html += dhcpFormRow(tr("Adressen"), dhcpInput("txtDhcpEntryStart", p.start, "::1000", "220px") + " <span class=\"unit dhcp-entry-range-end\">" + htmlEncode(tr("bis")) + "</span> " + dhcpInput("txtDhcpEntryEnd", p.end, "::1fff", "220px"), tr("Bei einer Schnittstelle nur der hintere Teil wie ::1000, sonst vollständige Adressen."), "dhcp-entry-range6-addresses");
            html += dhcpFormRow(tr("Präfixlänge"), dhcpInput("txtDhcpEntryPrefix", p.prefixLength, "64", "80px"), tr("Für SLAAC genau 64."));
            html += dhcpFormRow("", dhcpCheckbox("chkDhcpEntryOffLink", p.offLink, tr("Präfix nicht als im Netz erreichbar ankündigen (off-link)")));
            html += dhcpLeaseRow(p.lease);
            html += dhcpSetTagRow(p.setTags);
            return html;
        },
        read: function () {
            var mode = $("#optDhcpEntryMode").val();
            var fromIface = $("#optDhcpEntrySource").val() === "iface";
            var iface = dhcpVal("optDhcpEntryIface");
            var start = dhcpVal("txtDhcpEntryStart");
            var end = dhcpVal("txtDhcpEntryEnd");
            var prefix = dhcpVal("txtDhcpEntryPrefix");
            var lease = dhcpVal("txtDhcpEntryLease");
            var addresses = (mode === "") || (mode === "slaac");

            if (fromIface && (iface === ""))
                throw tr("Bitte eine Schnittstelle wählen.");

            if (!addresses && (mode !== "static")) {
                if (start === "")
                    start = "::";
            }
            else if (start === "") {
                throw tr("Bitte die erste Adresse angeben.");
            }

            if (start.indexOf(":") < 0)
                throw tr("Bitte eine IPv6-Adresse angeben, etwa ::1000.");

            if (addresses && (end === ""))
                throw tr("Bitte die letzte Adresse angeben.");

            if ((prefix !== "") && !/^\d{1,3}$/.test(prefix))
                throw tr("Die Präfixlänge ist ungültig.");

            var parts = readDhcpTagList("txtDhcpEntrySetTag", "set:");
            parts.push(start);

            if (mode === "static")
                parts.push("static");
            else if (addresses)
                parts.push(end);

            if (fromIface)
                parts.push("constructor:" + iface);

            if ((mode !== "") && (mode !== "static"))
                parts.push(mode);

            if ($("#chkDhcpEntryOffLink").prop("checked"))
                parts.push("off-link");

            parts.push(prefix === "" ? "64" : prefix);

            if (lease !== "")
                parts.push(lease);

            return joinDhcpLine("dhcp-range", parts);
        },
        update: function () {
            var mode = $("#optDhcpEntryMode").val();
            var addresses = (mode === "") || (mode === "slaac");
            $(".dhcp-entry-iface").toggle($("#optDhcpEntrySource").val() === "iface");
            $(".dhcp-entry-range6-addresses").toggle(addresses || (mode === "static") || ($("#optDhcpEntrySource").val() === "fixed"));
            $("#txtDhcpEntryEnd, .dhcp-entry-range-end").toggle(addresses);
        }
    },

    "host": {
        title: "Reservierung oder Geräteeintrag",
        intro: "Erkennt ein Gerät an MAC-Adresse, Client-ID (DHCPv4, Option 61) oder DUID (DHCPv6) und gibt ihm feste Adressen, einen Namen, eine eigene Lease-Dauer oder ein Tag – oder beantwortet es gar nicht.",
        render: function (p) {
            var html = dhcpFormRow(tr("MAC-Adresse"), dhcpInput("txtDhcpEntryMac", (p.macs || []).join(", "), "aa:bb:cc:dd:ee:ff", "300px"), tr("Mehrere mit Komma trennen; * steht für beliebige Stellen, etwa 11:22:33:*:*:*."));
            html += dhcpFormRow(tr("Client-ID oder DUID"), dhcpInput("txtDhcpEntryId", (p.ids || []).join(", "), "01:aa:bb:cc:dd:ee:ff", "380px"), tr("Optional; hexadezimal mit Doppelpunkten oder als Text. * lässt die Client-ID für die Zuordnung außer Acht."));
            html += dhcpFormRow(tr("Hostname"), dhcpInput("txtDhcpEntryName", p.name, tr("optional"), "220px"), tr("Ohne MAC und Client-ID passt der Eintrag auf Geräte, die diesen Namen senden."));
            html += dhcpFormRow(tr("IPv4-Adresse"), dhcpInput("txtDhcpEntryIpv4", p.ipv4, tr("optional"), "180px"));
            html += dhcpFormRow(tr("IPv6-Adresse"), dhcpInput("txtDhcpEntryIpv6", p.ipv6, "::20", "260px"), tr("Der hintere Teil wie ::20 gilt in jedem Präfix, eine vollständige Adresse nur in ihrem."));
            html += dhcpLeaseRow(p.lease);
            html += dhcpSetTagRow(p.setTags);
            html += dhcpTagConditionRow(p.conditions);
            html += dhcpFormRow("", dhcpCheckbox("chkDhcpEntryIgnore", p.ignore, tr("Dieses Gerät nicht beantworten")));
            return html;
        },
        read: function () {
            var parts = [];
            var macs = dhcpVal("txtDhcpEntryMac");
            var ids = dhcpVal("txtDhcpEntryId");
            var name = dhcpVal("txtDhcpEntryName");
            var ipv4 = dhcpVal("txtDhcpEntryIpv4");
            var ipv6 = dhcpVal("txtDhcpEntryIpv6").replace(/^\[|\]$/g, "");
            var lease = dhcpVal("txtDhcpEntryLease");
            var i;

            var macList = macs === "" ? [] : macs.split(/[\s,]+/);

            for (i = 0; i < macList.length; i++) {
                if (macList[i] === "")
                    continue;

                if (!isDhcpMac(macList[i]))
                    throw tr("„{0}“ ist keine gültige MAC-Adresse.", macList[i]);

                var mac = macList[i].toLowerCase();

                if (/^[0-9a-f*]{2}(-[0-9a-f*]{2}){5}$/.test(mac))
                    mac = mac.replace(/-/g, ":");

                parts.push(mac);
            }

            var idList = ids === "" ? [] : ids.split(/[\s,]+/);

            for (i = 0; i < idList.length; i++) {
                if (idList[i] !== "")
                    parts.push("id:" + idList[i].replace(/^id:/i, ""));
            }

            if ((parts.length === 0) && (name === ""))
                throw tr("Bitte eine MAC-Adresse, eine Client-ID oder einen Hostnamen angeben.");

            parts = parts.concat(readDhcpTagList("txtDhcpEntrySetTag", "set:"), readDhcpTagList("txtDhcpEntryConditions", "tag:"));

            if (ipv4 !== "") {
                if (!isDhcpIPv4(ipv4))
                    throw tr("Die IPv4-Adresse ist ungültig.");

                parts.push(ipv4);
            }

            if (ipv6 !== "") {
                if (ipv6.indexOf(":") < 0)
                    throw tr("Die IPv6-Adresse ist ungültig.");

                parts.push("[" + ipv6 + "]");
            }

            if (name !== "") {
                if (!/^[A-Za-z0-9][A-Za-z0-9.-]*$/.test(name))
                    throw tr("Der Hostname darf nur Buchstaben, Ziffern, Bindestriche und Punkte enthalten.");

                parts.push(name);
            }

            if (lease !== "")
                parts.push(lease);

            if ($("#chkDhcpEntryIgnore").prop("checked"))
                parts.push("ignore");

            return joinDhcpLine("dhcp-host", parts);
        }
    },

    "option": {
        title: "DHCP-Option (IPv4)",
        intro: "Einstellungen, die Geräte zusammen mit ihrer Adresse bekommen. Eine Option hier hat Vorrang vor derselben Option aus den einfachen Einstellungen; mit Tags gilt sie nur für bestimmte Geräte.",
        render: function (p) {
            var html = renderDhcpOptionPicker(false, p.optionName);
            html += dhcpTagConditionRow(p.conditions);
            html += dhcpFormRow("", dhcpCheckbox("chkDhcpEntryForce", p.force, tr("Immer senden, auch wenn das Gerät nicht danach fragt")));
            return html;
        },
        afterRender: function (p) {
            renderDhcpOptionValueEditor(false, p.values, p.anyQuoted);
            $("#optDhcpEntryOption").on("change", function () { renderDhcpOptionValueEditor(false, [], false); updateDhcpEntryPreview(); });
        },
        read: function () {
            return readDhcpOptionLine(false);
        }
    },

    "option6": {
        title: "DHCPv6-Option",
        intro: "Einstellungen für DHCPv6-Antworten. DNS-Server und Suchdomänen ohne Tag gelten auch für die Router Advertisements; [::] steht für die Adresse dieses Servers.",
        render: function (p) {
            var html = renderDhcpOptionPicker(true, p.optionName);
            html += dhcpTagConditionRow(p.conditions);
            html += dhcpFormRow("", dhcpCheckbox("chkDhcpEntryForce", p.force, tr("Immer senden, auch wenn das Gerät nicht danach fragt")));
            return html;
        },
        afterRender: function (p) {
            renderDhcpOptionValueEditor(true, p.values, p.anyQuoted);
            $("#optDhcpEntryOption").on("change", function () { renderDhcpOptionValueEditor(true, [], false); updateDhcpEntryPreview(); });
        },
        read: function () {
            return readDhcpOptionLine(true);
        }
    },

    "tag": {
        title: "Gerätegruppe (Tag)",
        intro: "Setzt ein Tag für Geräte mit bestimmten Merkmalen. Optionen, Bereiche und Regeln mit „Nur für Tags“ gelten dann nur für diese Gruppe.",
        render: function (p) {
            var kinds = [];

            for (var i = 0; i < DHCP_TAG_KINDS.length; i++)
                kinds.push([DHCP_TAG_KINDS[i][0], tr(DHCP_TAG_KINDS[i][1])]);

            var html = dhcpFormRow(tr("Tag"), dhcpInput("txtDhcpEntrySetTag", (p.setTags || []).join(", "), "telefone", "220px", "dlDhcpEntryTags"));
            html += dhcpFormRow(tr("Bedingung"), dhcpSelect("optDhcpEntryTagKind", kinds, p.key || "dhcp-vendorclass", "420px"));
            html += dhcpFormRow(tr("Option"), dhcpInput("txtDhcpEntryMatchOption", p.matchOption, "option:client-arch", "260px"), tr("Optionsname wie option:client-arch oder eine Nummer."), "dhcp-entry-match-option");
            html += dhcpFormRow(tr("Wert"), dhcpInput("txtDhcpEntryMatchValue", p.matchValue, "", "320px"), null, "dhcp-entry-match-value");
            return html;
        },
        read: function () {
            var kind = $("#optDhcpEntryTagKind").val();
            var tags = readDhcpTagList("txtDhcpEntrySetTag", "set:");
            var option = dhcpVal("txtDhcpEntryMatchOption");
            var value = dhcpVal("txtDhcpEntryMatchValue");

            if (tags.length !== 1)
                throw tr("Bitte genau ein Tag angeben.");

            var parts = tags;

            if (kind === "dhcp-match") {
                if (option === "")
                    throw tr("Bitte die Option angeben.");

                parts.push(option);

                if (value !== "")
                    parts.push(value);
            }
            else {
                if (value === "")
                    throw tr("Bitte einen Wert angeben.");

                parts.push(value);
            }

            return joinDhcpLine(kind, parts);
        },
        update: function () {
            $(".dhcp-entry-match-option").toggle($("#optDhcpEntryTagKind").val() === "dhcp-match");
        }
    },

    "ignore": {
        title: "Geräte nicht beantworten",
        intro: "Der Server schweigt gegenüber Geräten mit den angegebenen Tags, etwa einer Gruppe aus MAC-Adressen.",
        render: function (p) {
            return dhcpFormRow(tr("Tags"), dhcpInput("txtDhcpEntryConditions", (p.conditions || []).join(", "), "gesperrt", "320px", "dlDhcpEntryTags"), tr("Alle angegebenen Tags müssen gesetzt sein; ! verneint."));
        },
        read: function () {
            var tags = readDhcpTagList("txtDhcpEntryConditions", "tag:");

            if (tags.length === 0)
                throw tr("Bitte mindestens ein Tag angeben.");

            return joinDhcpLine("dhcp-ignore", tags);
        }
    },

    "boot": {
        title: "Netzwerkstart (PXE)",
        intro: "Startdatei und TFTP-Server für Geräte, die über das Netz starten. Mit Tags lassen sich etwa BIOS- und UEFI-Geräte unterscheiden.",
        render: function (p) {
            var html = dhcpFormRow(tr("Startdatei"), dhcpInput("txtDhcpEntryFile", p.file, "pxelinux.0", "260px"));
            html += dhcpFormRow(tr("Servername"), dhcpInput("txtDhcpEntryServerName", p.serverName, tr("optional"), "220px"));
            html += dhcpFormRow(tr("Serveradresse"), dhcpInput("txtDhcpEntryServerAddress", p.serverAddress, "192.168.1.5", "180px"), tr("Adresse des TFTP-Servers; leer gilt dieser Server."));
            html += dhcpTagConditionRow(p.conditions || []);
            return html;
        },
        read: function () {
            var file = dhcpVal("txtDhcpEntryFile");
            var name = dhcpVal("txtDhcpEntryServerName");
            var address = dhcpVal("txtDhcpEntryServerAddress");

            if (file === "")
                throw tr("Bitte die Startdatei angeben.");

            if ((address !== "") && !isDhcpIPv4(address))
                throw tr("Die Serveradresse ist ungültig.");

            var parts = readDhcpTagList("txtDhcpEntryConditions", "tag:");
            parts.push(file);

            if ((name !== "") || (address !== ""))
                parts.push(name);

            if (address !== "")
                parts.push(address);

            return joinDhcpLine("dhcp-boot", parts);
        }
    },

    "domain": {
        title: "Domain für Gerätenamen",
        intro: "Geräte sind unter name.domain erreichbar. Mit Netz gilt die Domain nur für Adressen daraus.",
        render: function (p) {
            var html = dhcpFormRow(tr("Domain"), dhcpInput("txtDhcpEntryDomain", p.domain, "home.arpa", "260px"));
            html += dhcpFormRow(tr("Netz"), dhcpInput("txtDhcpEntryNetwork", p.network, "192.168.10.0/24", "260px"), tr("Optional: Netz mit Präfix oder erste und letzte Adresse mit Komma."));
            html += dhcpFormRow("", dhcpCheckbox("chkDhcpEntryLocal", p.local !== false, tr("Unbekannte Namen in dieser Domain selbst mit NXDOMAIN beantworten")));
            return html;
        },
        read: function () {
            var domain = dhcpVal("txtDhcpEntryDomain").replace(/\.$/, "");
            var network = dhcpVal("txtDhcpEntryNetwork");

            if (!/^[A-Za-z0-9.-]+$/.test(domain))
                throw tr("Bitte eine gültige Domain angeben.");

            var parts = [domain];

            if (network !== "")
                parts.push(network);

            if ($("#chkDhcpEntryLocal").prop("checked"))
                parts.push("local");

            return joinDhcpLine("domain", parts);
        }
    },

    "ra": {
        title: "Router Advertisements einer Schnittstelle",
        intro: "Abstand, Router-Lebensdauer, Priorität und MTU der Router Advertisements auf einer Schnittstelle.",
        render: function (p) {
            var ifaces = getDhcpInterfaceNames(true);
            var options = [];

            for (var i = 0; i < ifaces.length; i++)
                options.push([ifaces[i], ifaces[i]]);

            if (p.iface && (ifaces.indexOf(p.iface) < 0))
                options.push([p.iface, p.iface]);

            var lifetimeMode = p.lifetime === "" || p.lifetime == null ? "auto" : (p.lifetime === "0" ? "no" : "custom");

            var html = dhcpFormRow(tr("Schnittstelle"), dhcpSelect("optDhcpEntryIface", options, p.iface || (ifaces.length > 0 ? ifaces[0] : ""), "260px"));
            html += dhcpFormRow(tr("Abstand"), dhcpInput("txtDhcpEntryInterval", p.interval || "600", "600", "100px") + " <span class=\"unit\">" + htmlEncode(tr("Sekunden (4 bis 1800)")) + "</span>");
            html += dhcpFormRow(tr("Standard-Router"), dhcpSelect("optDhcpEntryLifetimeMode", [["auto", tr("Automatisch: nur wenn dieser Rechner IPv6 weiterleitet")], ["no", tr("Nein, nur Präfix und DNS-Server ankündigen")], ["custom", tr("Ja, mit dieser Lebensdauer")]], lifetimeMode, "420px") + " " + dhcpInput("txtDhcpEntryLifetime", lifetimeMode === "custom" ? p.lifetime : "1800", "1800", "100px"));
            html += dhcpFormRow(tr("Router-Priorität"), dhcpSelect("optDhcpEntryPreference", [["", tr("Normal")], ["high", tr("Hoch")], ["low", tr("Niedrig")]], p.preference || "", "200px"));
            html += dhcpFormRow(tr("MTU"), dhcpInput("txtDhcpEntryMtu", p.mtu, tr("nicht ankündigen"), "160px"), tr("Zahl ab 1280, off oder der Name einer Schnittstelle, deren MTU gilt."));
            return html;
        },
        read: function () {
            var iface = dhcpVal("optDhcpEntryIface");
            var interval = dhcpVal("txtDhcpEntryInterval");
            var mode = $("#optDhcpEntryLifetimeMode").val();
            var lifetime = dhcpVal("txtDhcpEntryLifetime");
            var mtu = dhcpVal("txtDhcpEntryMtu");

            if (iface === "")
                throw tr("Bitte eine Schnittstelle wählen.");

            if (!/^\d+$/.test(interval))
                throw tr("Der Abstand muss eine Zahl sein.");

            var parts = [iface];

            if (mtu !== "")
                parts.push("mtu:" + mtu);

            if ($("#optDhcpEntryPreference").val() !== "")
                parts.push($("#optDhcpEntryPreference").val());

            parts.push(interval);

            if (mode === "no")
                parts.push("0");
            else if (mode === "custom") {
                if (!/^\d+$/.test(lifetime))
                    throw tr("Die Lebensdauer muss eine Zahl sein.");

                parts.push(lifetime);
            }

            return joinDhcpLine("ra-param", parts);
        },
        update: function () {
            $("#txtDhcpEntryLifetime").toggle($("#optDhcpEntryLifetimeMode").val() === "custom");
        }
    },

    "switches": {
        title: "Allgemeine Schalter",
        intro: "Gelten für den ganzen DHCP-Server. Eingeschaltete Schalter stehen als eigene Zeilen in der Konfiguration.",
        render: function () {
            var present = {};
            var lines = getDhcpExpertLines();
            var leaseMax = "";
            var ifaces = [];
            var excepts = [];

            for (var i = 0; i < lines.length; i++) {
                var p = parseDhcpLine(lines[i]);

                if (p.kind !== "switch")
                    continue;

                present[p.key] = true;

                if (p.key === "dhcp-lease-max")
                    leaseMax = p.value;
                else if (p.key === "interface")
                    ifaces.push(p.value);
                else if (p.key === "except-interface")
                    excepts.push(p.value);
            }

            var html = "<div class=\"dhcp-entry-switches\">";

            for (var s = 0; s < DHCP_SWITCHES.length; s++)
                html += dhcpCheckbox("chkDhcpSwitch" + s, present[DHCP_SWITCHES[s][0]] === true, tr(DHCP_SWITCHES[s][1]));

            html += "</div>";
            html += dhcpFormRow(tr("Höchstzahl Leases"), dhcpInput("txtDhcpEntryLeaseMax", leaseMax, "1000", "120px"), tr("Leer gilt 1000; gilt für IPv4 und IPv6 getrennt."));
            html += dhcpFormRow(tr("Nur Schnittstellen"), dhcpInput("txtDhcpEntryInterfaces", ifaces.join(", "), tr("alle"), "320px"), tr("Mehrere mit Komma trennen; eth* passt auf einen Anfang."));
            html += dhcpFormRow(tr("Außer Schnittstellen"), dhcpInput("txtDhcpEntryExcept", excepts.join(", "), tr("keine"), "320px"));
            return html;
        },
        read: function () {
            var result = [];
            var i;

            for (i = 0; i < DHCP_SWITCHES.length; i++) {
                if ($("#chkDhcpSwitch" + i).prop("checked"))
                    result.push(DHCP_SWITCHES[i][0]);
            }

            var leaseMax = dhcpVal("txtDhcpEntryLeaseMax");

            if (leaseMax !== "") {
                if (!/^\d+$/.test(leaseMax))
                    throw tr("Die Höchstzahl muss eine Zahl sein.");

                result.push("dhcp-lease-max=" + leaseMax);
            }

            var groups = [["txtDhcpEntryInterfaces", "interface="], ["txtDhcpEntryExcept", "except-interface="]];

            for (var g = 0; g < groups.length; g++) {
                var names = dhcpVal(groups[g][0]).split(/[\s,]+/);

                for (i = 0; i < names.length; i++) {
                    if (names[i] !== "")
                        result.push(groups[g][1] + names[i]);
                }
            }

            return result;
        }
    },

    "raw": {
        title: "Zeile",
        intro: "Eine Zeile in der Syntax von dnsmasq; die Übersicht der Anweisungen steht unten unter „Unterstützte Anweisungen“.",
        render: function (p) {
            return dhcpFormRow(tr("Zeile"), dhcpInput("txtDhcpEntryRaw", p.raw, "dhcp-option=option:ntp-server,192.168.1.1", "100%"));
        },
        read: function () {
            var raw = dhcpVal("txtDhcpEntryRaw");

            if (raw === "")
                throw tr("Die Zeile ist leer.");

            if (raw.indexOf("\n") >= 0)
                throw tr("Bitte nur eine Zeile angeben.");

            return raw;
        }
    }
};

function readDhcpOptionLine(v6) {
    var def = getSelectedDhcpOptionDefinition(v6);
    var spec;

    if ($("#optDhcpEntryOption").val() === "#") {
        var code = dhcpVal("txtDhcpEntryOptionCode");

        if (!/^\d+$/.test(code) || (parseInt(code, 10) < 1) || (parseInt(code, 10) > (v6 ? 65535 : 254)))
            throw tr("Bitte eine gültige Optionsnummer angeben.");

        spec = v6 ? "option6:" + code : code;
    }
    else {
        if (def == null)
            throw tr("Bitte eine Option wählen.");

        spec = (v6 ? "option6:" : "option:") + def.name;
    }

    var parts = readDhcpTagList("txtDhcpEntryConditions", "tag:");
    parts.push(spec);
    parts = parts.concat(readDhcpOptionValues(v6));

    return joinDhcpLine($("#chkDhcpEntryForce").prop("checked") ? "dhcp-option-force" : "dhcp-option", parts);
}

function openDhcpEntryEditor(type, lineIndex) {
    if (dhcpSettingsData == null)
        return;

    var parsed = { raw: "", conditions: [], setTags: [] };

    if (lineIndex >= 0) {
        var lines = getDhcpExpertLines();
        parsed = parseDhcpLine(lines[lineIndex]);
        type = getDhcpEditorType(parsed);

        if ((type === "raw") && (parsed.kind === "comment"))
            parsed.raw = lines[lineIndex];
    }

    var editor = DHCP_ENTRY_TYPES[type];
    dhcpEntryEditor = { type: type, lineIndex: lineIndex, editor: editor };

    $("#titleDhcpEntry").text(tr(editor.title));
    $("#lblDhcpEntryIntro").text(tr(editor.intro));
    $("#divDhcpEntryForm").html(dhcpDatalist("dlDhcpEntryTags", getDhcpKnownTags()) + dhcpDatalist("dlDhcpEntryLease", ["30m", "1h", "12h", "24h", "7d", "infinite"]) + editor.render(parsed));
    hideAlert($("#divDhcpEntryAlert"));

    if (editor.afterRender != null)
        editor.afterRender(parsed);

    updateDhcpEntryPreview();
    $("#btnDhcpEntryApply").text(lineIndex >= 0 ? tr("Übernehmen") : tr("Hinzufügen"));
    $("#modalDhcpEntry").modal("show");
}

function updateDhcpEntryPreview() {
    if (dhcpEntryEditor == null)
        return;

    if (dhcpEntryEditor.editor.update != null)
        dhcpEntryEditor.editor.update();

    try {
        var result = dhcpEntryEditor.editor.read();
        $("#preDhcpEntryLine").text(Array.isArray(result) ? (result.length === 0 ? tr("(keine Zeilen)") : result.join("\n")) : result).removeClass("text-muted");
    }
    catch (e) {
        $("#preDhcpEntryLine").text(typeof e === "string" ? e : String(e)).addClass("text-muted");
    }
}

function applyDhcpEntryEditor() {
    if (dhcpEntryEditor == null)
        return;

    var result;

    try {
        result = dhcpEntryEditor.editor.read();
    }
    catch (e) {
        showAlert("warning", tr("Unvollständig"), typeof e === "string" ? e : String(e), $("#divDhcpEntryAlert"));
        return;
    }

    var lines = getDhcpExpertLines();

    if (dhcpEntryEditor.type === "switches") {
        var firstIndex = -1;
        var kept = [];

        for (var i = 0; i < lines.length; i++) {
            if (parseDhcpLine(lines[i]).kind === "switch") {
                if (firstIndex < 0)
                    firstIndex = kept.length;

                continue;
            }

            kept.push(lines[i]);
        }

        if (firstIndex < 0)
            firstIndex = kept.length;

        lines = kept.slice(0, firstIndex).concat(result, kept.slice(firstIndex));
    }
    else if (dhcpEntryEditor.lineIndex >= 0) {
        lines[dhcpEntryEditor.lineIndex] = result;
    }
    else {
        lines.push(result);
    }

    dhcpEntryEditor = null;
    $("#modalDhcpEntry").modal("hide");
    setDhcpExpertLines(lines);
}
