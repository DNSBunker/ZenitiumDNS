let refreshTimerHandle;
let reverseProxyDetected = false;
let quickBlockLists = null;
let quickForwardersList = null;

function showPageLogin() {
    hideAlert();
    localStorage.removeItem("token");

    $("#pageMain").hide();
    $("#mnuUser").hide();
    $("#txtUser").val("");
    $("#txtPass").val("").prop("disabled", false);
    $("#div2FAOTP").hide();
    $("#txt2FATOTP").val("");
    $("#btnLogin").button("reset");
    $("#pageLogin").show();
    $("#txtUser").trigger("focus");

    if (refreshTimerHandle != null) {
        clearInterval(refreshTimerHandle);
        refreshTimerHandle = null;
    }
}

function showPageMain() {
    hideAlert();
    $("#pageLogin").hide();
    $("#mnuUser").show();

    $("#mainPanelTabListDhcp, #mainPanelTabPaneDhcp, #settingsTabListDhcp").hide();
    $("#mainPanelTabListCluster, #mainPanelTabPaneCluster, #settingsTabListCluster").hide();

    if (sessionData?.info?.permissions) {
        const sections = ["Dashboard","Zones","Cache","Allowed","Blocked","Apps","DnsClient","Settings","Administration","Logs"];
        for (const sec of sections) {
            sessionData.info.permissions[sec] ??= { canView: false, canModify: false, canDelete: false };
        }
    }

    $(".nav-tabs li").removeClass("active");
    $(".tab-pane").removeClass("active");

    for (const id of [
        "#mainPanelTabListDashboard:#mainPanelTabPaneDashboard",
        "#settingsTabListGeneral:#settingsTabPaneGeneral",
        "#adminTabListSessions:#adminTabPaneSessions",
        "#logsTabListLogViewer:#logsTabPaneLogViewer"
    ]) {
        const [tab, pane] = id.split(":");
        $(tab).addClass("active");
        $(pane).addClass("active");
    }

    $("#divViewZones").show();
    $("#divEditZone").hide();

    $("#txtDnsClientNameServer").val("This Server {this-server}");
    $("#txtDnsClientDomain").val("");
    $("#optDnsClientType").val("A");
    $("#optDnsClientProtocol").val("UDP");
    $("#txtDnsClientEDnsClientSubnet").val("");
    $("#chkDnsClientDnssecValidation").prop("checked", false);
    $("#divDnsClientLoader").hide();
    $("#preDnsClientFinalResponse").text("");
    $("#divDnsClientOutputAccordion").hide();
    $("#divLogViewer, #divQueryLogsTable").hide();

    const perms = sessionData.info.permissions;

    if (perms.Dashboard.canView) {
        $("#mainPanelTabListDashboard").show();
        refreshDashboard();
    } else {
        $("#mainPanelTabListDashboard").hide().removeClass("active");
        $("#mainPanelTabPaneDashboard").removeClass("active");

        const fallbacks = [
            { perm: perms.Zones.canView,         tab: "#mainPanelTabListZones",        pane: "#mainPanelTabPaneZones",        fn: () => refreshZones(true) },
            { perm: perms.Cache.canView,          tab: "#mainPanelTabListCachedZones",  pane: "#mainPanelTabPaneCachedZones" },
            { perm: perms.Allowed.canView,        tab: "#mainPanelTabListAllowedZones", pane: "#mainPanelTabPaneAllowedZones" },
            { perm: perms.Blocked.canView,        tab: "#mainPanelTabListBlockedZones", pane: "#mainPanelTabPaneBlockedZones" },
            { perm: perms.Apps.canView,           tab: "#mainPanelTabListApps",         pane: "#mainPanelTabPaneApps",         fn: refreshApps },
            { perm: perms.DnsClient.canView,      tab: "#mainPanelTabListDnsClient",    pane: "#mainPanelTabPaneDnsClient" },
            { perm: perms.Settings.canView,       tab: "#mainPanelTabListSettings",     pane: "#mainPanelTabPaneSettings",     fn: refreshDnsSettings },
            { perm: perms.Administration.canView, tab: "#mainPanelTabListAdmin",        pane: "#mainPanelTabPaneAdmin",        fn: refreshAdminTab },
            { perm: perms.Logs.canView,           tab: "#mainPanelTabListLogs",         pane: "#mainPanelTabPaneLogs",         fn: refreshLogsTab },
        ];

        const found = fallbacks.find(f => f.perm);
        if (found) {
            $(found.tab).addClass("active");
            $(found.pane).addClass("active");
            found.fn?.();
        } else {
            $("#mainPanelTabListAbout").addClass("active");
            $("#mainPanelTabPaneAbout").addClass("active");
        }
    }

    const tabVisibility = [
        { selector: "#mainPanelTabListZones",        perm: perms.Zones.canView,         fn: null },
        { selector: "#mainPanelTabListCachedZones",  perm: perms.Cache.canView,         fn: () => refreshCachedZonesList("") },
        { selector: "#mainPanelTabListAllowedZones", perm: perms.Allowed.canView,       fn: () => refreshAllowedZonesList("") },
        { selector: "#mainPanelTabListBlockedZones", perm: perms.Blocked.canView,       fn: () => refreshBlockedZonesList("") },
        { selector: "#mainPanelTabListApps",         perm: perms.Apps.canView,          fn: null },
        { selector: "#mainPanelTabListDnsClient",    perm: perms.DnsClient.canView,     fn: null },
        { selector: "#mainPanelTabListSettings",     perm: perms.Settings.canView,      fn: null },
        { selector: "#mainPanelTabListAdmin",        perm: perms.Administration.canView,fn: null },
        { selector: "#mainPanelTabListLogs",         perm: perms.Logs.canView,          fn: null },
    ];

    for (const { selector, perm, fn } of tabVisibility) {
        if (perm) { $(selector).show(); fn?.(); }
        else        $(selector).hide();
    }

    $("#pageMain").show();
    checkForUpdate();

    refreshTimerHandle = setInterval(() => {
        if ($("input[name=rdStatType]:checked").val() === "lastHour")
            refreshDashboard(true);
        $("#lblAboutUptime").text(
            moment(sessionData.info.uptimestamp).local().format("lll") +
            " (" + moment(sessionData.info.uptimestamp).fromNow() + ")"
        );
    }, 60000);
}


$(function () {
    const headerHtml = $("#header").html();
    $("#header").html(`<div class="title"><a href="."><span class="text" style="color:#ffffff;">Zenitium</span></a>${headerHtml}</div>`);
    $("#footer").html("Proudly presented by xRuffKez | Zenitium DNS | Codebase by Shreyas Zare");

    loadQuickBlockLists();
    loadQuickForwardersList();

    $("#chkEnableUdpSocketPool").on("click", function () {
        $("#txtUdpSocketPoolExcludedPorts").prop("disabled", !this.checked);
    });

    $("#chkEDnsClientSubnet").on("click", function () {
        const on = this.checked;
        $("#txtEDnsClientSubnetIPv4PrefixLength, #txtEDnsClientSubnetIPv6PrefixLength, #txtEDnsClientSubnetIpv4Override, #txtEDnsClientSubnetIpv6Override")
            .prop("disabled", !on);
    });

    $("#chkEnableBlocking").on("click", updateBlockingState);

    $("input[type=radio][name=rdProxyType]").on("change", function () {
        const on = $("input[name=rdProxyType]:checked").val().toLowerCase() !== "none";
        $("#txtProxyAddress, #txtProxyPort, #txtProxyUsername, #txtProxyPassword, #txtProxyBypassList").prop("disabled", !on);
    });

    $("input[type=radio][name=rdRecursion]").on("change", function () {
        $("#txtRecursionNetworkACL").prop("disabled", $("input[name=rdRecursion]:checked").val() !== "UseSpecifiedNetworkACL");
    });

    $("input[type=radio][name=rdBlockingType]").on("change", function () {
        $("#txtCustomBlockingAddresses").prop("disabled", $("input[name=rdBlockingType]:checked").val() !== "CustomAddress");
    });

    $("#chkWebServiceEnableTls").on("click", function () {
        const on = this.checked;
        $("#chkWebServiceEnableHttp3, #chkWebServiceHttpToTlsRedirect, #chkWebServiceUseSelfSignedTlsCertificate, #txtWebServiceTlsPort, #txtWebServiceTlsCertificatePath, #txtWebServiceTlsCertificatePassword")
            .prop("disabled", !on);
    });

    function updateReverseProxyACL() {
        const on = $("#chkEnableDnsOverUdpProxy, #chkEnableDnsOverTcpProxy, #chkEnableDnsOverHttp, #chkEnableDnsOverHttps")
            .toArray().some(el => el.checked);
        $("#txtReverseProxyNetworkACL").prop("disabled", !on);
    }

    function updateTlsCertFields() {
        const on = ["#chkEnableDnsOverTls","#chkEnableDnsOverHttps","#chkEnableDnsOverQuic"]
            .some(id => $(id).prop("checked"));
        $("#txtDnsTlsCertificatePath, #txtDnsTlsCertificatePassword").prop("disabled", !on);
    }

    function updateHttpRealIpField() {
        const on = $("#chkEnableDnsOverHttp").prop("checked") || $("#chkEnableDnsOverHttps").prop("checked");
        $("#txtDnsOverHttpRealIpHeader").prop("disabled", !on);
    }

    $("#chkEnableDnsOverUdpProxy").on("click", function () {
        $("#txtDnsOverUdpProxyPort").prop("disabled", !this.checked);
        updateReverseProxyACL();
    });

    $("#chkEnableDnsOverTcpProxy").on("click", function () {
        $("#txtDnsOverTcpProxyPort").prop("disabled", !this.checked);
        updateReverseProxyACL();
    });

    $("#chkEnableDnsOverHttp").on("click", function () {
        $("#txtDnsOverHttpPort").prop("disabled", !this.checked);
        updateReverseProxyACL();
        updateHttpRealIpField();
    });

    $("#chkEnableDnsOverTls").on("click", function () {
        $("#txtDnsOverTlsPort").prop("disabled", !this.checked);
        updateTlsCertFields();
    });

    $("#chkEnableDnsOverHttps").on("click", function () {
        $("#chkEnableDnsOverHttp3").prop("disabled", !this.checked);
        $("#txtDnsOverHttpsPort").prop("disabled", !this.checked);
        updateReverseProxyACL();
        updateTlsCertFields();
        updateHttpRealIpField();
    });

    $("#chkEnableDnsOverQuic").on("click", function () {
        $("#txtDnsOverQuicPort").prop("disabled", !this.checked);
        updateTlsCertFields();
    });

    $("#chkEnableConcurrentForwarding").on("click", function () {
        $("#txtForwarderConcurrency").prop("disabled", !this.checked);
    });

    $("input[type=radio][name=rdLoggingType]").on("change", function () {
        const on = $("input[name=rdLoggingType]:checked").val().toLowerCase() !== "none";
        $("#chkIgnoreResolverLogs, #chkLogQueries, #chkUseLocalTime, #txtLogFolderPath").prop("disabled", !on);
    });

    $("#chkServeStale").on("click", function () {
        const on = this.checked;
        $("#txtServeStaleTtl, #txtServeStaleAnswerTtl, #txtServeStaleResetTtl, #txtServeStaleMaxWaitTime").prop("disabled", !on);
    });

    $("#optQuickBlockList").on("change", function () {
        const selected = this.value;
        if (selected === "blank") return;
        if (selected === "none") { $("#txtBlockListUrls").val(""); return; }

        const entry = quickBlockLists.find(b => b.name === selected);
        if (!entry) return;

        const existing = selected.toLowerCase() === "default" ? "" : $("#txtBlockListUrls").val();
        const newList = entry.urls.reduce((acc, url) => acc.indexOf(url) < 0 ? acc + url + "\n" : acc, existing);
        $("#txtBlockListUrls").val(newList);
    });

    $("#optQuickForwarders").on("change", function () {
        const selected = this.value;
        if (selected === "blank") return;
        if (selected === "none") {
            $("#txtForwarders").val("");
            $("#rdForwarderProtocolUdp").prop("checked", true);
            return;
        }

        const entry = quickForwardersList.find(f => f.name === selected);
        if (!entry) return;

        $("#txtForwarders").val(entry.addresses.join("\n") + "\n");

        const protoMap = { TCP: "#rdForwarderProtocolTcp", TLS: "#rdForwarderProtocolTls", HTTPS: "#rdForwarderProtocolHttps", QUIC: "#rdForwarderProtocolQuic" };
        $(protoMap[entry.protocol?.toUpperCase()] ?? "#rdForwarderProtocolUdp").prop("checked", true);

        const proxyType = (entry.proxyType ?? "DefaultProxy").toUpperCase();
        if (proxyType === "SOCKS5" || proxyType === "HTTP") {
            $(proxyType === "SOCKS5" ? "#rdProxyTypeSocks5" : "#rdProxyTypeHttp").prop("checked", true);
            $("#txtProxyAddress").val(entry.proxyAddress).prop("disabled", false);
            $("#txtProxyPort").val(entry.proxyPort).prop("disabled", false);
            $("#txtProxyUsername").val(entry.proxyUsername).prop("disabled", false);
            $("#txtProxyPassword").val(entry.proxyPassword).prop("disabled", false);
        } else if (proxyType === "NONE") {
            $("#rdProxyTypeNone").prop("checked", true);
            $("#txtProxyAddress, #txtProxyPort, #txtProxyUsername, #txtProxyPassword").val("").prop("disabled", true);
        }
    });

    $("input[type=radio][name=rdStatType]").on("change", function () {
        const type = $("input[name=rdStatType]:checked").val();
        if (type === "custom") {
            $("#divCustomDayWise").show();
            if (!$("#dpCustomDayWiseStart").val()) { $("#dpCustomDayWiseStart").trigger("focus"); return; }
            if (!$("#dpCustomDayWiseEnd").val())   { $("#dpCustomDayWiseEnd").trigger("focus");   return; }
        } else {
            $("#divCustomDayWise").hide();
        }
        refreshDashboard();
    });

    $("#btnCustomDayWise").on("click", () => refreshDashboard());

    applyTheme();
});

function showAbout() {
    if ($("#pageLogin").is(":visible")) {
        window.open("https://technitium.com/aboutus.html", "_blank");
        return;
    }

    $([
        "#mainPanelTabListDashboard","#mainPanelTabPaneDashboard",
        "#mainPanelTabListZones","#mainPanelTabPaneZones",
        "#mainPanelTabListCachedZones","#mainPanelTabPaneCachedZones",
        "#mainPanelTabListAllowedZones","#mainPanelTabPaneAllowedZones",
        "#mainPanelTabListBlockedZones","#mainPanelTabPaneBlockedZones",
        "#mainPanelTabListApps","#mainPanelTabPaneApps",
        "#mainPanelTabListDnsClient","#mainPanelTabPaneDnsClient",
        "#mainPanelTabListSettings","#mainPanelTabPaneSettings",
        "#mainPanelTabListAdmin","#mainPanelTabPaneAdmin",
        "#mainPanelTabListLogs","#mainPanelTabPaneLogs"
    ].join(",")).removeClass("active");

    $("#mainPanelTabListAbout, #mainPanelTabPaneAbout").addClass("active");

    setTimeout(() => window.scroll({ top: 0, left: 0, behavior: "smooth" }), 500);
}

function checkForUpdate() {
    HTTPRequest({
        url: "api/user/checkForUpdate?token=" + sessionData.token,
        success(responseJSON) {
            const r = responseJSON.response;
            const lnk = $("#lnkUpdateAvailable");
            if (!r.updateAvailable) { lnk.hide(); return; }

            $("#lblUpdateVersion").text(r.updateVersion);
            $("#lblCurrentVersion").text(r.currentVersion);

            const title = r.updateTitle ?? "New Update Available!";
            lnk.text(title);
            $("#lblUpdateAvailableTitle").text(title);

            r.updateMessage  ? $("#lblUpdateMessage").text(r.updateMessage).show()          : $("#lblUpdateMessage").hide();
            r.downloadLink   ? $("#lnkUpdateDownload").attr("href", r.downloadLink).show()  : $("#lnkUpdateDownload").hide();
            r.instructionsLink ? $("#lnkUpdateInstructions").attr("href", r.instructionsLink).show() : $("#lnkUpdateInstructions").hide();
            r.changeLogLink  ? $("#lnkUpdateChangeLog").attr("href", r.changeLogLink).show(): $("#lnkUpdateChangeLog").hide();

            lnk.show();
        },
        invalidToken: showPageLogin
    });
}

function loadQuickBlockLists() {
    $.getJSON("json/quick-block-lists-custom.json")
        .then(loadQuickBlockListsFrom)
        .catch(() => $.getJSON("json/quick-block-lists-builtin.json").then(loadQuickBlockListsFrom));
}

function loadQuickBlockListsFrom(data) {
    quickBlockLists = data;
    $("#optQuickBlockList").html(
        '<option value="blank" selected></option><option value="none">None</option>' +
        data.map(b => `<option>${htmlEncode(b.name)}</option>`).join("")
    );
}

function loadQuickForwardersList() {
    $.getJSON("json/quick-forwarders-list-custom.json")
        .then(loadQuickForwardersListFrom)
        .catch(() => $.getJSON("json/quick-forwarders-list-builtin.json").then(loadQuickForwardersListFrom));
}

function loadQuickForwardersListFrom(data) {
    quickForwardersList = data;
    $("#optQuickForwarders").html(
        '<option value="blank" selected></option><option value="none">None</option>' +
        data.map(f => `<option>${htmlEncode(f.name)}</option>`).join("")
    );
}

function refreshDnsSettings() {
    const loader = $("#divDnsSettingsLoader");
    const panel  = $("#divDnsSettings");
    panel.hide();
    loader.show();

    HTTPRequest({
        url: "api/settings/get?token=" + sessionData.token,
        success(responseJSON) {
            updateDnsSettingsDataAndGui(responseJSON);
            loadDnsSettings(responseJSON);
            checkForReverseProxy(responseJSON);

            [
                "#divSettingsGeneralLocalParameters","#divSettingsGeneralDefaultParameters",
                "#divSettingsGeneralDnsApps","#divSettingsGeneralIpv6",
                "#divSettingsGeneralUdpSocketPool","#divSettingsGeneralEDns",
                "#divSettingsGeneralDnssec","#divSettingsGeneralEDnsClientSubnet",
                "#divSettingsGeneralRateLimiting","#divSettingsGeneralAdvancedOptions",
                "#settingsTabListWebService","#settingsTabListOptionalProtocols",
                "#settingsTabListTsig","#settingsTabListRecursion","#settingsTabListCache",
                "#settingsTabListBlocking","#settingsTabListProxyForwarders","#settingsTabListLogging",
                "#btnSettingsFlushCache","#btnShowBackupSettingsModal","#btnShowRestoreSettingsModal"
            ].forEach(sel => $(sel).show());

            loader.hide();
            panel.show();
        },
        error()  { loader.hide(); panel.show(); },
        invalidToken: showPageLogin,
        objLoaderPlaceholder: loader
    });
}

function getArrayAsString(array) {
    return array ? array.join("\r\n") + (array.length ? "\r\n" : "") : "";
}

function updateDnsSettingsDataAndGui(responseJSON) {
    const r = responseJSON.response;
    sessionData.info.dnsServerDomain = r.dnsServerDomain;
    sessionData.info.uptimestamp      = r.uptimestamp;

    document.title = `${r.dnsServerDomain} - Zenitium DNS Server v${r.version}`;
    $("#lblAboutVersion").text(r.version);
    $("#lblAboutUptime").text(moment(r.uptimestamp).local().format("lll") + " (" + moment(r.uptimestamp).fromNow() + ")");
    $("#lblDnsServerDomain").text(" - " + r.dnsServerDomain);
}

function loadDnsSettings(responseJSON) {
    const r = responseJSON.response;

    // general
    $("#txtDnsServerDomain").val(r.dnsServerDomain);
    $("#txtDnsServerLocalEndPoints").val(r.dnsServerLocalEndPoints ? getArrayAsString(r.dnsServerLocalEndPoints) : "");
    $("#txtDnsServerIPv4SourceAddresses").val(getArrayAsString(r.dnsServerIPv4SourceAddresses));
    $("#txtDnsServerIPv6SourceAddresses").val(getArrayAsString(r.dnsServerIPv6SourceAddresses));
    $("#txtDefaultRecordTtl").val(r.defaultRecordTtl);
    $("#txtDefaultNsRecordTtl").val(r.defaultNsRecordTtl);
    $("#txtDefaultSoaRecordTtl").val(r.defaultSoaRecordTtl);

    sessionData.info.defaultRecordTtl   = r.defaultRecordTtl;
    sessionData.info.defaultNsRecordTtl = r.defaultNsRecordTtl;
    sessionData.info.defaultSoaRecordTtl= r.defaultSoaRecordTtl;

    $("#txtDefaultResponsiblePerson").val(r.defaultResponsiblePerson);
    $("#chkUseSoaSerialDateScheme").prop("checked", r.useSoaSerialDateScheme);
    $("#txtMinSoaRefresh").val(r.minSoaRefresh);
    $("#txtMinSoaRetry").val(r.minSoaRetry);
    $("#txtZoneTransferAllowedNetworks").val(getArrayAsString(r.zoneTransferAllowedNetworks));
    $("#txtNotifyAllowedNetworks").val(getArrayAsString(r.notifyAllowedNetworks));
    $("#chkDnsAppsEnableAutomaticUpdate").prop("checked", r.dnsAppsEnableAutomaticUpdate);
    $("#chkPreferIPv6").prop("checked", r.preferIPv6);
    $("#chkEnableUdpSocketPool").prop("checked", r.enableUdpSocketPool);
    $("#txtUdpSocketPoolExcludedPorts").prop("disabled", !r.enableUdpSocketPool)
        .val(getArrayAsString(r.socketPoolExcludedPorts));
    $("#txtEdnsUdpPayloadSize").val(r.udpPayloadSize);
    $("#chkDnssecValidation").prop("checked", r.dnssecValidation);
    $("#chkEDnsClientSubnet").prop("checked", r.eDnsClientSubnet);

    $("#txtEDnsClientSubnetIPv4PrefixLength, #txtEDnsClientSubnetIPv6PrefixLength, #txtEDnsClientSubnetIpv4Override, #txtEDnsClientSubnetIpv6Override")
        .prop("disabled", !r.eDnsClientSubnet);
    $("#txtEDnsClientSubnetIPv4PrefixLength").val(r.eDnsClientSubnetIPv4PrefixLength);
    $("#txtEDnsClientSubnetIPv6PrefixLength").val(r.eDnsClientSubnetIPv6PrefixLength);
    $("#txtEDnsClientSubnetIpv4Override").val(r.eDnsClientSubnetIpv4Override);
    $("#txtEDnsClientSubnetIpv6Override").val(r.eDnsClientSubnetIpv6Override);

    $("#tableQpmPrefixLimitsIPv4").html("");
    r.qpmPrefixLimitsIPv4?.forEach(row => addQpmPrefixLimitsIPv4Row(row.prefix, row.udpLimit, row.tcpLimit));

    $("#tableQpmPrefixLimitsIPv6").html("");
    r.qpmPrefixLimitsIPv6?.forEach(row => addQpmPrefixLimitsIPv6Row(row.prefix, row.udpLimit, row.tcpLimit));

    $("#txtQpmLimitSampleMinutes").val(r.qpmLimitSampleMinutes);
    $("#txtQpmLimitUdpTruncation").val(r.qpmLimitUdpTruncationPercentage);
    $("#txtQpmLimitBypassList").val(getArrayAsString(r.qpmLimitBypassList));
    $("#txtClientTimeout").val(r.clientTimeout);
    $("#txtTcpSendTimeout").val(r.tcpSendTimeout);
    $("#txtTcpReceiveTimeout").val(r.tcpReceiveTimeout);
    $("#txtQuicIdleTimeout").val(r.quicIdleTimeout);
    $("#txtQuicMaxInboundStreams").val(r.quicMaxInboundStreams);
    $("#txtListenBacklog").val(r.listenBacklog);
    $("#txtMaxConcurrentResolutionsPerCore").val(r.maxConcurrentResolutionsPerCore);

    // web service
    $("#txtWebServiceLocalAddresses").val(r.webServiceLocalAddresses ? getArrayAsString(r.webServiceLocalAddresses) : "");
    $("#txtWebServiceHttpPort").val(r.webServiceHttpPort);
    $("#chkWebServiceEnableTls").prop("checked", r.webServiceEnableTls);

    $("#chkWebServiceEnableHttp3, #chkWebServiceHttpToTlsRedirect, #chkWebServiceUseSelfSignedTlsCertificate, #txtWebServiceTlsPort, #txtWebServiceTlsCertificatePath, #txtWebServiceTlsCertificatePassword")
        .prop("disabled", !r.webServiceEnableTls);

    $("#chkWebServiceEnableHttp3").prop("checked", r.webServiceEnableHttp3);
    $("#chkWebServiceHttpToTlsRedirect").prop("checked", r.webServiceHttpToTlsRedirect);
    $("#chkWebServiceUseSelfSignedTlsCertificate").prop("checked", r.webServiceUseSelfSignedTlsCertificate);
    $("#txtWebServiceTlsPort").val(r.webServiceTlsPort);
    $("#txtWebServiceTlsCertificatePath").val(r.webServiceTlsCertificatePath);
    $("#txtWebServiceTlsCertificatePassword").val(r.webServiceTlsCertificatePath ? r.webServiceTlsCertificatePassword : "");
    $("#txtWebServiceRealIpHeader").val(r.webServiceRealIpHeader);
    $("#lblWebServiceRealIpHeader").text(r.webServiceRealIpHeader);
    $("#lblWebServiceRealIpNginx").text(`proxy_set_header ${r.webServiceRealIpHeader} $remote_addr;`);

    // optional protocols
    const proto = {
        udpProxy: r.enableDnsOverUdpProxy, tcpProxy: r.enableDnsOverTcpProxy,
        http: r.enableDnsOverHttp, tls: r.enableDnsOverTls,
        https: r.enableDnsOverHttps, quic: r.enableDnsOverQuic
    };

    $("#chkEnableDnsOverUdpProxy").prop("checked", proto.udpProxy);
    $("#chkEnableDnsOverTcpProxy").prop("checked", proto.tcpProxy);
    $("#chkEnableDnsOverHttp").prop("checked", proto.http);
    $("#chkEnableDnsOverTls").prop("checked", proto.tls);
    $("#chkEnableDnsOverHttps").prop("checked", proto.https);
    $("#chkEnableDnsOverHttp3").prop("disabled", !proto.https).prop("checked", r.enableDnsOverHttp3);
    $("#chkEnableDnsOverQuic").prop("checked", proto.quic);

    $("#txtDnsOverUdpProxyPort").prop("disabled", !proto.udpProxy).val(r.dnsOverUdpProxyPort);
    $("#txtDnsOverTcpProxyPort").prop("disabled", !proto.tcpProxy).val(r.dnsOverTcpProxyPort);
    $("#txtDnsOverHttpPort").prop("disabled", !proto.http).val(r.dnsOverHttpPort);
    $("#txtDnsOverTlsPort").prop("disabled", !proto.tls).val(r.dnsOverTlsPort);
    $("#txtDnsOverHttpsPort").prop("disabled", !proto.https).val(r.dnsOverHttpsPort);
    $("#txtDnsOverQuicPort").prop("disabled", !proto.quic).val(r.dnsOverQuicPort);

    $("#txtReverseProxyNetworkACL")
        .prop("disabled", !proto.udpProxy && !proto.tcpProxy && !proto.http && !proto.https)
        .val(getArrayAsString(r.reverseProxyNetworkACL));

    $("#txtDnsTlsCertificatePath, #txtDnsTlsCertificatePassword")
        .prop("disabled", !proto.tls && !proto.https && !proto.quic);
    $("#txtDnsTlsCertificatePath").val(r.dnsTlsCertificatePath);
    $("#txtDnsTlsCertificatePassword").val(r.dnsTlsCertificatePath ? r.dnsTlsCertificatePassword : "");

    const httpHost = window.location.hostname;
    $("#lblDoHHost").text(httpHost + (r.dnsOverHttpPort == 80 ? "" : ":" + r.dnsOverHttpPort));
    $("#lblDoTHost").text("tls-certificate-domain:" + r.dnsOverTlsPort);
    $("#lblDoQHost").text("tls-certificate-domain:" + r.dnsOverQuicPort);
    $("#lblDoHsHost").text("tls-certificate-domain" + (r.dnsOverHttpsPort == 443 ? "" : ":" + r.dnsOverHttpsPort));

    $("#txtDnsOverHttpRealIpHeader").prop("disabled", !proto.http && !proto.https).val(r.dnsOverHttpRealIpHeader);
    $("#lblDnsOverHttpRealIpHeader").text(r.dnsOverHttpRealIpHeader);
    $("#lblDnsOverHttpRealIpNginx").text(`proxy_set_header ${r.dnsOverHttpRealIpHeader} $remote_addr;`);

    // tsig
    $("#tableTsigKeys").html("");
    r.tsigKeys?.forEach(k => addTsigKeyRow(k.keyName, k.sharedSecret, k.algorithmName));

    // recursion
    $("#txtRecursionNetworkACL").prop("disabled", true);
    const recursionRadioMap = {
        Allow: "#rdRecursionAllow",
        AllowOnlyForPrivateNetworks: "#rdRecursionAllowOnlyForPrivateNetworks",
        UseSpecifiedNetworkACL: "#rdRecursionUseSpecifiedNetworkACL",
        Deny: "#rdRecursionDeny"
    };
    $(recursionRadioMap[r.recursion] ?? "#rdRecursionDeny").prop("checked", true);
    if (r.recursion === "UseSpecifiedNetworkACL")
        $("#txtRecursionNetworkACL").prop("disabled", false);
    $("#txtRecursionNetworkACL").val(getArrayAsString(r.recursionNetworkACL));

    $("#chkRandomizeName").prop("checked", r.randomizeName);
    $("#chkQnameMinimization").prop("checked", r.qnameMinimization);
    $("#txtResolverRetries").val(r.resolverRetries);
    $("#txtResolverTimeout").val(r.resolverTimeout);
    $("#txtResolverConcurrency").val(r.resolverConcurrency);
    $("#txtResolverMaxStackCount").val(r.resolverMaxStackCount);

    // cache
    $("#chkSaveCache").prop("checked", r.saveCache);
    $("#chkServeStale").prop("checked", r.serveStale);
    $("#txtServeStaleTtl, #txtServeStaleAnswerTtl, #txtServeStaleResetTtl, #txtServeStaleMaxWaitTime")
        .prop("disabled", !r.serveStale);
    $("#txtServeStaleTtl").val(r.serveStaleTtl);
    $("#txtServeStaleAnswerTtl").val(r.serveStaleAnswerTtl);
    $("#txtServeStaleResetTtl").val(r.serveStaleResetTtl);
    $("#txtServeStaleMaxWaitTime").val(r.serveStaleMaxWaitTime);
    $("#txtCacheMaximumEntries").val(r.cacheMaximumEntries);
    $("#txtCacheMinimumRecordTtl").val(r.cacheMinimumRecordTtl);
    $("#txtCacheMaximumRecordTtl").val(r.cacheMaximumRecordTtl);
    $("#txtCacheNegativeRecordTtl").val(r.cacheNegativeRecordTtl);
    $("#txtCacheFailureRecordTtl").val(r.cacheFailureRecordTtl);
    $("#txtCachePrefetchEligibility").val(r.cachePrefetchEligibility);
    $("#txtCachePrefetchTrigger").val(r.cachePrefetchTrigger);
    $("#txtCachePrefetchSampleIntervalInMinutes").val(r.cachePrefetchSampleIntervalInMinutes);
    $("#txtCachePrefetchSampleEligibilityHitsPerHour").val(r.cachePrefetchSampleEligibilityHitsPerHour);

    // blocking
    $("#chkEnableBlocking").prop("checked", r.enableBlocking);
    ["#chkAllowTxtBlockingReport","#txtTemporaryDisableBlockingMinutes","#btnTemporaryDisableBlockingNow",
        "#txtBlockingBypassList","#rdBlockingTypeAnyAddress","#rdBlockingTypeNxDomain",
        "#rdBlockingTypeCustomAddress","#txtBlockListUrls","#optQuickBlockList",
        "#txtBlockListUpdateIntervalHours"
    ].forEach(sel => $(sel).prop("disabled", !r.enableBlocking));

    $("#chkAllowTxtBlockingReport").prop("checked", r.allowTxtBlockingReport);
    $("#lblTemporaryDisableBlockingTill").text(
        r.temporaryDisableBlockingTill
            ? moment(r.temporaryDisableBlockingTill).local().format("YYYY-MM-DD HH:mm:ss")
            : "Not Set"
    );
    $("#txtTemporaryDisableBlockingMinutes").val("");
    $("#txtCustomBlockingAddresses").prop("disabled", true);
    $("#txtBlockingBypassList").val(getArrayAsString(r.blockingBypassList));

    const blockingRadioMap = {
        NxDomain:      "#rdBlockingTypeNxDomain",
        CustomAddress: "#rdBlockingTypeCustomAddress",
        AnyAddress:    "#rdBlockingTypeAnyAddress"
    };
    $(blockingRadioMap[r.blockingType] ?? "#rdBlockingTypeAnyAddress").prop("checked", true);
    if (r.blockingType === "CustomAddress")
        $("#txtCustomBlockingAddresses").prop("disabled", !r.enableBlocking);
    $("#txtCustomBlockingAddresses").val(getArrayAsString(r.customBlockingAddresses));
    $("#txtBlockingAnswerTtl").val(r.blockingAnswerTtl);

    if (!r.blockListUrls) {
        $("#txtBlockListUrls").val("");
        $("#btnUpdateBlockListsNow").prop("disabled", true);
    } else {
        $("#txtBlockListUrls").val(getArrayAsString(r.blockListUrls));
        $("#btnUpdateBlockListsNow").prop("disabled", !r.enableBlocking);
    }
    $("#optQuickBlockList").val("blank");
    $("#txtBlockListUpdateIntervalHours").val(r.blockListUpdateIntervalHours);

    if (!r.blockListNextUpdatedOn) {
        $("#lblBlockListNextUpdatedOn").text("Not Scheduled");
    } else {
        const next = moment(r.blockListNextUpdatedOn);
        $("#lblBlockListNextUpdatedOn").text(moment().utc().isBefore(next)
            ? next.local().format("YYYY-MM-DD HH:mm:ss")
            : "Updating Now");
    }

    // proxy & forwarders
    if (!r.proxy) {
        $("#rdProxyTypeNone").prop("checked", true);
        $("#txtProxyAddress, #txtProxyPort, #txtProxyUsername, #txtProxyPassword, #txtProxyBypassList")
            .prop("disabled", true).val("");
    } else {
        const proxyTypeMap = { http: "#rdProxyTypeHttp", socks5: "#rdProxyTypeSocks5" };
        $(proxyTypeMap[r.proxy.type.toLowerCase()] ?? "#rdProxyTypeNone").prop("checked", true);
        $("#txtProxyAddress").val(r.proxy.address).prop("disabled", false);
        $("#txtProxyPort").val(r.proxy.port).prop("disabled", false);
        $("#txtProxyUsername").val(r.proxy.username).prop("disabled", false);
        $("#txtProxyPassword").val(r.proxy.password).prop("disabled", false);
        $("#txtProxyBypassList").val(getArrayAsString(r.proxy.bypass)).prop("disabled", false);
    }

    $("#txtForwarders").val(r.forwarders ? getArrayAsString(r.forwarders) : "");
    $("#optQuickForwarders").val("blank");

    const fwdProtoMap = { tcp: "#rdForwarderProtocolTcp", tls: "#rdForwarderProtocolTls", https: "#rdForwarderProtocolHttps", quic: "#rdForwarderProtocolQuic" };
    $(fwdProtoMap[r.forwarderProtocol.toLowerCase()] ?? "#rdForwarderProtocolUdp").prop("checked", true);

    $("#chkEnableConcurrentForwarding").prop("checked", r.concurrentForwarding);
    $("#txtForwarderConcurrency").prop("disabled", !r.concurrentForwarding).val(r.forwarderConcurrency);
    $("#txtForwarderRetries").val(r.forwarderRetries);
    $("#txtForwarderTimeout").val(r.forwarderTimeout);

    // logging
    const loggingMap = { file: "#rdLoggingTypeFile", console: "#rdLoggingTypeConsole", fileandconsole: "#rdLoggingTypeFileAndConsole" };
    const loggingOn = r.loggingType.toLowerCase() !== "none";
    $(loggingMap[r.loggingType.toLowerCase()] ?? "#rdLoggingTypeNone").prop("checked", true);
    $("#chkIgnoreResolverLogs, #chkLogQueries, #chkUseLocalTime, #txtLogFolderPath").prop("disabled", !loggingOn);
    $("#chkIgnoreResolverLogs").prop("checked", r.ignoreResolverLogs);
    $("#chkLogQueries").prop("checked", r.logQueries);
    $("#chkUseLocalTime").prop("checked", r.useLocalTime);
    $("#txtLogFolderPath").val(r.logFolder);
    $("#txtMaxLogFileDays").val(r.maxLogFileDays);
    $("#chkEnableInMemoryStats").prop("checked", r.enableInMemoryStats);
    $("#txtMaxStatFileDays").val(r.maxStatFileDays);
}

function saveDnsSettings(objBtn) {
    const params = new URLSearchParams();

    // ── general ──
    const dnsServerDomain = $("#txtDnsServerDomain").val();
    if (!dnsServerDomain) {
        showAlert("warning", "Missing!", "Please enter server domain name.");
        $("#txtDnsServerDomain").trigger("focus");
        return;
    }

    let dnsServerLocalEndPoints = cleanTextList($("#txtDnsServerLocalEndPoints").val());
    if (!dnsServerLocalEndPoints || dnsServerLocalEndPoints === ",")
        dnsServerLocalEndPoints = "0.0.0.0:53,[::]:53";
    else
        $("#txtDnsServerLocalEndPoints").val(dnsServerLocalEndPoints.replace(/,/g, "\n"));

    let dnsServerIPv4SourceAddresses = cleanTextList($("#txtDnsServerIPv4SourceAddresses").val());
    if (!dnsServerIPv4SourceAddresses || dnsServerIPv4SourceAddresses === ",") dnsServerIPv4SourceAddresses = false;

    let dnsServerIPv6SourceAddresses = cleanTextList($("#txtDnsServerIPv6SourceAddresses").val());
    if (!dnsServerIPv6SourceAddresses || dnsServerIPv6SourceAddresses === ",") dnsServerIPv6SourceAddresses = false;

    params.set("dnsServerDomain", dnsServerDomain);
    params.set("dnsServerLocalEndPoints", dnsServerLocalEndPoints);
    params.set("dnsServerIPv4SourceAddresses", dnsServerIPv4SourceAddresses || "");
    params.set("dnsServerIPv6SourceAddresses", dnsServerIPv6SourceAddresses || "");
    params.set("defaultRecordTtl", $("#txtDefaultRecordTtl").val());
    params.set("defaultNsRecordTtl", $("#txtDefaultNsRecordTtl").val());
    params.set("defaultSoaRecordTtl", $("#txtDefaultSoaRecordTtl").val());
    params.set("defaultResponsiblePerson", $("#txtDefaultResponsiblePerson").val());
    params.set("useSoaSerialDateScheme", $("#chkUseSoaSerialDateScheme").prop("checked"));
    params.set("minSoaRefresh", $("#txtMinSoaRefresh").val());
    params.set("minSoaRetry", $("#txtMinSoaRetry").val());

    const requiredFields = [
        ["#txtQpmLimitSampleMinutes", "Queries Per Minute (QPM) sample value"],
        ["#txtQpmLimitUdpTruncation", "QPM limit UDP truncation percentage value"],
        ["#txtClientTimeout", "Client Timeout"],
        ["#txtTcpSendTimeout", "TCP Send Timeout"],
        ["#txtTcpReceiveTimeout", "TCP Receive Timeout"],
        ["#txtQuicIdleTimeout", "QUIC Idle Timeout"],
        ["#txtQuicMaxInboundStreams", "QUIC Max Inbound Streams"],
        ["#txtListenBacklog", "Listen Backlog"],
        ["#txtMaxConcurrentResolutionsPerCore", "Max Concurrent Resolutions"],
        ["#txtDnsOverUdpProxyPort", "DNS-over-UDP-PROXY Port"],
        ["#txtDnsOverTcpProxyPort", "DNS-over-TCP-PROXY Port"],
        ["#txtDnsOverHttpPort", "DNS-over-HTTP Port"],
        ["#txtDnsOverTlsPort", "DNS-over-TLS Port"],
        ["#txtDnsOverHttpsPort", "DNS-over-HTTPS Port"],
        ["#txtDnsOverQuicPort", "DNS-over-QUIC Port"],
        ["#txtResolverRetries", "Resolver Retries"],
        ["#txtResolverTimeout", "Resolver Timeout"],
        ["#txtResolverConcurrency", "Resolver Concurrency"],
        ["#txtResolverMaxStackCount", "Resolver Max Stack Count"],
        ["#txtCacheMaximumEntries", "cache maximum entries"],
        ["#txtCacheMinimumRecordTtl", "cache minimum record TTL"],
        ["#txtCacheMaximumRecordTtl", "cache maximum record TTL"],
        ["#txtCacheNegativeRecordTtl", "cache negative record TTL"],
        ["#txtCacheFailureRecordTtl", "cache failure record TTL"],
        ["#txtCachePrefetchEligibility", "cache prefetch eligibility"],
        ["#txtCachePrefetchTrigger", "cache prefetch trigger"],
        ["#txtCachePrefetchSampleIntervalInMinutes", "cache auto prefetch sample interval"],
        ["#txtCachePrefetchSampleEligibilityHitsPerHour", "cache auto prefetch sample eligibility"],
        ["#txtForwarderRetries", "Forwarder Retries"],
        ["#txtForwarderTimeout", "Forwarder Timeout"],
        ["#txtForwarderConcurrency", "Forwarder Concurrency"],
    ];

    for (const [sel, label] of requiredFields) {
        if (!$(sel).val()) {
            showAlert("warning", "Missing!", `Please enter a value for ${label}.`);
            $(sel).trigger("focus");
            return;
        }
    }

    const listFields = [
        ["#txtZoneTransferAllowedNetworks", "zoneTransferAllowedNetworks"],
        ["#txtNotifyAllowedNetworks",       "notifyAllowedNetworks"],
        ["#txtUdpSocketPoolExcludedPorts",  "socketPoolExcludedPorts"],
        ["#txtQpmLimitBypassList",          "qpmLimitBypassList"],
        ["#txtReverseProxyNetworkACL",       "reverseProxyNetworkACL"],
        ["#txtRecursionNetworkACL",          "recursionNetworkACL"],
        ["#txtBlockingBypassList",           "blockingBypassList"],
        ["#txtCustomBlockingAddresses",      "customBlockingAddresses"],
        ["#txtBlockListUrls",                "blockListUrls"],
    ];

    for (const [sel, key] of listFields) {
        let val = cleanTextList($(sel).val());
        if (!val || val === ",") val = false;
        else $(sel).val(val.replace(/,/g, "\n") + "\n");
        params.set(key, val || "");
    }

    params.set("dnsAppsEnableAutomaticUpdate", $("#chkDnsAppsEnableAutomaticUpdate").prop("checked"));
    params.set("preferIPv6", $("#chkPreferIPv6").prop("checked"));
    params.set("enableUdpSocketPool", $("#chkEnableUdpSocketPool").prop("checked"));
    params.set("udpPayloadSize", $("#txtEdnsUdpPayloadSize").val());
    params.set("dnssecValidation", $("#chkDnssecValidation").prop("checked"));
    params.set("eDnsClientSubnet", $("#chkEDnsClientSubnet").prop("checked"));
    params.set("eDnsClientSubnetIPv4PrefixLength", $("#txtEDnsClientSubnetIPv4PrefixLength").val());
    params.set("eDnsClientSubnetIPv6PrefixLength", $("#txtEDnsClientSubnetIPv6PrefixLength").val());
    params.set("eDnsClientSubnetIpv4Override", $("#txtEDnsClientSubnetIpv4Override").val());
    params.set("eDnsClientSubnetIpv6Override", $("#txtEDnsClientSubnetIpv6Override").val());

    const qpmIPv4 = serializeTableData($("#tableQpmPrefixLimitsIPv4"), 3);
    const qpmIPv6 = serializeTableData($("#tableQpmPrefixLimitsIPv6"), 3);
    const tsigKeys = serializeTableData($("#tableTsigKeys"), 3);
    if (qpmIPv4 === false || qpmIPv6 === false || tsigKeys === false) return;

    params.set("qpmPrefixLimitsIPv4", qpmIPv4.length ? qpmIPv4 : "");
    params.set("qpmPrefixLimitsIPv6", qpmIPv6.length ? qpmIPv6 : "");
    params.set("qpmLimitSampleMinutes", $("#txtQpmLimitSampleMinutes").val());
    params.set("qpmLimitUdpTruncationPercentage", $("#txtQpmLimitUdpTruncation").val());
    params.set("clientTimeout", $("#txtClientTimeout").val());
    params.set("tcpSendTimeout", $("#txtTcpSendTimeout").val());
    params.set("tcpReceiveTimeout", $("#txtTcpReceiveTimeout").val());
    params.set("quicIdleTimeout", $("#txtQuicIdleTimeout").val());
    params.set("quicMaxInboundStreams", $("#txtQuicMaxInboundStreams").val());
    params.set("listenBacklog", $("#txtListenBacklog").val());
    params.set("maxConcurrentResolutionsPerCore", $("#txtMaxConcurrentResolutionsPerCore").val());

    // web service
    let wsLocalAddresses = cleanTextList($("#txtWebServiceLocalAddresses").val());
    if (!wsLocalAddresses || wsLocalAddresses === ",") wsLocalAddresses = "0.0.0.0,[::]";
    else $("#txtWebServiceLocalAddresses").val(wsLocalAddresses.replace(/,/g, "\n"));
    params.set("webServiceLocalAddresses", wsLocalAddresses);
    params.set("webServiceHttpPort", $("#txtWebServiceHttpPort").val() || 5380);
    params.set("webServiceEnableTls", $("#chkWebServiceEnableTls").prop("checked"));
    params.set("webServiceEnableHttp3", $("#chkWebServiceEnableHttp3").prop("checked"));
    params.set("webServiceHttpToTlsRedirect", $("#chkWebServiceHttpToTlsRedirect").prop("checked"));
    params.set("webServiceUseSelfSignedTlsCertificate", $("#chkWebServiceUseSelfSignedTlsCertificate").prop("checked"));
    params.set("webServiceTlsPort", $("#txtWebServiceTlsPort").val());
    params.set("webServiceTlsCertificatePath", $("#txtWebServiceTlsCertificatePath").val());
    params.set("webServiceTlsCertificatePassword", $("#txtWebServiceTlsCertificatePassword").val());
    params.set("webServiceRealIpHeader", $("#txtWebServiceRealIpHeader").val());

    // optional protocols
    params.set("enableDnsOverUdpProxy", $("#chkEnableDnsOverUdpProxy").prop("checked"));
    params.set("enableDnsOverTcpProxy", $("#chkEnableDnsOverTcpProxy").prop("checked"));
    params.set("enableDnsOverHttp", $("#chkEnableDnsOverHttp").prop("checked"));
    params.set("enableDnsOverTls", $("#chkEnableDnsOverTls").prop("checked"));
    params.set("enableDnsOverHttps", $("#chkEnableDnsOverHttps").prop("checked"));
    params.set("enableDnsOverHttp3", $("#chkEnableDnsOverHttp3").prop("checked"));
    params.set("enableDnsOverQuic", $("#chkEnableDnsOverQuic").prop("checked"));
    params.set("dnsOverUdpProxyPort", $("#txtDnsOverUdpProxyPort").val());
    params.set("dnsOverTcpProxyPort", $("#txtDnsOverTcpProxyPort").val());
    params.set("dnsOverHttpPort", $("#txtDnsOverHttpPort").val());
    params.set("dnsOverTlsPort", $("#txtDnsOverTlsPort").val());
    params.set("dnsOverHttpsPort", $("#txtDnsOverHttpsPort").val());
    params.set("dnsOverQuicPort", $("#txtDnsOverQuicPort").val());
    params.set("dnsTlsCertificatePath", $("#txtDnsTlsCertificatePath").val());
    params.set("dnsTlsCertificatePassword", $("#txtDnsTlsCertificatePassword").val());
    params.set("dnsOverHttpRealIpHeader", $("#txtDnsOverHttpRealIpHeader").val());
    params.set("tsigKeys", tsigKeys.length ? tsigKeys : "");

    // recursion
    params.set("recursion", $("input[name=rdRecursion]:checked").val());
    params.set("randomizeName", $("#chkRandomizeName").prop("checked"));
    params.set("qnameMinimization", $("#chkQnameMinimization").prop("checked"));
    params.set("resolverRetries", $("#txtResolverRetries").val());
    params.set("resolverTimeout", $("#txtResolverTimeout").val());
    params.set("resolverConcurrency", $("#txtResolverConcurrency").val());
    params.set("resolverMaxStackCount", $("#txtResolverMaxStackCount").val());

    // cache
    params.set("saveCache", $("#chkSaveCache").prop("checked"));
    params.set("serveStale", $("#chkServeStale").prop("checked"));
    params.set("serveStaleTtl", $("#txtServeStaleTtl").val());
    params.set("serveStaleAnswerTtl", $("#txtServeStaleAnswerTtl").val());
    params.set("serveStaleResetTtl", $("#txtServeStaleResetTtl").val());
    params.set("serveStaleMaxWaitTime", $("#txtServeStaleMaxWaitTime").val());
    params.set("cacheMaximumEntries", $("#txtCacheMaximumEntries").val());
    params.set("cacheMinimumRecordTtl", $("#txtCacheMinimumRecordTtl").val());
    params.set("cacheMaximumRecordTtl", $("#txtCacheMaximumRecordTtl").val());
    params.set("cacheNegativeRecordTtl", $("#txtCacheNegativeRecordTtl").val());
    params.set("cacheFailureRecordTtl", $("#txtCacheFailureRecordTtl").val());
    params.set("cachePrefetchEligibility", $("#txtCachePrefetchEligibility").val());
    params.set("cachePrefetchTrigger", $("#txtCachePrefetchTrigger").val());
    params.set("cachePrefetchSampleIntervalInMinutes", $("#txtCachePrefetchSampleIntervalInMinutes").val());
    params.set("cachePrefetchSampleEligibilityHitsPerHour", $("#txtCachePrefetchSampleEligibilityHitsPerHour").val());

    // blocking
    params.set("enableBlocking", $("#chkEnableBlocking").prop("checked"));
    params.set("allowTxtBlockingReport", $("#chkAllowTxtBlockingReport").prop("checked"));
    params.set("blockingType", $("input[name=rdBlockingType]:checked").val());
    params.set("blockingAnswerTtl", $("#txtBlockingAnswerTtl").val());
    params.set("blockListUpdateIntervalHours", $("#txtBlockListUpdateIntervalHours").val());

    // proxy & forwarders
    const proxyType = $("input[name=rdProxyType]:checked").val().toLowerCase();
    params.set("proxyType", proxyType);
    if (proxyType !== "none") {
        const proxyAddress = $("#txtProxyAddress").val();
        const proxyPort    = $("#txtProxyPort").val();
        if (!proxyAddress) { showAlert("warning", "Missing!", "Please enter proxy server address."); $("#txtProxyAddress").trigger("focus"); return; }
        if (!proxyPort)    { showAlert("warning", "Missing!", "Please enter proxy server port.");    $("#txtProxyPort").trigger("focus");    return; }
        params.set("proxyAddress",  proxyAddress);
        params.set("proxyPort",     proxyPort);
        params.set("proxyUsername", $("#txtProxyUsername").val());
        params.set("proxyPassword", $("#txtProxyPassword").val());
        let proxyBypass = cleanTextList($("#txtProxyBypassList").val());
        if (!proxyBypass || proxyBypass === ",") proxyBypass = "";
        else $("#txtProxyBypassList").val(proxyBypass.replace(/,/g, "\n"));
        params.set("proxyBypass", proxyBypass);
    }

    let forwarders = cleanTextList($("#txtForwarders").val());
    if (!forwarders || forwarders === ",") forwarders = false;
    else $("#txtForwarders").val(forwarders.replace(/,/g, "\n"));
    params.set("forwarders", forwarders || "");
    params.set("forwarderProtocol", $("input[name=rdForwarderProtocol]:checked").val());
    params.set("concurrentForwarding", $("#chkEnableConcurrentForwarding").prop("checked"));
    params.set("forwarderRetries", $("#txtForwarderRetries").val());
    params.set("forwarderTimeout", $("#txtForwarderTimeout").val());
    params.set("forwarderConcurrency", $("#txtForwarderConcurrency").val());

    // logging
    params.set("loggingType", $("input[name=rdLoggingType]:checked").val());
    params.set("ignoreResolverLogs", $("#chkIgnoreResolverLogs").prop("checked"));
    params.set("logQueries", $("#chkLogQueries").prop("checked"));
    params.set("useLocalTime", $("#chkUseLocalTime").prop("checked"));
    params.set("logFolder", $("#txtLogFolderPath").val());
    params.set("maxLogFileDays", $("#txtMaxLogFileDays").val());
    params.set("enableInMemoryStats", $("#chkEnableInMemoryStats").prop("checked"));
    params.set("maxStatFileDays", $("#txtMaxStatFileDays").val());

    const btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/settings/set?token=" + sessionData.token,
        method: "POST",
        data: params.toString(),
        processData: false,
        showInnerError: true,
        success(responseJSON) {
            updateDnsSettingsDataAndGui(responseJSON);
            loadDnsSettings(responseJSON);
            btn.button("reset");
            showAlert("success", "Settings Saved!", "DNS Server settings were saved successfully.");
            if (sessionData.info.dnsServerDomain === responseJSON.server)
                checkForWebConsoleRedirection(responseJSON);
        },
        error()  { btn.button("reset"); },
        invalidToken() { btn.button("reset"); showPageLogin(); }
    });
}

function makeQpmRow(tableId, prefix, udpLimit, tcpLimit) {
    const id = Math.floor(Math.random() * 10000);
    $(`#${tableId}`).append(`
        <tr id="${tableId}Row${id}">
            <td><input type="number" class="form-control" value="${htmlEncode(prefix)}"></td>
            <td><input type="number" class="form-control" value="${htmlEncode(udpLimit)}"></td>
            <td><input type="number" class="form-control" value="${htmlEncode(tcpLimit)}"></td>
            <td><button type="button" class="btn btn-danger" onclick="$('#${tableId}Row${id}').remove();">Delete</button></td>
        </tr>`);
}

function addQpmPrefixLimitsIPv4Row(prefix, udpLimit, tcpLimit) {
    makeQpmRow("tableQpmPrefixLimitsIPv4", prefix, udpLimit, tcpLimit);
}

function addQpmPrefixLimitsIPv6Row(prefix, udpLimit, tcpLimit) {
    makeQpmRow("tableQpmPrefixLimitsIPv6", prefix, udpLimit, tcpLimit);
}

function addTsigKeyRow(keyName, sharedSecret, algorithmName) {
    const id = Math.floor(Math.random() * 10000);
    const algos = [
        ["hmac-md5.sig-alg.reg.int", "HMAC-MD5 (obsolete)"],
        ["hmac-sha1",                "HMAC-SHA1"],
        ["hmac-sha256",              "HMAC-SHA256 (recommended)"],
        ["hmac-sha256-128",          "HMAC-SHA256 (128 bits)"],
        ["hmac-sha384",              "HMAC-SHA384"],
        ["hmac-sha384-192",          "HMAC-SHA384 (192 bits)"],
        ["hmac-sha512",              "HMAC-SHA512"],
        ["hmac-sha512-256",          "HMAC-SHA512 (256 bits)"],
    ];
    const options = algos.map(([v, l]) => `<option value="${v}"${algorithmName === v ? " selected" : ""}>${l}</option>`).join("");

    $("#tableTsigKeys").append(`
        <tr id="tableTsigKeyRow${id}">
            <td><input type="text" class="form-control" value="${htmlEncode(keyName)}"></td>
            <td><input type="text" class="form-control" data-optional="true" value="${htmlEncode(sharedSecret)}"></td>
            <td><select class="form-control">${options}</select></td>
            <td><button type="button" class="btn btn-danger" onclick="$('#tableTsigKeyRow${id}').remove();">Delete</button></td>
        </tr>`);
}

function checkForReverseProxy(responseJSON) {
    const r = responseJSON.response;
    if (window.location.protocol === "https:") {
        const currentPort = window.location.port || 443;
        reverseProxyDetected = !r.webServiceEnableTls || Number(currentPort) !== r.webServiceTlsPort;
    } else {
        const currentPort = window.location.port || 80;
        reverseProxyDetected = Number(currentPort) !== r.webServiceHttpPort;
    }
}

function checkForWebConsoleRedirection(responseJSON) {
    if (reverseProxyDetected) return;
    const r = responseJSON.response;

    const redirect = (url) => setTimeout(() => window.open(url, "_self"), 2500);

    if (location.protocol === "https:") {
        if (!r.webServiceEnableTls) { redirect(`http://${window.location.hostname}:${r.webServiceHttpPort}`); return; }
        const cur = window.location.port || 443;
        if (Number(cur) !== r.webServiceTlsPort) redirect(`https://${window.location.hostname}:${r.webServiceTlsPort}`);
    } else {
        if (r.webServiceEnableTls && r.webServiceHttpToTlsRedirect) { redirect(`https://${window.location.hostname}:${r.webServiceTlsPort}`); return; }
        const cur = window.location.port || 80;
        if (Number(cur) !== r.webServiceHttpPort) redirect(`http://${window.location.hostname}:${r.webServiceHttpPort}`);
    }
}

function forceUpdateBlockLists() {
    if (!confirm("Are you sure to force download and update the block lists?")) return;
    const btn = $("#btnUpdateBlockListsNow").button("loading");

    HTTPRequest({
        url: "api/settings/forceUpdateBlockLists?token=" + sessionData.token,
        success() {
            btn.button("reset");
            $("#lblBlockListNextUpdatedOn").text("Updating Now");
            showAlert("success", "Updating Block List!", "Block list update was triggered successfully.");
        },
        error()  { btn.button("reset"); },
        invalidToken() { btn.button("reset"); showPageLogin(); }
    });
}

function temporaryDisableBlockingNow() {
    const minutes = $("#txtTemporaryDisableBlockingMinutes").val();
    if (!minutes) {
        showAlert("warning", "Missing!", "Please enter a value in minutes to temporarily disable blocking.");
        $("#txtTemporaryDisableBlockingMinutes").trigger("focus");
        return;
    }
    if (!confirm(`Are you sure to temporarily disable blocking for ${minutes} minute(s)?`)) return;

    const btn = $("#btnTemporaryDisableBlockingNow").button("loading");

    HTTPRequest({
        url: `api/settings/temporaryDisableBlocking?token=${sessionData.token}&minutes=${minutes}`,
        success(responseJSON) {
            btn.button("reset");
            $("#chkEnableBlocking").prop("checked", false);
            $("#lblTemporaryDisableBlockingTill").text(moment(responseJSON.response.temporaryDisableBlockingTill).local().format("YYYY-MM-DD HH:mm:ss"));
            updateBlockingState();
            showAlert("success", "Blocking Disabled!", `Blocking was successfully disabled temporarily for ${htmlEncode(minutes)} minute(s).`);
            setTimeout(updateBlockingState, 500);
        },
        error()  { btn.button("reset"); },
        invalidToken() { btn.button("reset"); showPageLogin(); }
    });
}

function updateBlockingState() {
    const on = $("#chkEnableBlocking").prop("checked");
    ["#chkAllowTxtBlockingReport","#txtTemporaryDisableBlockingMinutes","#btnTemporaryDisableBlockingNow",
        "#txtBlockingBypassList","#rdBlockingTypeAnyAddress","#rdBlockingTypeNxDomain",
        "#rdBlockingTypeCustomAddress","#txtBlockListUrls","#optQuickBlockList","#txtBlockListUpdateIntervalHours"
    ].forEach(sel => $(sel).prop("disabled", !on));

    $("#txtCustomBlockingAddresses").prop("disabled", !on || !$("#rdBlockingTypeCustomAddress").prop("checked"));
    $("#btnUpdateBlockListsNow").prop("disabled", !on || !$("#txtBlockListUrls").val());
}

function updateChart(chart, data) {
    chart.data = data;
    chart.update();
    loadChartLegendSettings(chart);
}

function loadChartLegendSettings(chart) {
    const raw = localStorage.getItem("chart_" + chart.id + "_legend");
    if (!raw) return;
    const filters = JSON.parse(raw);
    const isDoughnutOrPie = ["doughnut","pie"].includes(chart.config.type);

    if (isDoughnutOrPie) {
        chart.data.labels.forEach((label, i) => {
            const f = filters.find(f => f.title === String(label));
            if (f) chart.getDatasetMeta(0).data[i].hidden = f.hidden;
        });
    } else {
        chart.data.datasets.forEach((ds, i) => {
            const f = filters.find(f => f.title === String(ds.label));
            if (f) chart.getDatasetMeta(i).hidden = f.hidden;
        });
    }
    chart.update();
}

function saveChartLegendSettings(chart) {
    const isDoughnutOrPie = ["doughnut","pie"].includes(chart.config.type);
    const filters = isDoughnutOrPie
        ? chart.data.labels.map((label, i) => ({ title: label, hidden: chart.getDatasetMeta(0).data[i].hidden }))
        : chart.data.datasets.map((ds, i) => ({ title: ds.label, hidden: chart.getDatasetMeta(i).hidden }));
    localStorage.setItem("chart_" + chart.id + "_legend", JSON.stringify(filters));
}

const chartLegendOnClick = function (e, legendItem) {
    const type = this.chart.config.type;
    if (type === "doughnut")  Chart.defaults.doughnut.legend.onClick.call(this, e, legendItem);
    else if (type === "pie")  Chart.defaults.pie.legend.onClick.call(this, e, legendItem);
    else                      Chart.defaults.global.legend.onClick.call(this, e, legendItem);
    saveChartLegendSettings(this.chart);
};

/**
 * Factory for the three identical bar charts on the dashboard.
 */
function createBarChart(canvasId) {
    const drawBarValues = {
        onComplete() {
            const { chart: ci } = this;
            const ctx = ci.ctx;
            ctx.font = "bold 11px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif";
            ctx.textAlign = "center";
            ctx.textBaseline = "bottom";
            ctx.fillStyle = document.body.classList.contains("dark-mode") ? "#e0e0e0" : "#555";

            this.data.datasets.forEach((dataset, i) => {
                ci.controller.getDatasetMeta(i).data.forEach((bar, idx) => {
                    const val = dataset.data[idx];
                    if (val > 0) ctx.fillText(val.toLocaleString(), bar._model.x, bar._model.y - 4);
                });
            });
        }
    };

    return new Chart(document.getElementById(canvasId).getContext("2d"), {
        type: "bar",
        data: { labels: [], datasets: [] },
        options: {
            layout: { padding: { left: 10, right: 30, top: 20, bottom: 10 } },
            maintainAspectRatio: false,
            legend: { display: false },
            scales: {
                xAxes: [{ gridLines: { display: false } }],
                yAxes: [{ ticks: { beginAtZero: true, maxTicksLimit: 5 }, gridLines: { color: "rgba(128,128,128,0.15)" } }]
            },
            tooltips: { cornerRadius: 4, backgroundColor: "rgba(25,25,25,0.9)" },
            animation: drawBarValues,
            hover: { animationDuration: 0 }
        }
    });
}

function renderTopClientsRows(items, idPrefix) {
    if (!items.length) return `<tr><td colspan="3" align="center">No Data</td></tr>`;
    return items.map((c, i) => `
        <tr${c.rateLimited ? " style=\"color:orange;\"" : ""}>
            <td style="word-wrap:anywhere;">${htmlEncode(c.name)}${c.rateLimited ? " (rate limited)" : ""}<br>${htmlEncode(c.domain || ".")}</td>
            <td>${c.hits.toLocaleString()}</td>
            <td align="right">
                <div class="dropdown">
                    <a href="#" id="${idPrefix}${i}" class="dropdown-toggle" data-toggle="dropdown" aria-haspopup="true" aria-expanded="true">
                        <span class="glyphicon glyphicon-option-vertical"></span>
                    </a>
                    <ul class="dropdown-menu dropdown-menu-right">
                        <li><a href="#" onclick="showQueryLogs(null,'${c.name}');return false;">Show Query Logs</a></li>
                    </ul>
                </div>
            </td>
        </tr>`).join("");
}

function renderTopDomainsRows(items, idPrefix, blockFn) {
    if (!items.length) return `<tr><td colspan="3" align="center">No Data</td></tr>`;
    return items.map((d, i) => {
        const display = htmlEncode(d.nameIdn ?? (d.name || "."));
        return `
        <tr>
            <td style="word-wrap:anywhere;">${display}</td>
            <td>${d.hits.toLocaleString()}</td>
            <td align="right">
                <div class="dropdown">
                    <a href="#" id="${idPrefix}${i}" class="dropdown-toggle" data-toggle="dropdown" aria-haspopup="true" aria-expanded="true">
                        <span class="glyphicon glyphicon-option-vertical"></span>
                    </a>
                    <ul class="dropdown-menu dropdown-menu-right">
                        <li><a href="#" onclick="showQueryLogs('${d.name}',null);return false;">Show Query Logs</a></li>
                        <li><a href="#" onclick="queryDnsServer('${d.name}',null);return false;">Query DNS Server</a></li>
                        <li><a href="#" data-domain="${htmlEncode(d.name)}" onclick="${blockFn}(this,'${idPrefix}');return false;">${blockFn === "blockDomain" ? "Block" : "Allow"} Domain</a></li>
                    </ul>
                </div>
            </td>
        </tr>`;
    }).join("");
}

function refreshDashboard(hideLoader) {
    if (!$("#mainPanelTabPaneDashboard").hasClass("active")) return;
    hideLoader = hideLoader ?? false;

    const loader  = $("#divDashboardLoader");
    const panel   = $("#divDashboard");
    const type    = $("input[name=rdStatType]:checked").val();
    let custom    = "";

    if (type === "custom") {
        const txtStart = $("#dpCustomDayWiseStart").val();
        const txtEnd   = $("#dpCustomDayWiseEnd").val();
        if (!txtStart) { showAlert("warning","Missing!","Please select a start date."); $("#dpCustomDayWiseStart").trigger("focus"); return; }
        if (!txtEnd)   { showAlert("warning","Missing!","Please select an end date.");   $("#dpCustomDayWiseEnd").trigger("focus");   return; }

        let start = moment(txtStart), end = moment(txtEnd);
        if ((end.diff(start,"days")+1) > 7) { start = moment.utc(txtStart).toISOString(); end = moment.utc(txtEnd).toISOString(); }
        else { start = start.toISOString(); end = end.toISOString(); }
        custom = "&start=" + encodeURIComponent(start) + "&end=" + encodeURIComponent(end);
    }

    if (!hideLoader) { panel.hide(); loader.show(); }

    HTTPRequest({
        url: `api/dashboard/stats/get?token=${sessionData.token}&type=${type}&utc=true${custom}`,
        success(responseJSON) {
            const r   = responseJSON.response;
            const st  = r.stats;
            const tot = st.totalQueries;

            // stats counters
            const statsMap = {
                TotalQueries: tot, TotalNoError: st.totalNoError,
                TotalServerFailure: st.totalServerFailure, TotalNxDomain: st.totalNxDomain,
                TotalRefused: st.totalRefused, TotalAuthHit: st.totalAuthoritative,
                TotalRecursions: st.totalRecursive, TotalCacheHit: st.totalCached,
                TotalBlocked: st.totalBlocked, TotalDropped: st.totalDropped,
                TotalClients: st.totalClients, Zones: st.zones,
                CachedEntries: st.cachedEntries, AllowedZones: st.allowedZones,
                BlockedZones: st.blockedZones, AllowListZones: st.allowListZones,
                BlockListZones: st.blockListZones
            };
            for (const [k, v] of Object.entries(statsMap))
                $(`#divDashboardStats${k}`).text(v.toLocaleString());

            const pctFields = ["TotalNoError","TotalServerFailure","TotalNxDomain","TotalRefused",
                "TotalAuthHit","TotalRecursions","TotalCacheHit","TotalBlocked","TotalDropped"];
            for (const f of pctFields) {
                const raw = statsMap[f];
                $(`#divDashboardStats${f}Percentage`).text(tot > 0 ? (raw * 100 / tot).toFixed(2) + "%" : "0%");
            }

            // main line chart
            const cd = r.mainChartData;
            const fmt = cd.labelFormat;
            cd.labels = cd.labels.map(l =>
                ["MM/DD","DD/MM","MM/YYYY"].includes(fmt)
                    ? moment(l).utc().format(fmt)
                    : moment(l).local().format(fmt)
            );
            cd.datasets.forEach(ds => { ds.fill = true; ds.borderWidth = 2; });

            const STEPS = [0,1,5,10,25,50,100,250,500,1000,2500,5000,10000,25000,50000,100000,250000,500000,1000000,2500000,5000000,10000000];
            const allVals  = cd.datasets.flatMap(ds => ds.data);
            const dataMax  = Math.max(...allVals);
            const maxTick  = STEPS.find(s => s >= dataMax) ?? STEPS[STEPS.length-1];

            if (!window.chartDashboardMain) {
                document.getElementById("canvasDashboardMain").parentElement.style.height = "450px";

                Chart.Tooltip.positioners.fixedCenter = function(elements, pos) {
                    const ca = this._chart.chartArea;
                    return { x: pos ? pos.x : elements[0]._model.x, y: ca.top + (ca.bottom - ca.top) / 2 };
                };

                window.chartDashboardMain = new Chart(
                    document.getElementById("canvasDashboardMain").getContext("2d"), {
                        type: "line",
                        data: cd,
                        options: {
                            maintainAspectRatio: false,
                            elements: { line: { tension: 0.35 }, point: { radius: 0, hitRadius: 15, hoverRadius: 5 } },
                            scales: {
                                xAxes: [{ gridLines: { display: false } }],
                                yAxes: [{
                                    ticks: {
                                        min: 0, max: maxTick,
                                        callback(v) {
                                            if (!STEPS.includes(v)) return "";
                                            if (v >= 1e6) return (v/1e6).toFixed(0) + "M";
                                            if (v >= 1e3) return (v/1e3).toFixed(0) + "k";
                                            return v.toLocaleString();
                                        }
                                    },
                                    gridLines: { color: "rgba(128,128,128,0.15)" },
                                    afterBuildTicks(scale) { scale.ticks = STEPS.filter(s => s <= maxTick); }
                                }]
                            },
                            tooltips: {
                                mode: "index", position: "fixedCenter", yAlign: "center", intersect: false,
                                cornerRadius: 6, backgroundColor: "rgba(25,25,25,0.9)",
                                titleFontSize: 14, bodySpacing: 6, xPadding: 12, yPadding: 12,
                                callbacks: { label: (item, data) => `${data.datasets[item.datasetIndex].label}: ${item.yLabel.toLocaleString()}` }
                            },
                            hover: { mode: "index", intersect: false },
                            legend: { onClick: chartLegendOnClick, labels: { usePointStyle: true, padding: 20 } }
                        }
                    });
                loadChartLegendSettings(window.chartDashboardMain);
            } else {
                window.chartDashboardMain.options.scales.yAxes[0].ticks.max = maxTick;
                updateChart(window.chartDashboardMain, cd);
            }

            // bar charts
            if (!window.chartDashboardPie)  window.chartDashboardPie  = createBarChart("canvasDashboardPie");
            if (!window.chartDashboardPie2) window.chartDashboardPie2 = createBarChart("canvasDashboardPie2");
            if (!window.chartDashboardPie3) window.chartDashboardPie3 = createBarChart("canvasDashboardPie3");

            updateChart(window.chartDashboardPie,  r.queryResponseChartData);
            updateChart(window.chartDashboardPie2, r.queryTypeChartData);
            updateChart(window.chartDashboardPie3, r.protocolTypeChartData);

            // tables
            $("#tableTopClients").html(renderTopClientsRows(r.topClients, "btnDashboardTopClientsRowOption"));
            $("#tableTopDomains").html(renderTopDomainsRows(r.topDomains, "btnDashboardTopDomainsRowOption", "blockDomain"));
            $("#tableTopBlockedDomains").html(renderTopDomainsRows(r.topBlockedDomains, "btnDashboardTopBlockedDomainsRowOption", "allowDomain"));

            if (!hideLoader) { loader.hide(); panel.show(); }
        },
        invalidToken: showPageLogin,
        objLoaderPlaceholder: loader,
        dontHideAlert: hideLoader
    });
}

function showTopStats(statsType, limit) {
    const loaderEl = $("#divTopStatsLoader");
    $("#tableTopStatsClients, #tableTopStatsDomains, #tableTopStatsBlockedDomains").hide();
    loaderEl.show();

    const titles = { TopClients: "Clients", TopDomains: "Domains", TopBlockedDomains: "Blocked Domains" };
    $("#lblTopStatsTitle").text(`Top ${limit} ${titles[statsType] ?? ""}`);
    $("#modalTopStats").modal("show");

    const type = $("input[name=rdStatType]:checked").val();
    let custom = "";

    if (type === "custom") {
        const s = $("#dpCustomDayWiseStart").val();
        const e = $("#dpCustomDayWiseEnd").val();
        if (!s) { showAlert("warning","Missing!","Please select a start date."); $("#dpCustomDayWiseStart").trigger("focus"); return; }
        if (!e) { showAlert("warning","Missing!","Please select an end date.");   $("#dpCustomDayWiseEnd").trigger("focus");   return; }
        let start = moment(s), end = moment(e);
        if ((end.diff(start,"days")+1) > 7) { start = moment.utc(s).toISOString(); end = moment.utc(e).toISOString(); }
        else { start = start.toISOString(); end = end.toISOString(); }
        custom = "&start=" + encodeURIComponent(start) + "&end=" + encodeURIComponent(end);
    }

    HTTPRequest({
        url: `api/dashboard/stats/getTop?token=${sessionData.token}&type=${type}${custom}&statsType=${statsType}&limit=${limit}`,
        success(responseJSON) {
            loaderEl.hide();
            const r = responseJSON.response;

            if (r.topClients) {
                $("#tbodyTopStatsClients").html(renderTopClientsRows(r.topClients, "btnDashboardTopClientsRowOption"));
                $("#tfootTopStatsClients").html(r.topClients.length ? `Total Clients: ${r.topClients.length}` : "");
                $("#tableTopStatsClients").show();
            } else if (r.topDomains) {
                $("#tbodyTopStatsDomains").html(renderTopDomainsRows(r.topDomains, "btnDashboardTopStatsDomainsRowOption", "blockDomain", "divTopStatsAlert"));
                $("#tfootTopStatsDomains").html(r.topDomains.length ? `Total Domains: ${r.topDomains.length}` : "");
                $("#tableTopStatsDomains").show();
            } else if (r.topBlockedDomains) {
                $("#tbodyTopStatsBlockedDomains").html(renderTopDomainsRows(r.topBlockedDomains, "btnDashboardTopStatsBlockedDomainsRowOption", "allowDomain", "divTopStatsAlert"));
                $("#tfootTopStatsBlockedDomains").html(r.topBlockedDomains.length ? `Total Domains: ${r.topBlockedDomains.length}` : "");
                $("#tableTopStatsBlockedDomains").show();
            }

            $("#divTopStatsData").animate({ scrollTop: 0 }, "fast");
        },
        invalidToken: showPageLogin,
        objLoaderPlaceholder: loaderEl,
        objAlertPlaceholder: $("#divTopStatsAlert")
    });
}

function resetBackupSettingsModal() {
    $("#divBackupSettingsAlert").html("");
    ["#chkBackupAuthConfig","#chkBackupWebServiceConfig","#chkBackupDnsConfig","#chkBackupLogConfig",
        "#chkBackupZones","#chkBackupAllowedZones","#chkBackupBlockedZones","#chkBackupBlockLists",
        "#chkBackupApps","#chkBackupStats"
    ].forEach(sel => $(sel).prop("checked", true));
    $("#chkBackupLogs").prop("checked", false);
}

function backupSettings() {
    const divAlert = $("#divBackupSettingsAlert");
    const keys = ["AuthConfig","WebServiceConfig","DnsConfig","LogConfig","Zones","AllowedZones","BlockedZones","BlockLists","Apps","Stats","Logs"];
    const vals = Object.fromEntries(keys.map(k => [k.charAt(0).toLowerCase() + k.slice(1), $(`#chkBackup${k}`).prop("checked")]));

    if (!Object.values(vals).some(Boolean)) {
        showAlert("warning", "Missing!", "Please select at least one item to backup.", divAlert);
        return;
    }

    const qs = Object.entries(vals).map(([k,v]) => `${k}=${v}`).join("&");
    window.open(`api/settings/backup?token=${sessionData.token}&${qs}&ts=${Date.now()}`, "_blank");
    $("#modalBackupSettings").modal("hide");
    showAlert("success", "Backed Up!", "Settings were backed up successfully.");
}

function resetRestoreSettingsModal() {
    $("#divRestoreSettingsAlert").html("");
    $("#fileBackupZip").val("");
    ["#chkRestoreAuthConfig","#chkRestoreWebServiceConfig","#chkRestoreDnsConfig","#chkRestoreLogConfig",
        "#chkRestoreZones","#chkRestoreAllowedZones","#chkRestoreBlockedZones","#chkRestoreBlockLists",
        "#chkRestoreApps","#chkRestoreStats","#chkDeleteExistingFiles"
    ].forEach(sel => $(sel).prop("checked", true));
    $("#chkRestoreLogs").prop("checked", false);
}

function restoreSettings() {
    const divAlert = $("#divRestoreSettingsAlert");
    const fileInput = $("#fileBackupZip");

    if (!fileInput[0].files.length) {
        showAlert("warning", "Missing!", "Please select a backup zip file to restore.", divAlert);
        fileInput.trigger("focus");
        return;
    }

    const keys = ["AuthConfig","WebServiceConfig","DnsConfig","LogConfig","Zones","AllowedZones","BlockedZones","BlockLists","Apps","Stats","Logs"];
    const vals = Object.fromEntries(keys.map(k => [k.charAt(0).toLowerCase() + k.slice(1), $(`#chkRestore${k}`).prop("checked")]));

    if (!Object.values(vals).some(Boolean)) {
        showAlert("warning", "Missing!", "Please select at least one item to restore.", divAlert);
        return;
    }

    const qs = Object.entries(vals).map(([k,v]) => `${k}=${v}`).join("&");
    const deleteExistingFiles = $("#chkDeleteExistingFiles").prop("checked");

    const formData = new FormData();
    formData.append("fileBackupZip", fileInput[0].files[0]);

    const btn = $("#btnRestoreSettings").button("loading");

    HTTPRequest({
        url: `api/settings/restore?token=${sessionData.token}&${qs}&deleteExistingFiles=${deleteExistingFiles}`,
        method: "POST",
        data: formData,
        contentType: false,
        processData: false,
        success(responseJSON) {
            updateDnsSettingsDataAndGui(responseJSON);
            loadDnsSettings(responseJSON);
            $("#modalRestoreSettings").modal("hide");
            btn.button("reset");
            showAlert("success", "Restored!", "Settings were restored successfully.");
            if (sessionData.info.dnsServerDomain === responseJSON.server)
                checkForWebConsoleRedirection(responseJSON);
        },
        error()  { btn.button("reset"); },
        invalidToken() { btn.button("reset"); showPageLogin(); },
        objAlertPlaceholder: divAlert
    });
}

function applyTheme() {
    document.body.classList.toggle("dark-mode", localStorage.getItem("theme") === "dark");
}

function toggleTheme() {
    document.body.classList.toggle("dark-mode");
    localStorage.setItem("theme", document.body.classList.contains("dark-mode") ? "dark" : "light");
    [window.chartDashboardMain, window.chartDashboardPie, window.chartDashboardPie2, window.chartDashboardPie3]
        .forEach(c => c?.update());
}