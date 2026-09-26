/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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

var refreshTimerHandle;
var reverseProxyDetected = false;
var quickBlockLists = null;
var quickForwardersList = null;

function showPageLogin(autoLogin) {
    hideAlert();

    localStorage.removeItem("token");

    document.body.classList.remove("signed-in");
    $("#pageMain").hide();

    $("#txtUser").val("");
    $("#txtPass").val("");
    $("#txtPass").prop("disabled", false);
    $("#div2FAOTP").hide();
    $("#txt2FATOTP").val("");
    $("#btnLogin").button("reset");
    $("#pageLogin").show();

    $("#txtUser").trigger("focus");

    if (refreshTimerHandle != null) {
        clearInterval(refreshTimerHandle);
        refreshTimerHandle = null;
    }

    HTTPRequest({
        url: "api/status",
        success: function (responseJSON) {
            if (responseJSON.ssoEnabled)
                $("#divLoginSso").show();
            else
                $("#divLoginSso").hide();

            if (autoLogin && responseJSON.hasDefaultCredentials)
                login("admin", "admin");
        }
    });
}

function showPageMain() {
    hideAlert();

    $("#txtUser").val("");
    $("#txtPass").val("");
    $("#txt2FATOTP").val("");

    $("#pageLogin").hide();

    switch (sessionData.type) {
        case "RemoteSSO":
            $("#mnuUserChangePassword").hide();
            $("#mnuUserConfigure2FA").hide();
            break;

        case "RemoteLDAP":
            $("#mnuUserChangePassword").hide();
            $("#mnuUserConfigure2FA").show();
            break;

        case "Local":
        default:
            $("#mnuUserChangePassword").show();
            $("#mnuUserConfigure2FA").show();
            break;
    }

    $(".main-nav li, .nav-tabs li, .nav-pills li").removeClass("active");
    $(".tab-pane").removeClass("active");
    $("#settingsTabListGeneral").addClass("active");
    $("#settingsTabPaneGeneral").addClass("active");
    $("#adminTabListSessions").addClass("active");
    $("#adminTabPaneSessions").addClass("active");
    $("#logsTabListLogViewer").addClass("active");
    $("#logsTabPaneLogViewer").addClass("active");

    var permissions = sessionData.info.permissions;
    var canViewResolver = permissions.Zones.canView || permissions.Cache.canView;
    var canViewFilter = permissions.Blocked.canView || permissions.Allowed.canView;

    $("#resolverTabListZones").toggle(permissions.Zones.canView);
    $("#resolverTabListCache").toggle(permissions.Cache.canView);

    if (permissions.Zones.canView) {
        $("#resolverTabListZones").addClass("active");
        $("#resolverTabPaneZones").addClass("active");
    }
    else {
        $("#resolverTabListCache").addClass("active");
        $("#resolverTabPaneCache").addClass("active");
    }

    $("#filterTabListBlocked").toggle(permissions.Blocked.canView);
    $("#filterTabListAllowed").toggle(permissions.Allowed.canView);
    $("#filterTabListLists").toggle(permissions.Settings.canView);

    if (permissions.Blocked.canView) {
        $("#filterTabListBlocked").addClass("active");
        $("#filterTabPaneBlocked").addClass("active");
    }
    else {
        $("#filterTabListAllowed").addClass("active");
        $("#filterTabPaneAllowed").addClass("active");
    }

    $("#txtZonesFilterName").val("");
    $("#tableZonesBody").html("");
    $("#divViewZones").show();
    $("#divEditZone").hide();

    $("#txtDnsClientNameServer").val("Dieser Server {this-server}");
    $("#txtDnsClientDomain").val("");
    $("#optDnsClientType").val("A");
    $("#optDnsClientProtocol").val("UDP");
    $("#txtDnsClientEDnsClientSubnet").val("");
    $("#chkDnsClientDnssecValidation").prop("checked", false);
    $("#divDnsClientLoader").hide();
    $("#preDnsClientFinalResponse").text("");
    $("#divDnsClientOutputAccordion").hide();

    $("#divLogViewer").hide();
    $("#divQueryLogsTable").hide();

    var tabs = [
        { list: "#mainPanelTabListDashboard", pane: "#mainPanelTabPaneDashboard", visible: permissions.Dashboard.canView, open: function () { refreshDashboard(); } },
        { list: "#mainPanelTabListResolver", pane: "#mainPanelTabPaneResolver", visible: canViewResolver, open: function () { refreshResolverTab(); } },
        { list: "#mainPanelTabListFilter", pane: "#mainPanelTabPaneFilter", visible: canViewFilter, open: null },
        { list: "#mainPanelTabListApps", pane: "#mainPanelTabPaneApps", visible: permissions.Apps.canView, open: function () { refreshApps(); } },
        { list: "#mainPanelTabListDnsClient", pane: "#mainPanelTabPaneDnsClient", visible: permissions.DnsClient.canView, open: null },
        { list: "#mainPanelTabListLogs", pane: "#mainPanelTabPaneLogs", visible: permissions.Logs.canView, open: function () { refreshLogsTab(); } },
        { list: "#mainPanelTabListSelfTest", pane: "#mainPanelTabPaneSelfTest", visible: permissions.Settings.canView, open: function () { refreshSelfTest(false); } },
        { list: "#mainPanelTabListSettings", pane: "#mainPanelTabPaneSettings", visible: permissions.Settings.canView, open: function () { refreshDnsSettings(); } },
        { list: "#mainPanelTabListAdmin", pane: "#mainPanelTabPaneAdmin", visible: permissions.Administration.canView, open: function () { refreshAdminTab(); } },
        { list: "#mainPanelTabListAbout", pane: "#mainPanelTabPaneAbout", visible: true, open: null }
    ];

    var opened = false;

    for (var i = 0; i < tabs.length; i++) {
        $(tabs[i].list).toggle(tabs[i].visible);

        if (!opened && tabs[i].visible) {
            $(tabs[i].list).addClass("active");
            $(tabs[i].pane).addClass("active");

            if (tabs[i].open != null)
                tabs[i].open();

            opened = true;
        }
    }

    if (permissions.Cache.canView)
        refreshCachedZonesList("");

    if (permissions.Allowed.canView)
        refreshAllowedZonesList("");

    if (permissions.Blocked.canView)
        refreshBlockedZonesList("");

    document.body.classList.add("signed-in");
    updatePageTitle();
    $("#pageMain").show();

    checkForUpdate();

    selfTestLastCheck = 0;
    $("#divDashboardHealth").hide();
    $("#divSelfTestResults").html("");
    $("#divSelfTestSummary").html("");
    checkDashboardHealth();

    if (refreshTimerHandle != null)
        clearInterval(refreshTimerHandle);

    refreshTimerHandle = setInterval(function () {
        var type = $("input[name=rdStatType]:checked").val();
        if (type === "lastHour")
            refreshDashboard(true);

        checkDashboardHealth();

        $("#lblAboutUptime").text(moment(sessionData.info.uptimestamp).local().format("lll") + " (" + moment(sessionData.info.uptimestamp).fromNow() + ")");
    }, 30000);
}

function updatePageTitle() {
    var title = $(".main-nav > li.active > a").first().text().trim();
    $("#lblPageTitle").text(title === "" ? "ZenitiumDNS" : title);
}

function refreshResolverTab() {
    if ($("#resolverTabListZones").hasClass("active"))
        refreshZones(true);
}

function showSettingsSection(settingsTabListId) {
    $("#mainPanelTabListSettings a").tab("show");
    refreshDnsSettings();
    $("#" + settingsTabListId + " a").tab("show");
}

$(function () {
    initTheme();
    initUpdateNotificationMenu();

    $(".main-nav a[data-toggle=tab]").on("shown.bs.tab", updatePageTitle);

    loadQuickBlockLists();
    loadQuickForwardersList();

    $("#chkEnableUdpSocketPool").on("click", function () {
        var enableUdpSocketPool = $("#chkEnableUdpSocketPool").prop("checked");

        $("#txtUdpSocketPoolExcludedPorts").prop("disabled", !enableUdpSocketPool);
    });

    $("#chkEDnsClientSubnet").on("click", function () {
        var eDnsClientSubnet = $("#chkEDnsClientSubnet").prop("checked");

        $("#txtEDnsClientSubnetIPv4PrefixLength").prop("disabled", !eDnsClientSubnet);
        $("#txtEDnsClientSubnetIPv6PrefixLength").prop("disabled", !eDnsClientSubnet);
        $("#txtEDnsClientSubnetIpv4Override").prop("disabled", !eDnsClientSubnet);
        $("#txtEDnsClientSubnetIpv6Override").prop("disabled", !eDnsClientSubnet);
    });

    $("#chkEnableBlocking").on("click", updateBlockingState);

    $("input[type=radio][name=rdProxyType]").on("change", function () {
        var proxyType = $("input[name=rdProxyType]:checked").val().toLowerCase();
        if (proxyType === "none") {
            $("#txtProxyAddress").prop("disabled", true);
            $("#txtProxyPort").prop("disabled", true);
            $("#txtProxyUsername").prop("disabled", true);
            $("#txtProxyPassword").prop("disabled", true);
            $("#txtProxyBypassList").prop("disabled", true);
        }
        else {
            $("#txtProxyAddress").prop("disabled", false);
            $("#txtProxyPort").prop("disabled", false);
            $("#txtProxyUsername").prop("disabled", false);
            $("#txtProxyPassword").prop("disabled", false);
            $("#txtProxyBypassList").prop("disabled", false);
        }
    });

    $("input[type=radio][name=rdRecursion]").on("change", function () {
        var recursion = $("input[name=rdRecursion]:checked").val();

        $("#txtRecursionNetworkACL").prop("disabled", recursion !== "UseSpecifiedNetworkACL");
    });

    $("input[type=radio][name=rdBlockingType]").on("change", function () {
        var recursion = $("input[name=rdBlockingType]:checked").val();
        if (recursion === "CustomAddress") {
            $("#txtCustomBlockingAddresses").prop("disabled", false);
        }
        else {
            $("#txtCustomBlockingAddresses").prop("disabled", true);
        }
    });

    $("#chkWebServiceEnableHttpUnixSocket").on("click", function () {
        var webServiceEnableHttpUnixSocket = $("#chkWebServiceEnableHttpUnixSocket").prop("checked");
        $("#txtWebServiceHttpUnixSocket").prop("disabled", !webServiceEnableHttpUnixSocket);
    });

    $("#chkWebServiceEnableTlsUnixSocket").on("click", function () {
        var webServiceEnableTlsUnixSocket = $("#chkWebServiceEnableTlsUnixSocket").prop("checked");
        var webServiceEnableTls = $("#chkWebServiceEnableTls").prop("checked");

        $("#txtWebServiceTlsUnixSocket").prop("disabled", !webServiceEnableTlsUnixSocket);
        $("#chkWebServiceUseSelfSignedTlsCertificate").prop("disabled", !webServiceEnableTls && !webServiceEnableTlsUnixSocket);
        $("#txtWebServiceTlsCertificatePath").prop("disabled", !webServiceEnableTls && !webServiceEnableTlsUnixSocket);
        $("#txtWebServiceTlsCertificatePassword").prop("disabled", !webServiceEnableTls && !webServiceEnableTlsUnixSocket);
        $("#txtWebServiceTlsCertificateKeyPath").prop("disabled", !webServiceEnableTls && !webServiceEnableTlsUnixSocket);
    });

    $("#chkWebServiceEnableTls").on("click", function () {
        var webServiceEnableTlsUnixSocket = $("#chkWebServiceEnableTlsUnixSocket").prop("checked");
        var webServiceEnableTls = $("#chkWebServiceEnableTls").prop("checked");

        $("#chkWebServiceEnableHttp3").prop("disabled", !webServiceEnableTls);
        $("#chkWebServiceHttpToTlsRedirect").prop("disabled", !webServiceEnableTls);
        $("#chkWebServiceUseSelfSignedTlsCertificate").prop("disabled", !webServiceEnableTls && !webServiceEnableTlsUnixSocket);
        $("#txtWebServiceTlsPort").prop("disabled", !webServiceEnableTls);
        $("#txtWebServiceTlsCertificatePath").prop("disabled", !webServiceEnableTls && !webServiceEnableTlsUnixSocket);
        $("#txtWebServiceTlsCertificatePassword").prop("disabled", !webServiceEnableTls && !webServiceEnableTlsUnixSocket);
        $("#txtWebServiceTlsCertificateKeyPath").prop("disabled", !webServiceEnableTls && !webServiceEnableTlsUnixSocket);
    });

    $("#chkEnableEDnsClientSubnetSourceAddress").on("click", function () {
        var chkEnableEDnsClientSubnetSourceAddress = $("#chkEnableEDnsClientSubnetSourceAddress").prop("checked");
        var enableDnsOverUdpProxy = $("#chkEnableDnsOverUdpProxy").prop("checked");
        var enableDnsOverTcpProxy = $("#chkEnableDnsOverTcpProxy").prop("checked");
        var enableDnsOverHttp = $("#chkEnableDnsOverHttp").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");

        $("#txtDnsOverUdpProxyPort").prop("disabled", !enableDnsOverUdpProxy);
        $("#txtDnsReverseProxyNetworkACL").prop("disabled", !chkEnableEDnsClientSubnetSourceAddress && !enableDnsOverUdpProxy && !enableDnsOverTcpProxy && !enableDnsOverHttp && !enableDnsOverHttps);
    });

    $("#chkEnableDnsOverUdpProxy").on("click", function () {
        var chkEnableEDnsClientSubnetSourceAddress = $("#chkEnableEDnsClientSubnetSourceAddress").prop("checked");
        var enableDnsOverUdpProxy = $("#chkEnableDnsOverUdpProxy").prop("checked");
        var enableDnsOverTcpProxy = $("#chkEnableDnsOverTcpProxy").prop("checked");
        var enableDnsOverHttp = $("#chkEnableDnsOverHttp").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");

        $("#txtDnsOverUdpProxyPort").prop("disabled", !enableDnsOverUdpProxy);
        $("#txtDnsReverseProxyNetworkACL").prop("disabled", !chkEnableEDnsClientSubnetSourceAddress && !enableDnsOverUdpProxy && !enableDnsOverTcpProxy && !enableDnsOverHttp && !enableDnsOverHttps);
    });

    $("#chkEnableDnsOverTcpProxy").on("click", function () {
        var chkEnableEDnsClientSubnetSourceAddress = $("#chkEnableEDnsClientSubnetSourceAddress").prop("checked");
        var enableDnsOverUdpProxy = $("#chkEnableDnsOverUdpProxy").prop("checked");
        var enableDnsOverTcpProxy = $("#chkEnableDnsOverTcpProxy").prop("checked");
        var enableDnsOverHttp = $("#chkEnableDnsOverHttp").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");

        $("#txtDnsOverTcpProxyPort").prop("disabled", !enableDnsOverTcpProxy);
        $("#txtDnsReverseProxyNetworkACL").prop("disabled", !chkEnableEDnsClientSubnetSourceAddress && !enableDnsOverUdpProxy && !enableDnsOverTcpProxy && !enableDnsOverHttp && !enableDnsOverHttps);
    });

    $("#chkEnableDnsOverHttp").on("click", function () {
        var chkEnableEDnsClientSubnetSourceAddress = $("#chkEnableEDnsClientSubnetSourceAddress").prop("checked");
        var enableDnsOverUdpProxy = $("#chkEnableDnsOverUdpProxy").prop("checked");
        var enableDnsOverTcpProxy = $("#chkEnableDnsOverTcpProxy").prop("checked");
        var enableDnsOverHttpUnixSocket = $("#chkEnableDnsOverHttpUnixSocket").prop("checked");
        var enableDnsOverHttpsUnixSocket = $("#chkEnableDnsOverHttpsUnixSocket").prop("checked");
        var enableDnsOverHttp = $("#chkEnableDnsOverHttp").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");

        $("#txtDnsOverHttpPort").prop("disabled", !enableDnsOverHttp);
        $("#txtDnsReverseProxyNetworkACL").prop("disabled", !chkEnableEDnsClientSubnetSourceAddress && !enableDnsOverUdpProxy && !enableDnsOverTcpProxy && !enableDnsOverHttp && !enableDnsOverHttps);
        $("#txtDnsOverHttpRealIpHeader").prop("disabled", !enableDnsOverHttpUnixSocket && !enableDnsOverHttpsUnixSocket && !enableDnsOverHttp && !enableDnsOverHttps);
    });

    $("#chkEnableDnsOverHttpUnixSocket").on("click", function () {
        var enableDnsOverHttpUnixSocket = $("#chkEnableDnsOverHttpUnixSocket").prop("checked");
        var enableDnsOverHttpsUnixSocket = $("#chkEnableDnsOverHttpsUnixSocket").prop("checked");
        var enableDnsOverHttp = $("#chkEnableDnsOverHttp").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");

        $("#txtDnsOverHttpUnixSocket").prop("disabled", !enableDnsOverHttpUnixSocket);
        $("#txtDnsOverHttpRealIpHeader").prop("disabled", !enableDnsOverHttpUnixSocket && !enableDnsOverHttpsUnixSocket && !enableDnsOverHttp && !enableDnsOverHttps);
    });

    $("#chkEnableDnsOverHttpsUnixSocket").on("click", function () {
        var enableDnsOverHttpUnixSocket = $("#chkEnableDnsOverHttpUnixSocket").prop("checked");
        var enableDnsOverHttpsUnixSocket = $("#chkEnableDnsOverHttpsUnixSocket").prop("checked");
        var enableDnsOverHttp = $("#chkEnableDnsOverHttp").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");
        var enableDnsOverTls = $("#chkEnableDnsOverTls").prop("checked");
        var enableDnsOverQuic = $("#chkEnableDnsOverQuic").prop("checked");

        $("#txtDnsOverHttpsUnixSocket").prop("disabled", !enableDnsOverHttpsUnixSocket);
        $("#txtDnsTlsCertificatePath").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic && !enableDnsOverHttpsUnixSocket);
        $("#txtDnsTlsCertificatePassword").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic && !enableDnsOverHttpsUnixSocket);
        $("#txtDnsTlsCertificateKeyPath").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic && !enableDnsOverHttpsUnixSocket);
        $("#txtDnsOverHttpRealIpHeader").prop("disabled", !enableDnsOverHttpUnixSocket && !enableDnsOverHttpsUnixSocket && !enableDnsOverHttp && !enableDnsOverHttps);
    });

    $("#chkEnableDnsOverTls").on("click", function () {
        var enableDnsOverHttpsUnixSocket = $("#chkEnableDnsOverHttpsUnixSocket").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");
        var enableDnsOverTls = $("#chkEnableDnsOverTls").prop("checked");
        var enableDnsOverQuic = $("#chkEnableDnsOverQuic").prop("checked");

        $("#txtDnsOverTlsPort").prop("disabled", !enableDnsOverTls);
        $("#txtDnsTlsCertificatePath").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic && !enableDnsOverHttpsUnixSocket);
        $("#txtDnsTlsCertificatePassword").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic && !enableDnsOverHttpsUnixSocket);
        $("#txtDnsTlsCertificateKeyPath").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic && !enableDnsOverHttpsUnixSocket);
    });

    $("#chkEnableDnsOverHttps").on("click", function () {
        var chkEnableEDnsClientSubnetSourceAddress = $("#chkEnableEDnsClientSubnetSourceAddress").prop("checked");
        var enableDnsOverUdpProxy = $("#chkEnableDnsOverUdpProxy").prop("checked");
        var enableDnsOverTcpProxy = $("#chkEnableDnsOverTcpProxy").prop("checked");
        var enableDnsOverHttpUnixSocket = $("#chkEnableDnsOverHttpUnixSocket").prop("checked");
        var enableDnsOverHttpsUnixSocket = $("#chkEnableDnsOverHttpsUnixSocket").prop("checked");
        var enableDnsOverHttp = $("#chkEnableDnsOverHttp").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");
        var enableDnsOverTls = $("#chkEnableDnsOverTls").prop("checked");
        var enableDnsOverQuic = $("#chkEnableDnsOverQuic").prop("checked");

        $("#chkEnableDnsOverHttp3").prop("disabled", !enableDnsOverHttps);
        $("#txtDnsOverHttpsPort").prop("disabled", !enableDnsOverHttps);
        $("#txtDnsReverseProxyNetworkACL").prop("disabled", !chkEnableEDnsClientSubnetSourceAddress && !enableDnsOverUdpProxy && !enableDnsOverTcpProxy && !enableDnsOverHttp && !enableDnsOverHttps);
        $("#txtDnsTlsCertificatePath").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic && !enableDnsOverHttpsUnixSocket);
        $("#txtDnsTlsCertificatePassword").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic && !enableDnsOverHttpsUnixSocket);
        $("#txtDnsTlsCertificateKeyPath").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic && !enableDnsOverHttpsUnixSocket);
        $("#txtDnsOverHttpRealIpHeader").prop("disabled", !enableDnsOverHttpUnixSocket && !enableDnsOverHttpsUnixSocket && !enableDnsOverHttp && !enableDnsOverHttps);
    });

    $("#chkEnableDnsOverQuic").on("click", function () {
        var enableDnsOverHttpsUnixSocket = $("#chkEnableDnsOverHttpsUnixSocket").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");
        var enableDnsOverTls = $("#chkEnableDnsOverTls").prop("checked");
        var enableDnsOverQuic = $("#chkEnableDnsOverQuic").prop("checked");

        $("#txtDnsOverQuicPort").prop("disabled", !enableDnsOverQuic);
        $("#txtDnsTlsCertificatePath").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic && !enableDnsOverHttpsUnixSocket);
        $("#txtDnsTlsCertificatePassword").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic && !enableDnsOverHttpsUnixSocket);
        $("#txtDnsTlsCertificateKeyPath").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic && !enableDnsOverHttpsUnixSocket);
    });

    $("#chkEnableConcurrentForwarding").on("click", function () {
        var concurrentForwarding = $("#chkEnableConcurrentForwarding").prop("checked");
        $("#txtForwarderConcurrency").prop("disabled", !concurrentForwarding)
    });

    $("input[type=radio][name=rdLoggingType]").on("change", function () {
        var rdLoggingType = $("input[name=rdLoggingType]:checked").val();
        var enableLogging = rdLoggingType.toLowerCase() != "none";

        $("#chkIgnoreResolverLogs").prop("disabled", !enableLogging);
        $("#chkNoStackTrace").prop("disabled", !enableLogging);
        $("#chkLogQueries").prop("disabled", !enableLogging);
        $("#chkUseLocalTime").prop("disabled", !enableLogging);
        $("#txtLogFolderPath").prop("disabled", !enableLogging);
    });

    $("#chkServeStale").on("click", function () {
        var serveStale = $("#chkServeStale").prop("checked");
        $("#txtServeStaleTtl").prop("disabled", !serveStale);
        $("#txtServeStaleAnswerTtl").prop("disabled", !serveStale);
        $("#txtServeStaleResetTtl").prop("disabled", !serveStale);
        $("#txtServeStaleMaxWaitTime").prop("disabled", !serveStale);
    });

    $("#optQuickClientBlockList").on("change", function () {
        var url = $("#optQuickClientBlockList").val();
        if ((url == null) || (url === ""))
            return;

        var existingList = $("#txtClientBlockListUrls").val();
        if (existingList.indexOf(url) < 0) {
            if ((existingList.length > 0) && !existingList.endsWith("\n"))
                existingList += "\n";

            $("#txtClientBlockListUrls").val(existingList + url + "\n");
        }

        $("#optQuickClientBlockList").val("");
    });

    $("#optQuickBlockList").on("change", function () {
        var selectedOption = $("#optQuickBlockList").val();

        switch (selectedOption) {
            case "blank":
                break;

            case "none":
                $("#txtBlockListUrls").val("");
                break;

            default:
                for (var i = 0; i < quickBlockLists.length; i++) {
                    if (quickBlockLists[i].name === selectedOption) {
                        var existingList = $("#txtBlockListUrls").val();

                        var newList = existingList;

                        for (var j = 0; j < quickBlockLists[i].urls.length; j++) {
                            var url = quickBlockLists[i].urls[j];

                            if (existingList.indexOf(url) < 0)
                                newList += url + "\n";
                        }

                        $("#txtBlockListUrls").val(newList);
                        break;
                    }
                }

                break;
        }
    });

    $("#optQuickForwarders").on("change", function () {
        var selectedOption = $("#optQuickForwarders").val();

        switch (selectedOption) {
            case "blank":
                break;

            case "none":
                $("#txtForwarders").val("");
                $("#rdForwarderProtocolUdp").prop("checked", true);
                break;

            default:
                for (var i = 0; i < quickForwardersList.length; i++) {
                    if (quickForwardersList[i].name === selectedOption) {
                        var forwarders = "";

                        for (var j = 0; j < quickForwardersList[i].addresses.length; j++) {
                            forwarders += quickForwardersList[i].addresses[j] + "\n";
                        }

                        $("#txtForwarders").val(forwarders);

                        switch (quickForwardersList[i].protocol.toUpperCase()) {
                            case "TCP":
                                $("#rdForwarderProtocolTcp").prop("checked", true);
                                break;

                            case "TLS":
                                $("#rdForwarderProtocolTls").prop("checked", true);
                                break;

                            case "HTTPS":
                                $("#rdForwarderProtocolHttps").prop("checked", true);
                                break;

                            case "QUIC":
                                $("#rdForwarderProtocolQuic").prop("checked", true);
                                break;

                            default:
                                $("#rdForwarderProtocolUdp").prop("checked", true);
                                break;
                        }

                        if (quickForwardersList[i].proxyType == null)
                            quickForwardersList[i].proxyType = "DefaultProxy";

                        switch (quickForwardersList[i].proxyType.toUpperCase()) {
                            case "SOCKS5":
                            case "HTTP":
                                if (quickForwardersList[i].proxyType.toUpperCase() == "SOCKS5")
                                    $("#rdProxyTypeSocks5").prop("checked", true);
                                else
                                    $("#rdProxyTypeHttp").prop("checked", true);

                                $("#txtProxyAddress").val(quickForwardersList[i].proxyAddress);
                                $("#txtProxyPort").val(quickForwardersList[i].proxyPort);
                                $("#txtProxyUsername").val(quickForwardersList[i].proxyUsername);
                                $("#txtProxyPassword").val(quickForwardersList[i].proxyPassword);

                                $("#txtProxyAddress").prop("disabled", false);
                                $("#txtProxyPort").prop("disabled", false);
                                $("#txtProxyUsername").prop("disabled", false);
                                $("#txtProxyPassword").prop("disabled", false);
                                break;

                            case "NONE":
                                $("#rdProxyTypeNone").prop("checked", true);

                                $("#txtProxyAddress").prop("disabled", true);
                                $("#txtProxyPort").prop("disabled", true);
                                $("#txtProxyUsername").prop("disabled", true);
                                $("#txtProxyPassword").prop("disabled", true);

                                $("#txtProxyAddress").val("");
                                $("#txtProxyPort").val("");
                                $("#txtProxyUsername").val("");
                                $("#txtProxyPassword").val("");
                                break;
                        }

                        break;
                    }
                }

                break;
        }
    });
});

function showAbout() {
    $("#mainPanelTabListAbout a").tab("show");

    setTimeout(function () {
        window.scroll({
            top: 0,
            left: 0,
            behavior: "smooth"
        });
    }, 500);
}

function initUpdateNotificationMenu() {
    var disableUpdateNotification = localStorage.getItem("disableUpdateNotification");
    if (disableUpdateNotification === "true") {
        $("#mnuDisableCheckForUpdateNotification").hide();
        $("#mnuEnableCheckForUpdateNotification").show();
    }
    else {
        $("#mnuEnableCheckForUpdateNotification").hide();
        $("#mnuDisableCheckForUpdateNotification").show();
    }
}

function disableUpdateNotification() {
    if (!confirm("Ohne Update-Hinweise zeigt die Weboberfläche nach der Anmeldung keine neuen Versionen mehr an.\r\n\r\nUpdate-Hinweise wirklich ausblenden?"))
        return;

    localStorage.setItem("disableUpdateNotification", true);
    $("#mnuDisableCheckForUpdateNotification").hide();
    $("#mnuEnableCheckForUpdateNotification").show();
    $("#lnkUpdateAvailable").hide();

    showAlert("success", "Hinweise ausgeblendet", "Update-Hinweise werden nicht mehr angezeigt.");
}

function enableUpdateNotification() {
    localStorage.setItem("disableUpdateNotification", false);
    $("#mnuEnableCheckForUpdateNotification").hide();
    $("#mnuDisableCheckForUpdateNotification").show();

    showAlert("success", "Hinweise eingeblendet", "Update-Hinweise werden wieder angezeigt.");
}

function checkForUpdate(force) {
    if (!force) {
        var disableUpdateNotification = localStorage.getItem("disableUpdateNotification");
        if (disableUpdateNotification === "true")
            return;
    }

    HTTPRequest({
        url: "api/user/checkForUpdate",
        token: sessionData.token,
        success: function (responseJSON) {
            var lnkUpdateAvailable = $("#lnkUpdateAvailable");

            if (responseJSON.response.updateAvailable) {
                $("#lblUpdateVersion").text(responseJSON.response.updateVersion);
                $("#lblCurrentVersion").text(responseJSON.response.currentVersion);

                if (responseJSON.response.updateTitle == null)
                    responseJSON.response.updateTitle = "Neue Version verfügbar!";

                lnkUpdateAvailable.text(responseJSON.response.updateTitle);
                $("#lblUpdateAvailableTitle").text(responseJSON.response.updateTitle);

                var lblUpdateMessage = $("#lblUpdateMessage");
                var lnkUpdateDownload = $("#lnkUpdateDownload");
                var lnkUpdateInstructions = $("#lnkUpdateInstructions");
                var lnkUpdateChangeLog = $("#lnkUpdateChangeLog");

                if (responseJSON.response.updateMessage == null) {
                    lblUpdateMessage.hide();
                }
                else {
                    lblUpdateMessage.text(responseJSON.response.updateMessage);
                    lblUpdateMessage.show();
                }

                if (responseJSON.response.downloadLink == null) {
                    lnkUpdateDownload.hide();
                }
                else {
                    lnkUpdateDownload.attr("href", responseJSON.response.downloadLink);
                    lnkUpdateDownload.show();
                }

                if (responseJSON.response.instructionsLink == null) {
                    lnkUpdateInstructions.hide();
                }
                else {
                    lnkUpdateInstructions.attr("href", responseJSON.response.instructionsLink);
                    lnkUpdateInstructions.show();
                }

                if (responseJSON.response.changeLogLink == null) {
                    lnkUpdateChangeLog.hide();
                }
                else {
                    lnkUpdateChangeLog.attr("href", responseJSON.response.changeLogLink);
                    lnkUpdateChangeLog.show();
                }

                lnkUpdateAvailable.show();
            }
            else {
                lnkUpdateAvailable.hide();

                if (force) {
                    if (responseJSON.response.dnsServerEnableCheckForUpdate)
                        showAlert("success", "Kein Update verfügbar", "Die installierte Version ist aktuell.");
                    else
                        showAlert("danger", "Update-Prüfung deaktiviert", "Die Update-Prüfung ist in den Einstellungen deaktiviert.");
                }
            }
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function loadQuickBlockLists() {
    $.ajax({
        type: "GET",
        url: "json/quick-block-lists-builtin.json",
        dataType: "json",
        cache: false,
        async: false,
        success: function (responseJSON, status, jqXHR) {
            loadQuickBlockListsFrom(responseJSON);
        },
        error: function (jqXHR, textStatus, errorThrown) {
            showAlert("danger", "Fehler", "Die Blocklisten-Schnellauswahl konnte nicht geladen werden: " + jqXHR.status + " " + jqXHR.statusText);
        }
    });
}

function loadQuickBlockListsFrom(responseJSON) {
    var htmlList = "<option value=\"blank\" selected></option><option value=\"none\">Leeren</option>";
    var currentGroup = null;

    for (var i = 0; i < responseJSON.length; i++) {
        var group = responseJSON[i].group == null ? null : responseJSON[i].group;

        if (group !== currentGroup) {
            if (currentGroup !== null)
                htmlList += "</optgroup>";

            if (group !== null)
                htmlList += "<optgroup label=\"" + htmlEncode(group) + "\">";

            currentGroup = group;
        }

        htmlList += "<option>" + htmlEncode(responseJSON[i].name) + "</option>";
    }

    if (currentGroup !== null)
        htmlList += "</optgroup>";

    quickBlockLists = responseJSON;
    $("#optQuickBlockList").html(htmlList);
}

function loadQuickForwardersList() {
    $.ajax({
        type: "GET",
        url: "json/quick-forwarders-list-custom.json",
        dataType: "json",
        cache: false,
        async: false,
        success: function (responseJSON, status, jqXHR) {
            loadQuickForwardersListFrom(responseJSON);
        },
        error: function (jqXHR, textStatus, errorThrown) {
            $.ajax({
                type: "GET",
                url: "json/quick-forwarders-list-builtin.json",
                dataType: "json",
                cache: false,
                async: false,
                success: function (responseJSON, status, jqXHR) {
                    loadQuickForwardersListFrom(responseJSON);
                },
                error: function (jqXHR, textStatus, errorThrown) {
                    showAlert("danger", "Fehler", "Die Forwarder-Schnellauswahl konnte nicht geladen werden: " + jqXHR.status + " " + jqXHR.statusText);
                }
            });
        }
    });
}

function loadQuickForwardersListFrom(responseJSON) {
    var htmlList = "<option value=\"blank\" selected></option><option value=\"none\">Leeren</option>";

    for (var i = 0; i < responseJSON.length; i++) {
        htmlList += "<option>" + htmlEncode(responseJSON[i].name) + "</option>";
    }

    quickForwardersList = responseJSON;
    $("#optQuickForwarders").html(htmlList);
}

function refreshDnsSettings() {
    var divDnsSettingsLoader = $("#divDnsSettingsLoader");
    var divDnsSettings = $("#divDnsSettings");

    divDnsSettings.hide();
    divDnsSettingsLoader.show();

    HTTPRequest({
        url: "api/settings/get",
        token: sessionData.token,
        success: function (responseJSON) {
            updateDnsSettingsDataAndGui(responseJSON);
            loadDnsSettings(responseJSON);
            checkForReverseProxy(responseJSON);

            $("#btnSaveSettings").toggle(sessionData.info.permissions.Settings.canModify);
            $("#btnSettingsFlushCache").toggle(sessionData.info.permissions.Cache.canDelete);
            $("#btnShowBackupSettingsModal").toggle(sessionData.info.permissions.Settings.canDelete);
            $("#btnShowRestoreSettingsModal").toggle(sessionData.info.permissions.Settings.canDelete);

            refreshIpv6UpstreamStatus();

            divDnsSettingsLoader.hide();
            divDnsSettings.show();
        },
        error: function () {
            divDnsSettingsLoader.hide();
            divDnsSettings.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divDnsSettingsLoader
    });
}

function renderIpv6UpstreamStatus(serverStatus) {
    var div = $("#divIpv6UpstreamStatus");

    if (serverStatus == null) {
        div.html("&ndash;");
        return;
    }

    if (serverStatus.ipv6Mode === "Disabled") {
        div.html("<span class=\"label label-default\">IPv6 deaktiviert</span>");
    }
    else if (serverStatus.ipv6UpstreamAvailable) {
        div.html("<span class=\"label label-success\">IPv6 wird genutzt</span>");
    }
    else if (serverStatus.ipv6UpstreamUnavailableUntil != null) {
        div.html("<span class=\"label label-warning\">IPv6 ausgesetzt</span> bis " + htmlEncode(moment(serverStatus.ipv6UpstreamUnavailableUntil).local().format("LTS")) + " (" + htmlEncode(moment(serverStatus.ipv6UpstreamUnavailableUntil).fromNow()) + "), bis dahin nur IPv4");
    }
    else {
        div.html("<span class=\"label label-warning\">IPv6 ausgesetzt</span>");
    }

    var ipv6Enabled = serverStatus.ipv6Mode !== "Disabled";
    $("#btnIpv6Probe").prop("disabled", !ipv6Enabled);
    $("#btnIpv6Reset").prop("disabled", !ipv6Enabled);
}

function refreshIpv6UpstreamStatus() {
    HTTPRequest({
        url: "api/dashboard/metrics/json",
        token: sessionData.token,
        success: function (responseJSON) {
            renderIpv6UpstreamStatus(responseJSON.response.serverStatus);
        },
        error: function () {
            renderIpv6UpstreamStatus(null);
        },
        invalidToken: function () {
            showPageLogin();
        },
        dontHideAlert: true
    });
}

function probeIpv6Upstream(objBtn, reset) {
    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/dashboard/ipv6/probe?reset=" + (reset ? "true" : "false"),
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");
            renderIpv6UpstreamStatus(responseJSON.response);

            if (responseJSON.response.ipv6UpstreamAvailable)
                showAlert("success", "IPv6 erreichbar", "Die IPv6-Root-Server antworten. Ausgehende IPv6-Anfragen sind aktiv.");
            else
                showAlert("warning", "IPv6 nicht erreichbar", "Die IPv6-Root-Server antworten nicht. Ausgehende Anfragen laufen vorerst nur über IPv4.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function getArrayAsString(array) {
    var value = "";

    for (var i = 0; i < array.length; i++)
        value += array[i] + "\r\n";

    return value;
}

function updateDnsSettingsDataAndGui(responseJSON) {
    sessionData.info.dnsServerDomain = responseJSON.response.dnsServerDomain;
    sessionData.info.uptimestamp = responseJSON.response.uptimestamp;

    document.title = responseJSON.response.dnsServerDomain + " - " + "ZenitiumDNS v" + responseJSON.response.version;
    $("#lblAboutVersion").text(responseJSON.response.version);
    $("#lblAboutUptime").text(moment(responseJSON.response.uptimestamp).local().format("lll") + " (" + moment(responseJSON.response.uptimestamp).fromNow() + ")");
    $("#lblDnsServerDomain").text(responseJSON.response.dnsServerDomain);
}

function loadDnsSettings(responseJSON) {
    $("#txtDnsServerDomain").val(responseJSON.response.dnsServerDomain);

    var dnsServerLocalEndPoints = responseJSON.response.dnsServerLocalEndPoints;
    if (dnsServerLocalEndPoints == null)
        $("#txtDnsServerLocalEndPoints").val("");
    else
        $("#txtDnsServerLocalEndPoints").val(getArrayAsString(dnsServerLocalEndPoints));

    $("#txtDnsServerIPv4SourceAddresses").val(getArrayAsString(responseJSON.response.dnsServerIPv4SourceAddresses));
    $("#txtDnsServerIPv6SourceAddresses").val(getArrayAsString(responseJSON.response.dnsServerIPv6SourceAddresses));

    $("#txtDefaultRecordTtl").val(responseJSON.response.defaultRecordTtl);

    sessionData.info.defaultRecordTtl = responseJSON.response.defaultRecordTtl;
    sessionData.info.defaultNsRecordTtl = responseJSON.response.defaultNsRecordTtl;
    sessionData.info.defaultSoaRecordTtl = responseJSON.response.defaultSoaRecordTtl;

    $("#txtDefaultResponsiblePerson").val(responseJSON.response.defaultResponsiblePerson);

    $("#chkDnsServerEnableCheckForUpdate").prop("checked", responseJSON.response.dnsServerEnableCheckForUpdate);
    $("#chkDnsAppsEnableAutomaticUpdate").prop("checked", responseJSON.response.dnsAppsEnableAutomaticUpdate);

    switch (responseJSON.response.ipv6Mode) {
        case "Enabled":
            $("#rdIPv6ModeEnabled").prop("checked", true);
            break;

        case "Preferred":
            $("#rdIPv6ModePreferred").prop("checked", true);
            break;

        case "Disabled":
        default:
            $("#rdIPv6ModeDisabled").prop("checked", true);
            break;
    }

    $("#chkIpv6AutoFallback").prop("checked", responseJSON.response.ipv6AutoFallback !== false);
    $("#txtUdpListenerThreads").val(responseJSON.response.udpListenerThreads);
    $("#txtMaxPendingStreamRequests").val(responseJSON.response.maxPendingStreamRequests);

    $("#chkRequestFilterMalformed").prop("checked", responseJSON.response.requestFilterMalformed);
    $("#txtRequestFilterMaxSize").val(responseJSON.response.requestFilterMaxSize);
    $("#chkRequestFilterOpcode").prop("checked", responseJSON.response.requestFilterOpcode);
    $("#chkRequestFilterClass").prop("checked", responseJSON.response.requestFilterClass);
    $("#chkRequestFilterAny").prop("checked", responseJSON.response.requestFilterAny);
    $("#chkRequestFilterZoneTransfer").prop("checked", responseJSON.response.requestFilterZoneTransfer);
    $("#chkRequestFilterNoRecursion").prop("checked", responseJSON.response.requestFilterNoRecursion);
    $("#chkRequestFilterEdnsVersion").prop("checked", responseJSON.response.requestFilterEdnsVersion);
    $("#chkRequestFilterRefuseOnly").prop("checked", responseJSON.response.requestFilterRefuseOnly);

    $("#txtClientBlockListUrls").val(getArrayAsString(responseJSON.response.clientBlockListUrls));
    $("#txtClientBlockListUpdateIntervalHours").val(responseJSON.response.clientBlockListUpdateIntervalHours);
    $("#optQuickClientBlockList").val("");

    if ((responseJSON.response.clientBlockListUrls == null) || (responseJSON.response.clientBlockListUrls.length === 0))
        $("#lblClientBlockListStatus").text("Keine Listen eingetragen.");
    else
        $("#lblClientBlockListStatus").text(responseJSON.response.clientBlockListAddressRanges.toLocaleString("de-DE") + " Adressbereiche geladen, zuletzt aktualisiert " + (responseJSON.response.clientBlockListLastUpdatedOn == null ? "noch nie" : "am " + moment(responseJSON.response.clientBlockListLastUpdatedOn).local().format("DD.MM.YYYY HH:mm")) + ", " + responseJSON.response.clientBlockListDrops.toLocaleString("de-DE") + " Anfragen oder Verbindungen seit dem Start verworfen.");

    $(".rule-hits").each(function () {
        var matches = responseJSON.response.requestFilterMatches == null ? null : responseJSON.response.requestFilterMatches[$(this).attr("data-rule")];
        $(this).text(matches == null ? "" : Number(matches).toLocaleString("de-DE") + " Treffer");
    });

    $("#chkEnableUdpSocketPool").prop("checked", responseJSON.response.enableUdpSocketPool);
    $("#txtUdpSocketPoolExcludedPorts").prop("disabled", !responseJSON.response.enableUdpSocketPool);
    $("#txtUdpSocketPoolExcludedPorts").val(getArrayAsString(responseJSON.response.socketPoolExcludedPorts));
    $("#txtEdnsUdpPayloadSize").val(responseJSON.response.udpPayloadSize);
    $("#chkDnssecValidation").prop("checked", responseJSON.response.dnssecValidation);
    $("#chkDnssecPostQuantumDowngradeProtection").prop("checked", responseJSON.response.dnssecPostQuantumDowngradeProtection !== false);

    $("#chkEDnsClientSubnet").prop("checked", responseJSON.response.eDnsClientSubnet);
    $("#txtEDnsClientSubnetIPv4PrefixLength").prop("disabled", !responseJSON.response.eDnsClientSubnet);
    $("#txtEDnsClientSubnetIPv6PrefixLength").prop("disabled", !responseJSON.response.eDnsClientSubnet);
    $("#txtEDnsClientSubnetIpv4Override").prop("disabled", !responseJSON.response.eDnsClientSubnet);
    $("#txtEDnsClientSubnetIpv6Override").prop("disabled", !responseJSON.response.eDnsClientSubnet);

    $("#txtEDnsClientSubnetIPv4PrefixLength").val(responseJSON.response.eDnsClientSubnetIPv4PrefixLength);
    $("#txtEDnsClientSubnetIPv6PrefixLength").val(responseJSON.response.eDnsClientSubnetIPv6PrefixLength);
    $("#txtEDnsClientSubnetIpv4Override").val(responseJSON.response.eDnsClientSubnetIpv4Override);
    $("#txtEDnsClientSubnetIpv6Override").val(responseJSON.response.eDnsClientSubnetIpv6Override);

    $("#tableQpsPrefixLimitsIPv4").html("");

    if (responseJSON.response.qpsPrefixLimitsIPv4 != null) {
        for (var i = 0; i < responseJSON.response.qpsPrefixLimitsIPv4.length; i++) {
            addQpsPrefixLimitsIPv4Row(responseJSON.response.qpsPrefixLimitsIPv4[i].prefix, responseJSON.response.qpsPrefixLimitsIPv4[i].udpLimit, responseJSON.response.qpsPrefixLimitsIPv4[i].tcpLimit);
        }
    }

    $("#tableQpsPrefixLimitsIPv6").html("");

    if (responseJSON.response.qpsPrefixLimitsIPv6 != null) {
        for (var i = 0; i < responseJSON.response.qpsPrefixLimitsIPv6.length; i++) {
            addQpsPrefixLimitsIPv6Row(responseJSON.response.qpsPrefixLimitsIPv6[i].prefix, responseJSON.response.qpsPrefixLimitsIPv6[i].udpLimit, responseJSON.response.qpsPrefixLimitsIPv6[i].tcpLimit);
        }
    }

    $("#txtRateLimitBurstSeconds").val(responseJSON.response.rateLimitBurstSeconds);
    $("#txtRateLimitUdpTruncation").val(responseJSON.response.rateLimitUdpTruncationPercentage);
    $("#txtRateLimitBypassList").val(getArrayAsString(responseJSON.response.rateLimitBypassList));

    $("#txtClientTimeout").val(responseJSON.response.clientTimeout);
    $("#txtTcpSendTimeout").val(responseJSON.response.tcpSendTimeout);
    $("#txtTcpReceiveTimeout").val(responseJSON.response.tcpReceiveTimeout);
    $("#txtQuicIdleTimeout").val(responseJSON.response.quicIdleTimeout);
    $("#txtQuicMaxInboundStreams").val(responseJSON.response.quicMaxInboundStreams);
    $("#txtListenBacklog").val(responseJSON.response.listenBacklog);
    $("#txtUdpSendBufferSizeKB").val(responseJSON.response.udpSendBufferSizeKB);
    $("#txtUdpReceiveBufferSizeKB").val(responseJSON.response.udpReceiveBufferSizeKB);
    $("#txtMaxConcurrentResolutionsPerCore").val(responseJSON.response.maxConcurrentResolutionsPerCore);

    var webServiceLocalAddresses = responseJSON.response.webServiceLocalAddresses;
    if (webServiceLocalAddresses == null)
        $("#txtWebServiceLocalAddresses").val("");
    else
        $("#txtWebServiceLocalAddresses").val(getArrayAsString(webServiceLocalAddresses));

    $("#txtWebServiceHttpPort").val(responseJSON.response.webServiceHttpPort);

    $("#chkWebServiceEnableHttpUnixSocket").prop("checked", responseJSON.response.webServiceEnableHttpUnixSocket);
    $("#txtWebServiceHttpUnixSocket").prop("disabled", !responseJSON.response.webServiceEnableHttpUnixSocket);
    $("#txtWebServiceHttpUnixSocket").val(responseJSON.response.webServiceHttpUnixSocket);

    $("#chkWebServiceEnableTlsUnixSocket").prop("checked", responseJSON.response.webServiceEnableTlsUnixSocket);
    $("#txtWebServiceTlsUnixSocket").prop("disabled", !responseJSON.response.webServiceEnableTlsUnixSocket);
    $("#txtWebServiceTlsUnixSocket").val(responseJSON.response.webServiceTlsUnixSocket);

    $("#chkWebServiceEnableTls").prop("checked", responseJSON.response.webServiceEnableTls);

    $("#chkWebServiceEnableHttp3").prop("disabled", !responseJSON.response.webServiceEnableTls);
    $("#chkWebServiceHttpToTlsRedirect").prop("disabled", !responseJSON.response.webServiceEnableTls);
    $("#chkWebServiceUseSelfSignedTlsCertificate").prop("disabled", !responseJSON.response.webServiceEnableTls && !responseJSON.response.webServiceEnableTlsUnixSocket);
    $("#txtWebServiceTlsPort").prop("disabled", !responseJSON.response.webServiceEnableTls);

    $("#chkWebServiceEnableHttp3").prop("checked", responseJSON.response.webServiceEnableHttp3);
    $("#chkWebServiceHttpToTlsRedirect").prop("checked", responseJSON.response.webServiceHttpToTlsRedirect);
    $("#chkWebServiceUseSelfSignedTlsCertificate").prop("checked", responseJSON.response.webServiceUseSelfSignedTlsCertificate);
    $("#txtWebServiceTlsPort").val(responseJSON.response.webServiceTlsPort);

    $("#txtWebServiceReverseProxyAddresses").val(getArrayAsString(responseJSON.response.webServiceReverseProxyAddresses));

    $("#txtWebServiceRealIpHeader").val(responseJSON.response.webServiceRealIpHeader);
    $("#lblWebServiceRealIpNginx").text("proxy_set_header " + responseJSON.response.webServiceRealIpHeader + " $remote_addr;");

    $("#txtWebServiceCspFrameAncestorsHeader").val(responseJSON.response.webServiceCspFrameAncestorsHeader);

    $("#txtWebServiceTlsCertificatePath").prop("disabled", !responseJSON.response.webServiceEnableTls && !responseJSON.response.webServiceEnableTlsUnixSocket);
    $("#txtWebServiceTlsCertificatePassword").prop("disabled", !responseJSON.response.webServiceEnableTls && !responseJSON.response.webServiceEnableTlsUnixSocket);
    $("#txtWebServiceTlsCertificateKeyPath").prop("disabled", !responseJSON.response.webServiceEnableTls && !responseJSON.response.webServiceEnableTlsUnixSocket);

    $("#txtWebServiceTlsCertificatePath").val(responseJSON.response.webServiceTlsCertificatePath);
    $("#txtWebServiceTlsCertificateKeyPath").val(responseJSON.response.webServiceTlsCertificateKeyPath == null ? "" : responseJSON.response.webServiceTlsCertificateKeyPath);

    if (responseJSON.response.webServiceTlsCertificatePath == null)
        $("#txtWebServiceTlsCertificatePassword").val("");
    else
        $("#txtWebServiceTlsCertificatePassword").val(responseJSON.response.webServiceTlsCertificatePassword);

    $("#chkEnableEDnsClientSubnetSourceAddress").prop("checked", responseJSON.response.enableEDnsClientSubnetSourceAddress);
    $("#chkEnableDnsOverUdpProxy").prop("checked", responseJSON.response.enableDnsOverUdpProxy);
    $("#chkEnableDnsOverTcpProxy").prop("checked", responseJSON.response.enableDnsOverTcpProxy);
    $("#chkEnableDnsOverHttp").prop("checked", responseJSON.response.enableDnsOverHttp);
    $("#chkEnableDnsOverHttpUnixSocket").prop("checked", responseJSON.response.enableDnsOverHttpUnixSocket);
    $("#chkEnableDnsOverHttpsUnixSocket").prop("checked", responseJSON.response.enableDnsOverHttpsUnixSocket);
    $("#chkEnableDnsOverTls").prop("checked", responseJSON.response.enableDnsOverTls);
    $("#chkEnableDnsOverHttps").prop("checked", responseJSON.response.enableDnsOverHttps);
    $("#chkEnableDnsOverHttp3").prop("disabled", !responseJSON.response.enableDnsOverHttps);
    $("#chkEnableDnsOverHttp3").prop("checked", responseJSON.response.enableDnsOverHttp3);
    $("#chkEnableDnsOverQuic").prop("checked", responseJSON.response.enableDnsOverQuic);

    $("#chkEnableDnsOverHttpHelpRedirect").prop("checked", responseJSON.response.enableDnsOverHttpHelpRedirect);

    $("#txtDnsOverUdpProxyPort").prop("disabled", !responseJSON.response.enableDnsOverUdpProxy);
    $("#txtDnsOverTcpProxyPort").prop("disabled", !responseJSON.response.enableDnsOverTcpProxy);
    $("#txtDnsOverHttpPort").prop("disabled", !responseJSON.response.enableDnsOverHttp);
    $("#txtDnsOverHttpUnixSocket").prop("disabled", !responseJSON.response.enableDnsOverHttpUnixSocket);
    $("#txtDnsOverHttpsUnixSocket").prop("disabled", !responseJSON.response.enableDnsOverHttpsUnixSocket);
    $("#txtDnsOverTlsPort").prop("disabled", !responseJSON.response.enableDnsOverTls);
    $("#txtDnsOverHttpsPort").prop("disabled", !responseJSON.response.enableDnsOverHttps);
    $("#txtDnsOverQuicPort").prop("disabled", !responseJSON.response.enableDnsOverQuic);

    $("#txtDnsOverUdpProxyPort").val(responseJSON.response.dnsOverUdpProxyPort);
    $("#txtDnsOverTcpProxyPort").val(responseJSON.response.dnsOverTcpProxyPort);
    $("#txtDnsOverHttpPort").val(responseJSON.response.dnsOverHttpPort);
    $("#txtDnsOverHttpUnixSocket").val(responseJSON.response.dnsOverHttpUnixSocket);
    $("#txtDnsOverHttpsUnixSocket").val(responseJSON.response.dnsOverHttpsUnixSocket);
    $("#txtDnsOverTlsPort").val(responseJSON.response.dnsOverTlsPort);
    $("#txtDnsOverHttpsPort").val(responseJSON.response.dnsOverHttpsPort);
    $("#txtDnsOverQuicPort").val(responseJSON.response.dnsOverQuicPort);

    $("#txtDnsReverseProxyNetworkACL").prop("disabled", !responseJSON.response.enableEDnsClientSubnetSourceAddress && !responseJSON.response.enableDnsOverUdpProxy && !responseJSON.response.enableDnsOverTcpProxy && !responseJSON.response.enableDnsOverHttp && !responseJSON.response.enableDnsOverHttps);
    $("#txtDnsReverseProxyNetworkACL").val(getArrayAsString(responseJSON.response.dnsReverseProxyNetworkACL));

    $("#txtDnsOverHttpRealIpHeader").prop("disabled", !responseJSON.response.enableDnsOverHttpUnixSocket && !responseJSON.response.enableDnsOverHttpsUnixSocket && !responseJSON.response.enableDnsOverHttp && !responseJSON.response.enableDnsOverHttps);
    $("#txtDnsOverHttpRealIpHeader").val(responseJSON.response.dnsOverHttpRealIpHeader);
    $("#lblDnsOverHttpRealIpNginx").text("proxy_set_header " + responseJSON.response.dnsOverHttpRealIpHeader + " $remote_addr;");

    $("#txtDnsTlsCertificatePath").prop("disabled", !responseJSON.response.enableDnsOverTls && !responseJSON.response.enableDnsOverHttps && !responseJSON.response.enableDnsOverQuic && !responseJSON.response.enableDnsOverHttpsUnixSocket);
    $("#txtDnsTlsCertificatePassword").prop("disabled", !responseJSON.response.enableDnsOverTls && !responseJSON.response.enableDnsOverHttps && !responseJSON.response.enableDnsOverQuic && !responseJSON.response.enableDnsOverHttpsUnixSocket);
    $("#txtDnsTlsCertificateKeyPath").prop("disabled", !responseJSON.response.enableDnsOverTls && !responseJSON.response.enableDnsOverHttps && !responseJSON.response.enableDnsOverQuic && !responseJSON.response.enableDnsOverHttpsUnixSocket);

    $("#txtDnsTlsCertificatePath").val(responseJSON.response.dnsTlsCertificatePath);
    $("#txtDnsTlsCertificateKeyPath").val(responseJSON.response.dnsTlsCertificateKeyPath == null ? "" : responseJSON.response.dnsTlsCertificateKeyPath);

    $("#chkEnableDdr").prop("checked", responseJSON.response.enableDdr);
    $("#chkDdrOnlyUnencrypted").prop("checked", responseJSON.response.ddrOnlyUnencrypted);

    if ((responseJSON.response.ddrRecords == null) || (responseJSON.response.ddrRecords.length === 0))
        $("#preDdrRecords").text("Keine Einträge: Es ist kein TLS-Zertifikat geladen oder kein verschlüsselter Dienst aktiv.");
    else
        $("#preDdrRecords").text(responseJSON.response.ddrRecords.join("\n"));

    if (responseJSON.response.dnsTlsCertificatePath == null)
        $("#txtDnsTlsCertificatePassword").val("");
    else
        $("#txtDnsTlsCertificatePassword").val(responseJSON.response.dnsTlsCertificatePassword);

    $("#lblDoHHost").text(window.location.hostname + (responseJSON.response.dnsOverHttpPort == 80 ? "" : ":" + responseJSON.response.dnsOverHttpPort));
    $("#lblDoTHost").text("tls-certificate-domain:" + responseJSON.response.dnsOverTlsPort);
    $("#lblDoQHost").text("tls-certificate-domain:" + responseJSON.response.dnsOverQuicPort);
    $("#lblDoHsHost").text("tls-certificate-domain" + (responseJSON.response.dnsOverHttpsPort == 443 ? "" : ":" + responseJSON.response.dnsOverHttpsPort));

    $("#txtRecursionNetworkACL").prop("disabled", true);

    switch (responseJSON.response.recursion) {
        case "Allow":
            $("#rdRecursionAllow").prop("checked", true);
            break;

        case "AllowOnlyForPrivateNetworks":
            $("#rdRecursionAllowOnlyForPrivateNetworks").prop("checked", true);
            break;

        case "UseSpecifiedNetworkACL":
            $("#rdRecursionUseSpecifiedNetworkACL").prop("checked", true);
            $("#txtRecursionNetworkACL").prop("disabled", false);
            break;

        case "Deny":
        default:
            $("#rdRecursionDeny").prop("checked", true);
            break;
    }

    $("#txtRecursionNetworkACL").val(getArrayAsString(responseJSON.response.recursionNetworkACL));

    $("#chkRandomizeName").prop("checked", responseJSON.response.randomizeName);
    $("#chkQnameMinimization").prop("checked", responseJSON.response.qnameMinimization);
    $("#chkLocallyServedDnsZones").prop("checked", responseJSON.response.locallyServedDnsZones);

    $("#txtResolverRetries").val(responseJSON.response.resolverRetries);
    $("#txtResolverTimeout").val(responseJSON.response.resolverTimeout);
    $("#txtResolverConcurrency").val(responseJSON.response.resolverConcurrency);
    $("#txtResolverMaxStackCount").val(responseJSON.response.resolverMaxStackCount);

    $("#chkSaveCache").prop("checked", responseJSON.response.saveCache);

    $("#chkServeStale").prop("checked", responseJSON.response.serveStale);

    $("#txtServeStaleTtl").prop("disabled", !responseJSON.response.serveStale);
    $("#txtServeStaleAnswerTtl").prop("disabled", !responseJSON.response.serveStale);
    $("#txtServeStaleResetTtl").prop("disabled", !responseJSON.response.serveStale);
    $("#txtServeStaleMaxWaitTime").prop("disabled", !responseJSON.response.serveStale);

    $("#txtServeStaleTtl").val(responseJSON.response.serveStaleTtl);
    $("#txtServeStaleAnswerTtl").val(responseJSON.response.serveStaleAnswerTtl);
    $("#txtServeStaleResetTtl").val(responseJSON.response.serveStaleResetTtl);
    $("#txtServeStaleMaxWaitTime").val(responseJSON.response.serveStaleMaxWaitTime);

    $("#txtCacheMaximumEntries").val(responseJSON.response.cacheMaximumEntries);
    $("#txtCacheMinimumRecordTtl").val(responseJSON.response.cacheMinimumRecordTtl);
    $("#txtCacheMaximumRecordTtl").val(responseJSON.response.cacheMaximumRecordTtl);
    $("#txtCacheNegativeRecordTtl").val(responseJSON.response.cacheNegativeRecordTtl);
    $("#txtCacheFailureRecordTtl").val(responseJSON.response.cacheFailureRecordTtl);

    $("#txtCachePrefetchEligibility").val(responseJSON.response.cachePrefetchEligibility);
    $("#txtCachePrefetchTrigger").val(responseJSON.response.cachePrefetchTrigger);

    $("#chkEnableBlocking").prop("checked", responseJSON.response.enableBlocking);

    $("#chkAllowTxtBlockingReport").prop("disabled", !responseJSON.response.enableBlocking);
    $("#txtTemporaryDisableBlockingMinutes").prop("disabled", !responseJSON.response.enableBlocking);
    $("#btnTemporaryDisableBlockingNow").prop("disabled", !responseJSON.response.enableBlocking);
    $("#txtBlockingBypassList").prop("disabled", !responseJSON.response.enableBlocking);
    $("#rdBlockingTypeAnyAddress").prop("disabled", !responseJSON.response.enableBlocking);
    $("#rdBlockingTypeNxDomain").prop("disabled", !responseJSON.response.enableBlocking);
    $("#rdBlockingTypeCustomAddress").prop("disabled", !responseJSON.response.enableBlocking);
    $("#txtBlockingAnswerTtl").prop("disabled", !responseJSON.response.enableBlocking);
    $("#txtBlockingNegativeTtl").prop("disabled", !responseJSON.response.enableBlocking);
    $("#txtBlockingReportText").prop("disabled", !responseJSON.response.enableBlocking);
    $("#txtBlockListUrls").prop("disabled", !responseJSON.response.enableBlocking);
    $("#optQuickBlockList").prop("disabled", !responseJSON.response.enableBlocking);

    $("#chkAllowTxtBlockingReport").prop("checked", responseJSON.response.allowTxtBlockingReport);

    if (responseJSON.response.temporaryDisableBlockingTill == null)
        $("#lblTemporaryDisableBlockingTill").text("nicht pausiert");
    else
        $("#lblTemporaryDisableBlockingTill").text(moment(responseJSON.response.temporaryDisableBlockingTill).local().format("DD.MM.YYYY HH:mm:ss"));

    $("#txtTemporaryDisableBlockingMinutes").val("");

    $("#txtCustomBlockingAddresses").prop("disabled", true);

    $("#txtBlockingBypassList").val(getArrayAsString(responseJSON.response.blockingBypassList));

    switch (responseJSON.response.blockingType) {
        case "NxDomain":
            $("#rdBlockingTypeNxDomain").prop("checked", true);
            break;

        case "CustomAddress":
            $("#rdBlockingTypeCustomAddress").prop("checked", true);
            $("#txtCustomBlockingAddresses").prop("disabled", !responseJSON.response.enableBlocking);
            break;

        case "AnyAddress":
        default:
            $("#rdBlockingTypeAnyAddress").prop("checked", true);
            break;
    }

    $("#txtCustomBlockingAddresses").val(getArrayAsString(responseJSON.response.customBlockingAddresses));

    $("#txtBlockingAnswerTtl").val(responseJSON.response.blockingAnswerTtl);
    $("#txtBlockingNegativeTtl").val(responseJSON.response.blockingNegativeTtl);
    $("#txtBlockingReportText").val(responseJSON.response.blockingReportText == null ? "" : responseJSON.response.blockingReportText);

    var blockListUrls = responseJSON.response.blockListUrls;
    if (blockListUrls == null) {
        $("#txtBlockListUrls").val("");
        $("#btnUpdateBlockListsNow").prop("disabled", true);
    }
    else {
        $("#txtBlockListUrls").val(getArrayAsString(blockListUrls));
        $("#btnUpdateBlockListsNow").prop("disabled", false);
    }

    $("#optQuickBlockList").val("blank");

    $("#txtBlockListUpdateIntervalHours").val(responseJSON.response.blockListUpdateIntervalHours);

    if (responseJSON.response.blockListNextUpdatedOn == null) {
        $("#lblBlockListNextUpdatedOn").text("nicht geplant");
    }
    else {
        var blockListNextUpdatedOn = moment(responseJSON.response.blockListNextUpdatedOn);

        if (moment().utc().isBefore(blockListNextUpdatedOn))
            $("#lblBlockListNextUpdatedOn").text(blockListNextUpdatedOn.local().format("DD.MM.YYYY HH:mm:ss"));
        else
            $("#lblBlockListNextUpdatedOn").text("wird gerade aktualisiert");
    }

    var proxy = responseJSON.response.proxy;
    if (proxy === null) {
        $("#rdProxyTypeNone").prop("checked", true);

        $("#txtProxyAddress").prop("disabled", true);
        $("#txtProxyPort").prop("disabled", true);
        $("#txtProxyUsername").prop("disabled", true);
        $("#txtProxyPassword").prop("disabled", true);
        $("#txtProxyBypassList").prop("disabled", true);

        $("#txtProxyAddress").val("");
        $("#txtProxyPort").val("");
        $("#txtProxyUsername").val("");
        $("#txtProxyPassword").val("");
        $("#txtProxyBypassList").val("");
    }
    else {
        switch (proxy.type.toLowerCase()) {
            case "http":
                $("#rdProxyTypeHttp").prop("checked", true);
                break;

            case "socks5":
                $("#rdProxyTypeSocks5").prop("checked", true);
                break;

            default:
                $("#rdProxyTypeNone").prop("checked", true);
                break;
        }

        $("#txtProxyAddress").val(proxy.address);
        $("#txtProxyPort").val(proxy.port);
        $("#txtProxyUsername").val(proxy.username);
        $("#txtProxyPassword").val(proxy.password);
        $("#txtProxyBypassList").val(getArrayAsString(proxy.bypass));

        $("#txtProxyAddress").prop("disabled", false);
        $("#txtProxyPort").prop("disabled", false);
        $("#txtProxyUsername").prop("disabled", false);
        $("#txtProxyPassword").prop("disabled", false);
        $("#txtProxyBypassList").prop("disabled", false);
    }

    var forwarders = responseJSON.response.forwarders;
    if (forwarders == null)
        $("#txtForwarders").val("");
    else
        $("#txtForwarders").val(getArrayAsString(forwarders));

    $("#optQuickForwarders").val("blank");

    switch (responseJSON.response.forwarderProtocol.toLowerCase()) {
        case "tcp":
            $("#rdForwarderProtocolTcp").prop("checked", true);
            break;

        case "tls":
            $("#rdForwarderProtocolTls").prop("checked", true);
            break;

        case "https":
            $("#rdForwarderProtocolHttps").prop("checked", true);
            break;

        case "quic":
            $("#rdForwarderProtocolQuic").prop("checked", true);
            break;

        default:
            $("#rdForwarderProtocolUdp").prop("checked", true);
            break;
    }

    $("#chkEnableConcurrentForwarding").prop("checked", responseJSON.response.concurrentForwarding);
    $("#txtForwarderConcurrency").prop("disabled", !responseJSON.response.concurrentForwarding)

    $("#txtForwarderRetries").val(responseJSON.response.forwarderRetries);
    $("#txtForwarderTimeout").val(responseJSON.response.forwarderTimeout);
    $("#txtForwarderConcurrency").val(responseJSON.response.forwarderConcurrency);

    var enableLogging;

    switch (responseJSON.response.loggingType.toLowerCase()) {
        case "file":
            $("#rdLoggingTypeFile").prop("checked", true);
            enableLogging = true;
            break;

        case "console":
            $("#rdLoggingTypeConsole").prop("checked", true);
            enableLogging = true;
            break;

        case "fileandconsole":
            $("#rdLoggingTypeFileAndConsole").prop("checked", true);
            enableLogging = true;
            break;

        default:
            $("#rdLoggingTypeNone").prop("checked", true);
            enableLogging = false;
            break;
    }

    $("#chkIgnoreResolverLogs").prop("disabled", !enableLogging);
    $("#chkNoStackTrace").prop("disabled", !enableLogging);
    $("#chkLogQueries").prop("disabled", !enableLogging);
    $("#chkUseLocalTime").prop("disabled", !enableLogging);
    $("#txtLogFolderPath").prop("disabled", !enableLogging);

    $("#chkIgnoreResolverLogs").prop("checked", responseJSON.response.ignoreResolverLogs);
    $("#chkNoStackTrace").prop("checked", responseJSON.response.noStackTrace);
    $("#chkLogQueries").prop("checked", responseJSON.response.logQueries);
    $("#chkUseLocalTime").prop("checked", responseJSON.response.useLocalTime);
    $("#txtLogFolderPath").val(responseJSON.response.logFolder);
    $("#txtMaxLogFileDays").val(responseJSON.response.maxLogFileDays);

    $("#chkEnableInMemoryStats").prop("checked", responseJSON.response.enableInMemoryStats);
    $("#txtMaxStatFileDays").val(responseJSON.response.maxStatFileDays);
}

function saveDnsSettings(objBtn) {
    var formData = "";

    var dnsServerDomain = $("#txtDnsServerDomain").val();

    if ((dnsServerDomain === null) || (dnsServerDomain === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte die Server-Domain eingeben.");
        $("#txtDnsServerDomain").trigger("focus");
        return;
    }

    var dnsServerLocalEndPoints = cleanTextList($("#txtDnsServerLocalEndPoints").val());

    if ((dnsServerLocalEndPoints.length === 0) || (dnsServerLocalEndPoints === ","))
        dnsServerLocalEndPoints = "0.0.0.0:53,[::]:53";
    else
        $("#txtDnsServerLocalEndPoints").val(dnsServerLocalEndPoints.replace(/,/g, "\n"));

    var dnsServerIPv4SourceAddresses = cleanTextList($("#txtDnsServerIPv4SourceAddresses").val());
    if ((dnsServerIPv4SourceAddresses.length == 0) || (dnsServerIPv4SourceAddresses === ","))
        dnsServerIPv4SourceAddresses = false;

    var dnsServerIPv6SourceAddresses = cleanTextList($("#txtDnsServerIPv6SourceAddresses").val());
    if ((dnsServerIPv6SourceAddresses.length == 0) || (dnsServerIPv6SourceAddresses === ","))
        dnsServerIPv6SourceAddresses = false;

    formData += "&dnsServerDomain=" + dnsServerDomain + "&dnsServerLocalEndPoints=" + encodeURIComponent(dnsServerLocalEndPoints) + "&dnsServerIPv4SourceAddresses=" + encodeURIComponent(dnsServerIPv4SourceAddresses) + "&dnsServerIPv6SourceAddresses=" + encodeURIComponent(dnsServerIPv6SourceAddresses)

    var defaultRecordTtl = $("#txtDefaultRecordTtl").val();
    var defaultResponsiblePerson = $("#txtDefaultResponsiblePerson").val();

    var dnsServerEnableCheckForUpdate = $("#chkDnsServerEnableCheckForUpdate").prop("checked");
    var dnsAppsEnableAutomaticUpdate = $("#chkDnsAppsEnableAutomaticUpdate").prop("checked");

    formData += "&defaultRecordTtl=" + encodeURIComponent(defaultRecordTtl) + "&defaultResponsiblePerson=" + encodeURIComponent(defaultResponsiblePerson) + "&dnsServerEnableCheckForUpdate=" + dnsServerEnableCheckForUpdate + "&dnsAppsEnableAutomaticUpdate=" + dnsAppsEnableAutomaticUpdate;

    var ipv6Mode = $("input[name=rdIPv6Mode]:checked").val();
    var ipv6AutoFallback = $("#chkIpv6AutoFallback").prop("checked");
    var enableUdpSocketPool = $("#chkEnableUdpSocketPool").prop("checked");

    var udpListenerThreads = $("#txtUdpListenerThreads").val();
    if ((udpListenerThreads == null) || (udpListenerThreads === ""))
        udpListenerThreads = 0;

    var maxPendingStreamRequests = $("#txtMaxPendingStreamRequests").val();
    if ((maxPendingStreamRequests == null) || (maxPendingStreamRequests === ""))
        maxPendingStreamRequests = 100;

    var socketPoolExcludedPorts = cleanTextList($("#txtUdpSocketPoolExcludedPorts").val());
    if ((socketPoolExcludedPorts.length == 0) || (socketPoolExcludedPorts === ","))
        socketPoolExcludedPorts = false;
    else
        $("#txtUdpSocketPoolExcludedPorts").val(socketPoolExcludedPorts.replace(/,/g, "\n") + "\n");

    var requestFilterMaxSize = $("#txtRequestFilterMaxSize").val();
    if ((requestFilterMaxSize == null) || (requestFilterMaxSize === ""))
        requestFilterMaxSize = 0;

    var clientBlockListUrls = cleanTextList($("#txtClientBlockListUrls").val());
    if ((clientBlockListUrls.length === 0) || (clientBlockListUrls === ","))
        clientBlockListUrls = false;
    else
        $("#txtClientBlockListUrls").val(clientBlockListUrls.replace(/,/g, "\n") + "\n");

    formData += "&clientBlockListUrls=" + encodeURIComponent(clientBlockListUrls) + "&clientBlockListUpdateIntervalHours=" + $("#txtClientBlockListUpdateIntervalHours").val();
    formData += "&requestFilterMalformed=" + $("#chkRequestFilterMalformed").prop("checked") + "&requestFilterMaxSize=" + requestFilterMaxSize + "&requestFilterOpcode=" + $("#chkRequestFilterOpcode").prop("checked") + "&requestFilterClass=" + $("#chkRequestFilterClass").prop("checked") + "&requestFilterAny=" + $("#chkRequestFilterAny").prop("checked") + "&requestFilterZoneTransfer=" + $("#chkRequestFilterZoneTransfer").prop("checked") + "&requestFilterNoRecursion=" + $("#chkRequestFilterNoRecursion").prop("checked") + "&requestFilterEdnsVersion=" + $("#chkRequestFilterEdnsVersion").prop("checked") + "&requestFilterRefuseOnly=" + $("#chkRequestFilterRefuseOnly").prop("checked");

    formData += "&ipv6Mode=" + ipv6Mode + "&ipv6AutoFallback=" + ipv6AutoFallback + "&udpListenerThreads=" + udpListenerThreads + "&maxPendingStreamRequests=" + maxPendingStreamRequests + "&enableUdpSocketPool=" + enableUdpSocketPool + "&socketPoolExcludedPorts=" + encodeURIComponent(socketPoolExcludedPorts);

    var udpPayloadSize = $("#txtEdnsUdpPayloadSize").val();
    var dnssecValidation = $("#chkDnssecValidation").prop("checked");
    var dnssecPostQuantumDowngradeProtection = $("#chkDnssecPostQuantumDowngradeProtection").prop("checked");

    var eDnsClientSubnet = $("#chkEDnsClientSubnet").prop("checked");

    var eDnsClientSubnetIPv4PrefixLength = $("#txtEDnsClientSubnetIPv4PrefixLength").val();
    if ((eDnsClientSubnetIPv4PrefixLength == null) || (eDnsClientSubnetIPv4PrefixLength === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte die IPv4-Präfixlänge für ECS eingeben.");
        $("#txtEDnsClientSubnetIPv4PrefixLength").trigger("focus");
        return;
    }

    var eDnsClientSubnetIPv6PrefixLength = $("#txtEDnsClientSubnetIPv6PrefixLength").val();
    if ((eDnsClientSubnetIPv6PrefixLength == null) || (eDnsClientSubnetIPv6PrefixLength === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte die IPv6-Präfixlänge für ECS eingeben.");
        $("#txtEDnsClientSubnetIPv6PrefixLength").trigger("focus");
        return;
    }

    var eDnsClientSubnetIpv4Override = $("#txtEDnsClientSubnetIpv4Override").val();
    var eDnsClientSubnetIpv6Override = $("#txtEDnsClientSubnetIpv6Override").val();

    var qpsPrefixLimitsIPv4 = serializeTableData($("#tableQpsPrefixLimitsIPv4"), 3);
    if (qpsPrefixLimitsIPv4 === false)
        return;

    if (qpsPrefixLimitsIPv4.length === 0)
        qpsPrefixLimitsIPv4 = false;

    var qpsPrefixLimitsIPv6 = serializeTableData($("#tableQpsPrefixLimitsIPv6"), 3);
    if (qpsPrefixLimitsIPv6 === false)
        return;

    if (qpsPrefixLimitsIPv6.length === 0)
        qpsPrefixLimitsIPv6 = false;

    var rateLimitBurstSeconds = $("#txtRateLimitBurstSeconds").val();
    if ((rateLimitBurstSeconds == null) || (rateLimitBurstSeconds === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte die Burst-Dauer für die Ratenbegrenzung eingeben.");
        $("#txtRateLimitBurstSeconds").trigger("focus");
        return;
    }

    var rateLimitUdpTruncationPercentage = $("#txtRateLimitUdpTruncation").val();
    if ((rateLimitUdpTruncationPercentage == null) || (rateLimitUdpTruncationPercentage === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte den Anteil der TC-Antworten für die Ratenbegrenzung eingeben.");
        $("#txtRateLimitUdpTruncation").trigger("focus");
        return;
    }

    var rateLimitBypassList = cleanTextList($("#txtRateLimitBypassList").val());
    if ((rateLimitBypassList.length == 0) || (rateLimitBypassList === ","))
        rateLimitBypassList = false;
    else
        $("#txtRateLimitBypassList").val(rateLimitBypassList.replace(/,/g, "\n") + "\n");

    var clientTimeout = $("#txtClientTimeout").val();
    if ((clientTimeout == null) || (clientTimeout === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte einen Wert für das Client-Zeitlimit eingeben.");
        $("#txtClientTimeout").trigger("focus");
        return;
    }

    var tcpSendTimeout = $("#txtTcpSendTimeout").val();
    if ((tcpSendTimeout == null) || (tcpSendTimeout === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte einen Wert für das TCP-Sendezeitlimit eingeben.");
        $("#txtTcpSendTimeout").trigger("focus");
        return;
    }

    var tcpReceiveTimeout = $("#txtTcpReceiveTimeout").val();
    if ((tcpReceiveTimeout == null) || (tcpReceiveTimeout === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte einen Wert für das TCP-Empfangszeitlimit eingeben.");
        $("#txtTcpReceiveTimeout").trigger("focus");
        return;
    }

    var quicIdleTimeout = $("#txtQuicIdleTimeout").val();
    if ((quicIdleTimeout == null) || (quicIdleTimeout === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte einen Wert für die QUIC-Leerlaufzeit eingeben.");
        $("#txtQuicIdleTimeout").trigger("focus");
        return;
    }

    var quicMaxInboundStreams = $("#txtQuicMaxInboundStreams").val();
    if ((quicMaxInboundStreams == null) || (quicMaxInboundStreams === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte einen Wert für die QUIC-Streams je Verbindung eingeben.");
        $("#txtQuicMaxInboundStreams").trigger("focus");
        return;
    }

    var listenBacklog = $("#txtListenBacklog").val();
    if ((listenBacklog == null) || (listenBacklog === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte einen Wert für das Listen-Backlog eingeben.");
        $("#txtListenBacklog").trigger("focus");
        return;
    }

    var udpSendBufferSizeKB = $("#txtUdpSendBufferSizeKB").val();
    if ((udpSendBufferSizeKB == null) || (udpSendBufferSizeKB === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte einen Wert für den UDP-Sendepuffer eingeben.");
        $("#txtUdpSendBufferSizeKB").trigger("focus");
        return;
    }

    var udpReceiveBufferSizeKB = $("#txtUdpReceiveBufferSizeKB").val();
    if ((udpReceiveBufferSizeKB == null) || (udpReceiveBufferSizeKB === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte einen Wert für den UDP-Empfangspuffer eingeben.");
        $("#txtUdpReceiveBufferSizeKB").trigger("focus");
        return;
    }

    var maxConcurrentResolutionsPerCore = $("#txtMaxConcurrentResolutionsPerCore").val();
    if ((maxConcurrentResolutionsPerCore == null) || (maxConcurrentResolutionsPerCore === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte einen Wert für die gleichzeitigen Auflösungen eingeben.");
        $("#txtMaxConcurrentResolutionsPerCore").trigger("focus");
        return;
    }

    formData += "&udpPayloadSize=" + udpPayloadSize + "&dnssecValidation=" + dnssecValidation + "&dnssecPostQuantumDowngradeProtection=" + dnssecPostQuantumDowngradeProtection;
    formData += "&eDnsClientSubnet=" + eDnsClientSubnet + "&eDnsClientSubnetIPv4PrefixLength=" + eDnsClientSubnetIPv4PrefixLength + "&eDnsClientSubnetIPv6PrefixLength=" + eDnsClientSubnetIPv6PrefixLength + "&eDnsClientSubnetIpv4Override=" + encodeURIComponent(eDnsClientSubnetIpv4Override) + "&eDnsClientSubnetIpv6Override=" + encodeURIComponent(eDnsClientSubnetIpv6Override);
    formData += "&qpsPrefixLimitsIPv4=" + encodeURIComponent(qpsPrefixLimitsIPv4) + "&qpsPrefixLimitsIPv6=" + encodeURIComponent(qpsPrefixLimitsIPv6) + "&rateLimitBurstSeconds=" + rateLimitBurstSeconds + "&rateLimitUdpTruncationPercentage=" + rateLimitUdpTruncationPercentage + "&rateLimitBypassList=" + encodeURIComponent(rateLimitBypassList);
    formData += "&clientTimeout=" + clientTimeout + "&tcpSendTimeout=" + tcpSendTimeout + "&tcpReceiveTimeout=" + tcpReceiveTimeout + "&quicIdleTimeout=" + quicIdleTimeout + "&quicMaxInboundStreams=" + quicMaxInboundStreams + "&listenBacklog=" + listenBacklog + "&udpSendBufferSizeKB=" + udpSendBufferSizeKB + "&udpReceiveBufferSizeKB=" + udpReceiveBufferSizeKB + "&maxConcurrentResolutionsPerCore=" + maxConcurrentResolutionsPerCore;

    var webServiceLocalAddresses = cleanTextList($("#txtWebServiceLocalAddresses").val());

    if ((webServiceLocalAddresses.length === 0) || (webServiceLocalAddresses === ","))
        webServiceLocalAddresses = "0.0.0.0,[::]";
    else
        $("#txtWebServiceLocalAddresses").val(webServiceLocalAddresses.replace(/,/g, "\n"));

    var webServiceHttpPort = $("#txtWebServiceHttpPort").val();

    if ((webServiceHttpPort === null) || (webServiceHttpPort === ""))
        webServiceHttpPort = 5380;

    var webServiceEnableHttpUnixSocket = $("#chkWebServiceEnableHttpUnixSocket").prop("checked");
    var webServiceHttpUnixSocket = $("#txtWebServiceHttpUnixSocket").val();

    var webServiceEnableTlsUnixSocket = $("#chkWebServiceEnableTlsUnixSocket").prop("checked");
    var webServiceTlsUnixSocket = $("#txtWebServiceTlsUnixSocket").val();

    var webServiceEnableTls = $("#chkWebServiceEnableTls").prop("checked");
    var webServiceEnableHttp3 = $("#chkWebServiceEnableHttp3").prop("checked");
    var webServiceHttpToTlsRedirect = $("#chkWebServiceHttpToTlsRedirect").prop("checked");
    var webServiceUseSelfSignedTlsCertificate = $("#chkWebServiceUseSelfSignedTlsCertificate").prop("checked");
    var webServiceTlsPort = $("#txtWebServiceTlsPort").val();

    var webServiceReverseProxyAddresses = cleanTextList($("#txtWebServiceReverseProxyAddresses").val());

    if ((webServiceReverseProxyAddresses.length === 0) || (webServiceReverseProxyAddresses === ","))
        webServiceReverseProxyAddresses = false;
    else
        $("#txtWebServiceReverseProxyAddresses").val(webServiceReverseProxyAddresses.replace(/,/g, "\n"));

    var webServiceRealIpHeader = $("#txtWebServiceRealIpHeader").val();
    var webServiceCspFrameAncestorsHeader = $("#txtWebServiceCspFrameAncestorsHeader").val();

    var webServiceTlsCertificatePath = $("#txtWebServiceTlsCertificatePath").val();
    var webServiceTlsCertificatePassword = $("#txtWebServiceTlsCertificatePassword").val();
    var webServiceTlsCertificateKeyPath = $("#txtWebServiceTlsCertificateKeyPath").val();

    formData += "&webServiceLocalAddresses=" + encodeURIComponent(webServiceLocalAddresses) + "&webServiceHttpPort=" + webServiceHttpPort + "&webServiceEnableHttpUnixSocket=" + webServiceEnableHttpUnixSocket + "&webServiceHttpUnixSocket=" + encodeURIComponent(webServiceHttpUnixSocket) + "&webServiceEnableTlsUnixSocket=" + webServiceEnableTlsUnixSocket + "&webServiceTlsUnixSocket=" + encodeURIComponent(webServiceTlsUnixSocket) + "&webServiceEnableTls=" + webServiceEnableTls + "&webServiceEnableHttp3=" + webServiceEnableHttp3 + "&webServiceHttpToTlsRedirect=" + webServiceHttpToTlsRedirect + "&webServiceUseSelfSignedTlsCertificate=" + webServiceUseSelfSignedTlsCertificate + "&webServiceTlsPort=" + webServiceTlsPort + "&webServiceReverseProxyAddresses=" + encodeURIComponent(webServiceReverseProxyAddresses) + "&webServiceRealIpHeader=" + encodeURIComponent(webServiceRealIpHeader) + "&webServiceCspFrameAncestorsHeader=" + encodeURIComponent(webServiceCspFrameAncestorsHeader) + "&webServiceTlsCertificatePath=" + encodeURIComponent(webServiceTlsCertificatePath) + "&webServiceTlsCertificatePassword=" + encodeURIComponent(webServiceTlsCertificatePassword) + "&webServiceTlsCertificateKeyPath=" + encodeURIComponent(webServiceTlsCertificateKeyPath);

    var enableEDnsClientSubnetSourceAddress = $("#chkEnableEDnsClientSubnetSourceAddress").prop("checked");
    var enableDnsOverUdpProxy = $("#chkEnableDnsOverUdpProxy").prop("checked");
    var enableDnsOverTcpProxy = $("#chkEnableDnsOverTcpProxy").prop("checked");
    var enableDnsOverHttp = $("#chkEnableDnsOverHttp").prop("checked");
    var enableDnsOverHttpUnixSocket = $("#chkEnableDnsOverHttpUnixSocket").prop("checked");
    var enableDnsOverHttpsUnixSocket = $("#chkEnableDnsOverHttpsUnixSocket").prop("checked");
    var enableDnsOverTls = $("#chkEnableDnsOverTls").prop("checked");
    var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");
    var enableDnsOverHttp3 = $("#chkEnableDnsOverHttp3").prop("checked");
    var enableDnsOverQuic = $("#chkEnableDnsOverQuic").prop("checked");

    var enableDnsOverHttpHelpRedirect = $("#chkEnableDnsOverHttpHelpRedirect").prop("checked");

    var dnsOverUdpProxyPort = $("#txtDnsOverUdpProxyPort").val();
    if ((dnsOverUdpProxyPort == null) || (dnsOverUdpProxyPort === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte den Port für DNS-over-UDP-PROXY eingeben.");
        $("#txtDnsOverUdpProxyPort").trigger("focus");
        return;
    }

    var dnsOverTcpProxyPort = $("#txtDnsOverTcpProxyPort").val();
    if ((dnsOverTcpProxyPort == null) || (dnsOverTcpProxyPort === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte den Port für DNS-over-TCP-PROXY eingeben.");
        $("#txtDnsOverTcpProxyPort").trigger("focus");
        return;
    }

    var dnsOverHttpPort = $("#txtDnsOverHttpPort").val();
    if ((dnsOverHttpPort == null) || (dnsOverHttpPort === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte den Port für DNS-over-HTTP eingeben.");
        $("#txtDnsOverHttpPort").trigger("focus");
        return;
    }

    var dnsOverHttpUnixSocket = $("#txtDnsOverHttpUnixSocket").val();
    var dnsOverHttpsUnixSocket = $("#txtDnsOverHttpsUnixSocket").val();

    var dnsOverTlsPort = $("#txtDnsOverTlsPort").val();
    if ((dnsOverTlsPort == null) || (dnsOverTlsPort === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte den Port für DNS-over-TLS eingeben.");
        $("#txtDnsOverTlsPort").trigger("focus");
        return;
    }

    var dnsOverHttpsPort = $("#txtDnsOverHttpsPort").val();
    if ((dnsOverHttpsPort == null) || (dnsOverHttpsPort === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte den Port für DNS-over-HTTPS eingeben.");
        $("#txtDnsOverHttpsPort").trigger("focus");
        return;
    }

    var dnsOverQuicPort = $("#txtDnsOverQuicPort").val();
    if ((dnsOverQuicPort == null) || (dnsOverQuicPort === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte den Port für DNS-over-QUIC eingeben.");
        $("#txtDnsOverQuicPort").trigger("focus");
        return;
    }

    var dnsReverseProxyNetworkACL = cleanTextList($("#txtDnsReverseProxyNetworkACL").val());

    if ((dnsReverseProxyNetworkACL.length === 0) || (dnsReverseProxyNetworkACL === ","))
        dnsReverseProxyNetworkACL = false;
    else
        $("#txtDnsReverseProxyNetworkACL").val(dnsReverseProxyNetworkACL.replace(/,/g, "\n"));

    var dnsOverHttpRealIpHeader = $("#txtDnsOverHttpRealIpHeader").val();

    var dnsTlsCertificatePath = $("#txtDnsTlsCertificatePath").val();
    var dnsTlsCertificatePassword = $("#txtDnsTlsCertificatePassword").val();
    var dnsTlsCertificateKeyPath = $("#txtDnsTlsCertificateKeyPath").val();
    var enableDdr = $("#chkEnableDdr").prop("checked");
    var ddrOnlyUnencrypted = $("#chkDdrOnlyUnencrypted").prop("checked");

    formData += "&enableEDnsClientSubnetSourceAddress=" + enableEDnsClientSubnetSourceAddress + "&enableDnsOverUdpProxy=" + enableDnsOverUdpProxy + "&enableDnsOverTcpProxy=" + enableDnsOverTcpProxy + "&enableDnsOverHttp=" + enableDnsOverHttp + "&enableDnsOverHttpUnixSocket=" + enableDnsOverHttpUnixSocket + "&enableDnsOverHttpsUnixSocket=" + enableDnsOverHttpsUnixSocket + "&enableDnsOverTls=" + enableDnsOverTls + "&enableDnsOverHttps=" + enableDnsOverHttps + "&enableDnsOverHttp3=" + enableDnsOverHttp3 + "&enableDnsOverQuic=" + enableDnsOverQuic + "&enableDnsOverHttpHelpRedirect=" + enableDnsOverHttpHelpRedirect + "&dnsOverUdpProxyPort=" + dnsOverUdpProxyPort + "&dnsOverTcpProxyPort=" + dnsOverTcpProxyPort + "&dnsOverHttpPort=" + dnsOverHttpPort + "&dnsOverHttpUnixSocket=" + encodeURIComponent(dnsOverHttpUnixSocket) + "&dnsOverHttpsUnixSocket=" + encodeURIComponent(dnsOverHttpsUnixSocket) + "&dnsOverTlsPort=" + dnsOverTlsPort + "&dnsOverHttpsPort=" + dnsOverHttpsPort + "&dnsOverQuicPort=" + dnsOverQuicPort + "&dnsReverseProxyNetworkACL=" + encodeURIComponent(dnsReverseProxyNetworkACL) + "&dnsOverHttpRealIpHeader=" + encodeURIComponent(dnsOverHttpRealIpHeader) + "&dnsTlsCertificatePath=" + encodeURIComponent(dnsTlsCertificatePath) + "&dnsTlsCertificatePassword=" + encodeURIComponent(dnsTlsCertificatePassword) + "&dnsTlsCertificateKeyPath=" + encodeURIComponent(dnsTlsCertificateKeyPath) + "&enableDdr=" + enableDdr + "&ddrOnlyUnencrypted=" + ddrOnlyUnencrypted;

    var recursion = $("input[name=rdRecursion]:checked").val();

    var recursionNetworkACL = cleanTextList($("#txtRecursionNetworkACL").val());

    if ((recursionNetworkACL.length === 0) || (recursionNetworkACL === ","))
        recursionNetworkACL = false;
    else
        $("#txtRecursionNetworkACL").val(recursionNetworkACL.replace(/,/g, "\n"));

    var randomizeName = $("#chkRandomizeName").prop("checked");
    var qnameMinimization = $("#chkQnameMinimization").prop("checked");
    var locallyServedDnsZones = $("#chkLocallyServedDnsZones").prop("checked");

    var resolverRetries = $("#txtResolverRetries").val();
    if ((resolverRetries == null) || (resolverRetries === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte die Wiederholungen des Resolvers eingeben.");
        $("#txtResolverRetries").trigger("focus");
        return;
    }

    var resolverTimeout = $("#txtResolverTimeout").val();
    if ((resolverTimeout == null) || (resolverTimeout === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte das Zeitlimit des Resolvers eingeben.");
        $("#txtResolverTimeout").trigger("focus");
        return;
    }

    var resolverConcurrency = $("#txtResolverConcurrency").val();
    if ((resolverConcurrency == null) || (resolverConcurrency === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte die parallelen Anfragen des Resolvers eingeben.");
        $("#txtResolverConcurrency").trigger("focus");
        return;
    }

    var resolverMaxStackCount = $("#txtResolverMaxStackCount").val();
    if ((resolverMaxStackCount == null) || (resolverMaxStackCount === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte die maximale Verschachtelung des Resolvers eingeben.");
        $("#txtResolverMaxStackCount").trigger("focus");
        return;
    }

    formData += "&recursion=" + recursion + "&recursionNetworkACL=" + encodeURIComponent(recursionNetworkACL) + "&randomizeName=" + randomizeName + "&qnameMinimization=" + qnameMinimization + "&locallyServedDnsZones=" + locallyServedDnsZones + "&resolverRetries=" + resolverRetries + "&resolverTimeout=" + resolverTimeout + "&resolverConcurrency=" + resolverConcurrency + "&resolverMaxStackCount=" + resolverMaxStackCount;

    var saveCache = $("#chkSaveCache").prop("checked");

    var serveStale = $("#chkServeStale").prop("checked");
    var serveStaleTtl = $("#txtServeStaleTtl").val();
    var serveStaleAnswerTtl = $("#txtServeStaleAnswerTtl").val();
    var serveStaleResetTtl = $("#txtServeStaleResetTtl").val();
    var serveStaleMaxWaitTime = $("#txtServeStaleMaxWaitTime").val();

    var cacheMaximumEntries = $("#txtCacheMaximumEntries").val();
    if ((cacheMaximumEntries === null) || (cacheMaximumEntries === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte die maximalen Cache-Einträge eingeben.");
        $("#txtCacheMaximumEntries").trigger("focus");
        return;
    }

    var cacheMinimumRecordTtl = $("#txtCacheMinimumRecordTtl").val();
    if ((cacheMinimumRecordTtl === null) || (cacheMinimumRecordTtl === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte die minimale Cache-TTL eingeben.");
        $("#txtCacheMinimumRecordTtl").trigger("focus");
        return;
    }

    var cacheMaximumRecordTtl = $("#txtCacheMaximumRecordTtl").val();
    if ((cacheMaximumRecordTtl === null) || (cacheMaximumRecordTtl === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte die maximale Cache-TTL eingeben.");
        $("#txtCacheMaximumRecordTtl").trigger("focus");
        return;
    }

    var cacheNegativeRecordTtl = $("#txtCacheNegativeRecordTtl").val();
    if ((cacheNegativeRecordTtl === null) || (cacheNegativeRecordTtl === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte die negative Cache-TTL eingeben.");
        $("#txtCacheNegativeRecordTtl").trigger("focus");
        return;
    }

    var cacheFailureRecordTtl = $("#txtCacheFailureRecordTtl").val();
    if ((cacheFailureRecordTtl === null) || (cacheFailureRecordTtl === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte die Fehler-TTL eingeben.");
        $("#txtCacheFailureRecordTtl").trigger("focus");
        return;
    }

    var cachePrefetchEligibility = $("#txtCachePrefetchEligibility").val();
    if ((cachePrefetchEligibility === null) || (cachePrefetchEligibility === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte die Mindest-TTL für Prefetch eingeben.");
        $("#txtCachePrefetchEligibility").trigger("focus");
        return;
    }

    var cachePrefetchTrigger = $("#txtCachePrefetchTrigger").val();
    if ((cachePrefetchTrigger === null) || (cachePrefetchTrigger === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte den Prefetch-Auslöser eingeben.");
        $("#txtCachePrefetchTrigger").trigger("focus");
        return;
    }

    formData += "&saveCache=" + saveCache + "&serveStale=" + serveStale + "&serveStaleTtl=" + serveStaleTtl + "&serveStaleAnswerTtl=" + serveStaleAnswerTtl + "&serveStaleResetTtl=" + serveStaleResetTtl + "&serveStaleMaxWaitTime=" + serveStaleMaxWaitTime + "&cacheMaximumEntries=" + cacheMaximumEntries + "&cacheMinimumRecordTtl=" + cacheMinimumRecordTtl + "&cacheMaximumRecordTtl=" + cacheMaximumRecordTtl + "&cacheNegativeRecordTtl=" + cacheNegativeRecordTtl + "&cacheFailureRecordTtl=" + cacheFailureRecordTtl + "&cachePrefetchEligibility=" + cachePrefetchEligibility + "&cachePrefetchTrigger=" + cachePrefetchTrigger;

    var enableBlocking = $("#chkEnableBlocking").prop("checked");
    var allowTxtBlockingReport = $("#chkAllowTxtBlockingReport").prop("checked");

    var blockingBypassList = cleanTextList($("#txtBlockingBypassList").val());
    if ((blockingBypassList.length == 0) || (blockingBypassList === ","))
        blockingBypassList = false;
    else
        $("#txtBlockingBypassList").val(blockingBypassList.replace(/,/g, "\n") + "\n");

    var blockingType = $("input[name=rdBlockingType]:checked").val();

    var customBlockingAddresses = cleanTextList($("#txtCustomBlockingAddresses").val());
    if ((customBlockingAddresses.length === 0) || customBlockingAddresses === ",")
        customBlockingAddresses = false;
    else
        $("#txtCustomBlockingAddresses").val(customBlockingAddresses.replace(/,/g, "\n") + "\n");

    var blockingAnswerTtl = $("#txtBlockingAnswerTtl").val();
    var blockingNegativeTtl = $("#txtBlockingNegativeTtl").val();
    var blockingReportText = $("#txtBlockingReportText").val();

    var blockListUrls = cleanTextList($("#txtBlockListUrls").val());

    if ((blockListUrls.length === 0) || (blockListUrls === ","))
        blockListUrls = false;
    else
        $("#txtBlockListUrls").val(blockListUrls.replace(/,/g, "\n") + "\n");

    var blockListUpdateIntervalHours = $("#txtBlockListUpdateIntervalHours").val();

    formData += "&enableBlocking=" + enableBlocking + "&allowTxtBlockingReport=" + allowTxtBlockingReport + "&blockingBypassList=" + encodeURIComponent(blockingBypassList) + "&blockingType=" + blockingType + "&customBlockingAddresses=" + encodeURIComponent(customBlockingAddresses) + "&blockingAnswerTtl=" + blockingAnswerTtl + "&blockingNegativeTtl=" + blockingNegativeTtl + "&blockingReportText=" + encodeURIComponent(blockingReportText) + "&blockListUrls=" + encodeURIComponent(blockListUrls) + "&blockListUpdateIntervalHours=" + blockListUpdateIntervalHours;

    var proxy;

    var proxyType = $("input[name=rdProxyType]:checked").val().toLowerCase();
    if (proxyType === "none") {
        proxy = "&proxyType=" + proxyType;
    }
    else {
        var proxyAddress = $("#txtProxyAddress").val();

        if ((proxyAddress === null) || (proxyAddress === "")) {
            showAlert("warning", "Angabe fehlt", "Bitte die Proxy-Adresse eingeben.");
            $("#txtProxyAddress").trigger("focus");
            return;
        }

        var proxyPort = $("#txtProxyPort").val();

        if ((proxyPort === null) || (proxyPort === "")) {
            showAlert("warning", "Angabe fehlt", "Bitte den Proxy-Port eingeben.");
            $("#txtProxyPort").trigger("focus");
            return;
        }

        var proxyBypass = cleanTextList($("#txtProxyBypassList").val());

        if ((proxyBypass.length === 0) || (proxyBypass === ","))
            proxyBypass = "";
        else
            $("#txtProxyBypassList").val(proxyBypass.replace(/,/g, "\n"));

        proxy = "&proxyType=" + proxyType + "&proxyAddress=" + encodeURIComponent(proxyAddress) + "&proxyPort=" + proxyPort + "&proxyUsername=" + encodeURIComponent($("#txtProxyUsername").val()) + "&proxyPassword=" + encodeURIComponent($("#txtProxyPassword").val()) + "&proxyBypass=" + encodeURIComponent(proxyBypass);
    }

    var forwarders = cleanTextList($("#txtForwarders").val());

    if ((forwarders.length === 0) || (forwarders === ","))
        forwarders = false;
    else
        $("#txtForwarders").val(forwarders.replace(/,/g, "\n"));

    var forwarderProtocol = $("input[name=rdForwarderProtocol]:checked").val();

    var concurrentForwarding = $("#chkEnableConcurrentForwarding").prop("checked");

    var forwarderRetries = $("#txtForwarderRetries").val();
    if ((forwarderRetries == null) || (forwarderRetries === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte die Wiederholungen je Forwarder eingeben.");
        $("#txtForwarderRetries").trigger("focus");
        return;
    }

    var forwarderTimeout = $("#txtForwarderTimeout").val();
    if ((forwarderTimeout == null) || (forwarderTimeout === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte das Zeitlimit je Forwarder eingeben.");
        $("#txtForwarderTimeout").trigger("focus");
        return;
    }

    var forwarderConcurrency = $("#txtForwarderConcurrency").val();
    if ((forwarderConcurrency == null) || (forwarderConcurrency === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte die Zahl gleichzeitiger Forwarder eingeben.");
        $("#txtForwarderConcurrency").trigger("focus");
        return;
    }

    formData += proxy + "&forwarders=" + encodeURIComponent(forwarders) + "&forwarderProtocol=" + forwarderProtocol + "&concurrentForwarding=" + concurrentForwarding + "&forwarderRetries=" + forwarderRetries + "&forwarderTimeout=" + forwarderTimeout + "&forwarderConcurrency=" + forwarderConcurrency;

    var loggingType = $("input[name=rdLoggingType]:checked").val();
    var ignoreResolverLogs = $("#chkIgnoreResolverLogs").prop("checked");
    var noStackTrace = $("#chkNoStackTrace").prop("checked");
    var logQueries = $("#chkLogQueries").prop("checked");
    var useLocalTime = $("#chkUseLocalTime").prop("checked");
    var logFolder = $("#txtLogFolderPath").val();
    var maxLogFileDays = $("#txtMaxLogFileDays").val();

    var enableInMemoryStats = $("#chkEnableInMemoryStats").prop("checked");
    var maxStatFileDays = $("#txtMaxStatFileDays").val();

    formData += "&loggingType=" + loggingType + "&ignoreResolverLogs=" + ignoreResolverLogs + "&noStackTrace=" + noStackTrace + "&logQueries=" + logQueries + "&useLocalTime=" + useLocalTime + "&logFolder=" + encodeURIComponent(logFolder) + "&maxLogFileDays=" + maxLogFileDays + "&enableInMemoryStats=" + enableInMemoryStats + "&maxStatFileDays=" + maxStatFileDays;

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/settings/set",
        token: sessionData.token,
        method: "POST",
        data: formData,
        processData: false,
        showInnerError: true,
        success: function (responseJSON) {
            updateDnsSettingsDataAndGui(responseJSON);

            loadDnsSettings(responseJSON);

            btn.button("reset");
            showAlert("success", "Gespeichert", "Die Einstellungen wurden übernommen.");

            if (sessionData.info.dnsServerDomain == responseJSON.server)
                checkForWebConsoleRedirection(responseJSON);
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

function addQpsPrefixLimitsIPv4Row(prefix, udpLimit, tcpLimit) {
    var id = Math.floor(Math.random() * 10000);

    var tableHtmlRows = "<tr id=\"tableQpsPrefixLimitsIPv4Row" + id + "\"><td><input type=\"number\" class=\"form-control\" value=\"" + htmlEncode(prefix) + "\"></td>";
    tableHtmlRows += "<td><input type=\"number\" class=\"form-control\" value=\"" + htmlEncode(udpLimit) + "\"></td>";
    tableHtmlRows += "<td><input type=\"number\" class=\"form-control\" value=\"" + htmlEncode(tcpLimit) + "\"></td>";

    tableHtmlRows += "<td><button type=\"button\" class=\"btn btn-danger\" onclick=\"$('#tableQpsPrefixLimitsIPv4Row" + id + "').remove();\">Löschen</button></td></tr>";

    $("#tableQpsPrefixLimitsIPv4").append(tableHtmlRows);
}

function addQpsPrefixLimitsIPv6Row(prefix, udpLimit, tcpLimit) {
    var id = Math.floor(Math.random() * 10000);

    var tableHtmlRows = "<tr id=\"tableQpsPrefixLimitsIPv6Row" + id + "\"><td><input type=\"number\" class=\"form-control\" value=\"" + htmlEncode(prefix) + "\"></td>";
    tableHtmlRows += "<td><input type=\"number\" class=\"form-control\" value=\"" + htmlEncode(udpLimit) + "\"></td>";
    tableHtmlRows += "<td><input type=\"number\" class=\"form-control\" value=\"" + htmlEncode(tcpLimit) + "\"></td>";

    tableHtmlRows += "<td><button type=\"button\" class=\"btn btn-danger\" onclick=\"$('#tableQpsPrefixLimitsIPv6Row" + id + "').remove();\">Löschen</button></td></tr>";

    $("#tableQpsPrefixLimitsIPv6").append(tableHtmlRows);
}

function checkForReverseProxy(responseJSON) {
    if (window.location.protocol == "https:") {
        var currentPort = window.location.port;

        if ((currentPort == 0) || (currentPort == ""))
            currentPort = 443;

        reverseProxyDetected = !responseJSON.response.webServiceEnableTls || (currentPort != responseJSON.response.webServiceTlsPort);
    } else {
        var currentPort = window.location.port;

        if ((currentPort == 0) || (currentPort == ""))
            currentPort = 80;

        reverseProxyDetected = currentPort != responseJSON.response.webServiceHttpPort
    }
}

function checkForWebConsoleRedirection(responseJSON) {
    if (reverseProxyDetected)
        return;

    if (location.protocol == "https:") {
        if (!responseJSON.response.webServiceEnableTls) {
            setTimeout(function () {
                window.open("http://" + window.location.hostname + ":" + responseJSON.response.webServiceHttpPort, "_self");
            }, 2500);

            return;
        }

        var currentPort = window.location.port;

        if ((currentPort == 0) || (currentPort == ""))
            currentPort = 443;

        if (currentPort != responseJSON.response.webServiceTlsPort) {
            setTimeout(function () {
                window.open("https://" + window.location.hostname + ":" + responseJSON.response.webServiceTlsPort, "_self");
            }, 2500);
        }
    }
    else {
        if (responseJSON.response.webServiceEnableTls && responseJSON.response.webServiceHttpToTlsRedirect) {
            setTimeout(function () {
                window.open("https://" + window.location.hostname + ":" + responseJSON.response.webServiceTlsPort, "_self");
            }, 2500);

            return;
        }

        var currentPort = window.location.port;

        if ((currentPort == 0) || (currentPort == ""))
            currentPort = 80;

        if (currentPort != responseJSON.response.webServiceHttpPort) {
            setTimeout(function () {
                window.open("http://" + window.location.hostname + ":" + responseJSON.response.webServiceHttpPort, "_self");
            }, 2500);
        }
    }
}

function forceUpdateBlockLists() {
    if (!confirm("Blocklisten jetzt herunterladen und aktualisieren?"))
        return;

    var btn = $("#btnUpdateBlockListsNow");
    btn.button("loading");

    HTTPRequest({
        url: "api/settings/forceUpdateBlockLists",
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");

            $("#lblBlockListNextUpdatedOn").text("wird gerade aktualisiert");

            showAlert("success", "Blocklisten werden aktualisiert", "Die Aktualisierung der Blocklisten wurde gestartet.");
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

function temporaryDisableBlockingNow() {
    var minutes = $("#txtTemporaryDisableBlockingMinutes").val();

    if ((minutes === null) || (minutes === "")) {
        showAlert("warning", "Angabe fehlt", "Bitte angeben, wie viele Minuten die Blockierung pausieren soll.");
        $("#txtTemporaryDisableBlockingMinutes").trigger("focus");
        return;
    }

    if (!confirm("Blockierung für " + minutes + " Minute(n) pausieren?"))
        return;

    var btn = $("#btnTemporaryDisableBlockingNow");
    btn.button("loading");

    HTTPRequest({
        url: "api/settings/temporaryDisableBlocking?minutes=" + minutes,
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");

            $("#chkEnableBlocking").prop("checked", false);
            $("#lblTemporaryDisableBlockingTill").text(moment(responseJSON.response.temporaryDisableBlockingTill).local().format("DD.MM.YYYY HH:mm:ss"));
            updateBlockingState();

            showAlert("success", "Blockierung aus", "Die Blockierung ist pausiert für " + htmlEncode(minutes) + " Minute(n).");

            setTimeout(updateBlockingState, 500);
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

function forceUpdateClientBlockLists() {
    var btn = $("#btnUpdateClientBlockListsNow");
    btn.button("loading");

    HTTPRequest({
        url: "api/settings/forceUpdateClientBlockLists",
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");
            showAlert("success", "Aktualisierung gestartet", "Die Client-Sperrlisten werden im Hintergrund heruntergeladen und neu geladen.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function updateBlockingState() {
    var enableBlocking = $("#chkEnableBlocking").prop("checked");

    $("#chkAllowTxtBlockingReport").prop("disabled", !enableBlocking);
    $("#txtTemporaryDisableBlockingMinutes").prop("disabled", !enableBlocking);
    $("#btnTemporaryDisableBlockingNow").prop("disabled", !enableBlocking);
    $("#txtBlockingBypassList").prop("disabled", !enableBlocking);
    $("#rdBlockingTypeAnyAddress").prop("disabled", !enableBlocking);
    $("#rdBlockingTypeNxDomain").prop("disabled", !enableBlocking);
    $("#rdBlockingTypeCustomAddress").prop("disabled", !enableBlocking);
    $("#txtBlockingAnswerTtl").prop("disabled", !enableBlocking);
    $("#txtBlockingNegativeTtl").prop("disabled", !enableBlocking);
    $("#txtBlockingReportText").prop("disabled", !enableBlocking);
    $("#txtCustomBlockingAddresses").prop("disabled", !enableBlocking || !$("#rdBlockingTypeCustomAddress").prop("checked"));
    $("#txtBlockListUrls").prop("disabled", !enableBlocking);
    $("#optQuickBlockList").prop("disabled", !enableBlocking);
}

function dashboardBlockingOptionsOnClick() {
    $("#mnuDashboardBlockingOptionsEnableBlocking").hide();
    $("#mnuDashboardBlockingOptionsDisableBlocking").hide();

    HTTPRequest({
        url: "api/settings/get",
        token: sessionData.token,
        success: function (responseJSON) {
            if (responseJSON.response.enableBlocking)
                $("#mnuDashboardBlockingOptionsDisableBlocking").show();
            else
                $("#mnuDashboardBlockingOptionsEnableBlocking").show();
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function enableBlocking() {
    if (!confirm("Blockierung aktivieren?"))
        return;

    HTTPRequest({
        url: "api/settings/set?enableBlocking=true",
        token: sessionData.token,
        success: function (responseJSON) {
            showAlert("success", "Blockierung aktiv", "Die Blockierung ist aktiviert.");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function disableBlocking() {
    if (!confirm("Blockierung deaktivieren?"))
        return;

    HTTPRequest({
        url: "api/settings/set?enableBlocking=false",
        token: sessionData.token,
        success: function (responseJSON) {
            showAlert("success", "Blockierung aus", "Die Blockierung ist deaktiviert.");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function temporaryDisableBlockingForMenu(minutes) {
    if (!confirm("Blockierung für " + minutes + " Minute(n) pausieren?"))
        return;

    HTTPRequest({
        url: "api/settings/temporaryDisableBlocking?minutes=" + minutes,
        token: sessionData.token,
        success: function (responseJSON) {
            showAlert("success", "Blockierung aus", "Die Blockierung ist pausiert für " + htmlEncode(minutes) + " Minute(n).");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function resetBackupSettingsModal() {
    $("#divBackupSettingsAlert").html("");

    $("#chkBackupAuthConfig").prop("checked", true);
    $("#chkBackupWebServiceConfig").prop("checked", true);
    $("#chkBackupDnsConfig").prop("checked", true);
    $("#chkBackupLogConfig").prop("checked", true);
    $("#chkBackupZones").prop("checked", true);
    $("#chkBackupAllowedZones").prop("checked", true);
    $("#chkBackupBlockedZones").prop("checked", true);
    $("#chkBackupBlockLists").prop("checked", true);
    $("#chkBackupApps").prop("checked", true);
    $("#chkBackupStats").prop("checked", true);
    $("#chkBackupLogs").prop("checked", false);
}

function backupSettings(objBtn) {
    var divBackupSettingsAlert = $("#divBackupSettingsAlert");

    var authConfig = $("#chkBackupAuthConfig").prop("checked");
    var webServiceSettings = $("#chkBackupWebServiceConfig").prop("checked");
    var dnsSettings = $("#chkBackupDnsConfig").prop("checked");
    var logSettings = $("#chkBackupLogConfig").prop("checked");
    var zones = $("#chkBackupZones").prop("checked");
    var allowedZones = $("#chkBackupAllowedZones").prop("checked");
    var blockedZones = $("#chkBackupBlockedZones").prop("checked");
    var blockLists = $("#chkBackupBlockLists").prop("checked");
    var apps = $("#chkBackupApps").prop("checked");
    var stats = $("#chkBackupStats").prop("checked");
    var logs = $("#chkBackupLogs").prop("checked");

    if (!authConfig && !webServiceSettings && !dnsSettings && !logSettings && !zones && !allowedZones && !blockedZones && !blockLists && !apps && !stats && !logs) {
        showAlert("warning", "Angabe fehlt", "Bitte mindestens einen Bestandteil für die Sicherung auswählen.", divBackupSettingsAlert);
        return;
    }

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/user/createSingleUseToken",
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");

            window.open("api/settings/backup?token=" + responseJSON.response.token + "&authConfig=" + authConfig + "&webServiceSettings=" + webServiceSettings + "&dnsSettings=" + dnsSettings + "&logSettings=" + logSettings + "&zones=" + zones + "&allowedZones=" + allowedZones + "&blockedZones=" + blockedZones + "&blockLists=" + blockLists + "&apps=" + apps + "&stats=" + stats + "&logs=" + logs + "&ts=" + (new Date().getTime()), "_blank");

            $("#modalBackupSettings").modal("hide");
            showAlert("success", "Gesichert", "Die Sicherung wurde erstellt.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            showPageLogin();
        },
        objAlertPlaceholder: divBackupSettingsAlert
    });
}

function resetRestoreSettingsModal() {
    $("#divRestoreSettingsAlert").html("");

    $("#fileBackupZip").val("");

    $("#chkRestoreAuthConfig").prop("checked", true);
    $("#chkRestoreWebServiceConfig").prop("checked", true);
    $("#chkRestoreDnsConfig").prop("checked", true);
    $("#chkRestoreLogConfig").prop("checked", true);
    $("#chkRestoreZones").prop("checked", true);
    $("#chkRestoreAllowedZones").prop("checked", true);
    $("#chkRestoreBlockedZones").prop("checked", true);
    $("#chkRestoreBlockLists").prop("checked", true);
    $("#chkRestoreApps").prop("checked", true);
    $("#chkRestoreStats").prop("checked", true);
    $("#chkRestoreLogs").prop("checked", false);
    $("#chkDeleteExistingFiles").prop("checked", true);
}

function restoreSettings() {
    var divRestoreSettingsAlert = $("#divRestoreSettingsAlert");

    var fileBackupZip = $("#fileBackupZip");

    if (fileBackupZip[0].files.length === 0) {
        showAlert("warning", "Angabe fehlt", "Bitte eine Sicherungsdatei (ZIP) auswählen.", divRestoreSettingsAlert);
        fileBackupZip.trigger("focus");
        return;
    }

    var authConfig = $("#chkRestoreAuthConfig").prop("checked");
    var webServiceSettings = $("#chkRestoreWebServiceConfig").prop("checked");
    var dnsSettings = $("#chkRestoreDnsConfig").prop("checked");
    var logSettings = $("#chkRestoreLogConfig").prop("checked");
    var zones = $("#chkRestoreZones").prop("checked");
    var allowedZones = $("#chkRestoreAllowedZones").prop("checked");
    var blockedZones = $("#chkRestoreBlockedZones").prop("checked");
    var blockLists = $("#chkRestoreBlockLists").prop("checked");
    var apps = $("#chkRestoreApps").prop("checked");
    var stats = $("#chkRestoreStats").prop("checked");
    var logs = $("#chkRestoreLogs").prop("checked");

    var deleteExistingFiles = $("#chkDeleteExistingFiles").prop("checked");

    if (!authConfig && !webServiceSettings && !dnsSettings && !logSettings && !zones && !allowedZones && !blockedZones && !blockLists && !apps && !stats && !logs) {
        showAlert("warning", "Angabe fehlt", "Bitte mindestens einen Bestandteil zum Wiederherstellen auswählen.", divRestoreSettingsAlert);
        return;
    }

    var formData = new FormData();
    formData.append("fileBackupZip", $("#fileBackupZip")[0].files[0]);

    var btn = $("#btnRestoreSettings");
    btn.button("loading");

    HTTPRequest({
        url: "api/settings/restore?authConfig=" + authConfig + "&webServiceSettings=" + webServiceSettings + "&dnsSettings=" + dnsSettings + "&logSettings=" + logSettings + "&zones=" + zones + "&allowedZones=" + allowedZones + "&blockedZones=" + blockedZones + "&blockLists=" + blockLists + "&apps=" + apps + "&stats=" + stats + "&logs=" + logs + "&deleteExistingFiles=" + deleteExistingFiles,
        token: sessionData.token,
        method: "POST",
        data: formData,
        contentType: false,
        processData: false,
        success: function (responseJSON) {
            updateDnsSettingsDataAndGui(responseJSON);

            loadDnsSettings(responseJSON);

            $("#modalRestoreSettings").modal("hide");
            btn.button("reset");

            showAlert("success", "Wiederhergestellt", "Die Sicherung wurde wiederhergestellt.");

            if (sessionData.info.dnsServerDomain == responseJSON.server)
                checkForWebConsoleRedirection(responseJSON);
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            showPageLogin();
        },
        objAlertPlaceholder: divRestoreSettingsAlert
    });
}

function initTheme() {
    if (window.matchMedia) {
        window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", e => {
            const currentTheme = localStorage.getItem("theme");
            switch (currentTheme) {
                case "light":
                case "dark":
                case "amber":
                    break;

                default:
                    if (e.matches)
                        applyDarkMode();
                    else
                        applyLightMode();

                    break;
            }
        });
    }

    const currentTheme = localStorage.getItem("theme");
    changeTheme(currentTheme);
}

function changeTheme(newTheme) {
    switch (newTheme) {
        case "light":
            applyLightMode();
            break;

        case "dark":
            applyDarkMode();
            break;

        case "amber":
            applyAmberMode();
            break;

        default:
            if (window.matchMedia) {
                if (window.matchMedia("(prefers-color-scheme: dark)").matches)
                    applyDarkMode();
                else
                    applyLightMode();
            }

            break;
    }

    localStorage.setItem("theme", newTheme);

    updateDashboardChartTheme();
}

function applyDarkMode() {
    document.body.classList.add("dark-mode");
    document.body.classList.remove("light-mode", "amber-mode");
}

function applyLightMode() {
    document.body.classList.add("light-mode");
    document.body.classList.remove("dark-mode", "amber-mode");
}

function applyAmberMode() {
    document.body.classList.add("amber-mode");
    document.body.classList.remove("light-mode", "dark-mode");
}

function showChangeThemeModal() {
    const currentTheme = localStorage.getItem("theme");
    switch (currentTheme) {
        case "light":
            $("#rdChangeThemeLight").prop("checked", true);
            break;

        case "dark":
            $("#rdChangeThemeDark").prop("checked", true);
            break;

        case "amber":
            $("#rdChangeThemeAmber").prop("checked", true);
            break;

        default:
            $("#rdChangeThemeSystem").prop("checked", true);
            break;
    }

    $("#modalChangeTheme").modal("show");
}
