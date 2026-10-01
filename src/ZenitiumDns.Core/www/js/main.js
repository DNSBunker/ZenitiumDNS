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

var refreshTimerHandle;
var reverseProxyDetected = false;
var quickBlockLists = null;
var quickForwardersList = null;

function onServerReconnected() {
    if (typeof resetLiveSystem === "function")
        resetLiveSystem();

    switch ($("ul.main-nav li.active").attr("id")) {
        case "mainPanelTabListDashboard":
            refreshDashboard(true);
            break;

        case "mainPanelTabListSelfTest":
            refreshSelfTest(false);
            break;

        case "mainPanelTabListDhcp":
            if ($("#dhcpTabListStatus").hasClass("active"))
                refreshDhcpStatus();
            else if ($("#dhcpTabListLeases").hasClass("active"))
                refreshDhcpLeases();

            break;
    }
}

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

    $("#divLoginLanguage").toggle(!zdnsI18n.chosen);
    $("#divLoginLanguage a").each(function () {
        $(this).toggleClass("active", $(this).attr("data-language") === zdnsI18n.language);
    });

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

            if (responseJSON.onlyAdminUser && ($("#txtUser").val() === "")) {
                $("#txtUser").val("admin");

                if ($("#txtPass").val() === "")
                    $("#txtPass").trigger("focus");
            }

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

    $("#filterTabListBlockLists").toggle(permissions.Settings.canView);
    $("#filterTabListBlocked").toggle(permissions.Blocked.canView);
    $("#filterTabListAllowed").toggle(permissions.Allowed.canView);
    $("#filterTabListClients").toggle(permissions.Settings.canView);
    $("#filterTabListBlocking").toggle(permissions.Settings.canView);

    $("#mainPanelTabPaneFilter .sub-nav > li").removeClass("active");
    $("#mainPanelTabPaneFilter > .tab-content > .tab-pane").removeClass("active");

    if (permissions.Settings.canView) {
        $("#filterTabListBlockLists").addClass("active");
        $("#filterTabPaneBlockLists").addClass("active");
    }
    else if (permissions.Blocked.canView) {
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

    $("#txtDnsClientNameServer").val(tr("Dieser Server") + " {this-server}");
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
        { list: "#mainPanelTabListFilter", pane: "#mainPanelTabPaneFilter", visible: canViewFilter, open: function () { refreshFilterTab(); } },
        { list: "#mainPanelTabListDhcp", pane: "#mainPanelTabPaneDhcp", visible: (permissions.DhcpServer != null) && permissions.DhcpServer.canView, open: function () { refreshDhcpTab(); } },
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
        if ((type === "lastHour") || (type === "last30Minutes"))
            refreshDashboard(true);

        checkDashboardHealth();

        $("#lblAboutUptime").text(moment(sessionData.info.uptimestamp).local().format("lll") + " (" + moment(sessionData.info.uptimestamp).fromNow() + ")");
    }, 30000);

    languageChooserVisible = showLanguageChooserIfNeeded();
}

var languageChooserVisible = false;
var languageChooserPasswordPrompt = null;

function setLoginLanguage(language) {
    zdnsI18n.setLanguageCookie(language);
    window.location.reload();
}

function showLanguageChooserIfNeeded() {
    if (zdnsI18n.chosen || (sessionData == null) || (sessionData.info == null) || !sessionData.info.permissions.Settings.canModify)
        return false;

    hideAlert($("#divChooseLanguageAlert"));

    $("#modalChooseLanguage .language-choice .btn").each(function () {
        var current = $(this).attr("data-language") === zdnsI18n.language;
        $(this).toggleClass("btn-primary", current).toggleClass("btn-default", !current);
    });

    $("#modalChooseLanguage").modal("show");
    return true;
}

function chooseLanguage(objBtn, language) {
    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/settings/set",
        token: sessionData.token,
        method: "POST",
        data: "language=" + encodeURIComponent(language),
        processData: false,
        success: function () {
            zdnsI18n.chosen = true;
            languageChooserVisible = false;

            if (language !== zdnsI18n.language) {
                if (languageChooserPasswordPrompt != null) {
                    try {
                        sessionStorage.setItem("changePasswordPrompt", "true");
                    }
                    catch (e) { }
                }

                window.location.reload();
                return;
            }

            btn.button("reset");
            $("#modalChooseLanguage").modal("hide");

            if (languageChooserPasswordPrompt != null) {
                showChangePasswordModal(languageChooserPasswordPrompt);
                languageChooserPasswordPrompt = null;
            }
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalChooseLanguage").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: $("#divChooseLanguageAlert")
    });
}

function consumeChangePasswordPrompt() {
    var prompt = null;

    try {
        prompt = sessionStorage.getItem("changePasswordPrompt");
        sessionStorage.removeItem("changePasswordPrompt");
    }
    catch (e) { }

    return prompt === "true";
}

function updatePageTitle() {
    var title = $(".main-nav > li.active > a").first().text().trim();
    $("#lblPageTitle").text(title === "" ? "ZenitiumDNS" : title);
}

function refreshResolverTab() {
    if ($("#resolverTabListZones").hasClass("active"))
        refreshZones(true);
}

function updateCacheDependentSettings() {
    var enabled = $("#chkEnableCache").prop("checked");

    $(".cache-dependent").toggleClass("settings-section-inactive", !enabled);
    $(".cache-dependent :input").prop("disabled", !enabled);

    if (enabled)
        $("#chkServeStale").triggerHandler("click");
}

function refreshFilterTab() {
    var active = $("#mainPanelTabPaneFilter .sub-nav > li.active").attr("id");

    if ((active === "filterTabListBlockLists") || (active === "filterTabListBlocking"))
        loadFilterSettings();
}

function showFilterSection(filterTabListId) {
    $("#mainPanelTabListFilter a").tab("show");
    $("#" + filterTabListId + " a").tab("show");
    loadFilterSettings();
}

function loadFilterSettings() {
    var bodies = $("#mainPanelTabPaneFilter .filter-settings-body");
    var loaders = $("#mainPanelTabPaneFilter .filter-settings-loader");

    $(".filter-settings-save").prop("disabled", true);
    bodies.hide();
    loaders.show();

    HTTPRequest({
        url: "api/settings/get",
        token: sessionData.token,
        success: function (responseJSON) {
            updateDnsSettingsDataAndGui(responseJSON);
            loadDnsSettings(responseJSON);

            $(".filter-settings-save").toggle(sessionData.info.permissions.Settings.canModify).prop("disabled", false);
            applySettingsLockState();
            refreshBlockListStatus();

            loaders.hide();
            bodies.show();
        },
        error: function () {
            loaders.hide();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: loaders
    });
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

    $("#divDnsSettings .settings-nav a[data-toggle=tab]").on("shown.bs.tab", function (e) {
        $("#divSettingsActions").toggle($(e.target).attr("href") !== "#settingsTabPaneBackup");
    });

    $("#filterTabListBlockLists a, #filterTabListBlocking a").on("shown.bs.tab", function () {
        loadFilterSettings();
    });

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

    $("#chkEnableCache").on("change", updateCacheDependentSettings);

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

    $("input[type=radio][name=rdDo53Mode]").on("change", function () {
        updateDo53ModeState();
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
        $("#chkHideClientAddresses").prop("disabled", !enableLogging);
        $("#chkLogQueries").prop("disabled", !enableLogging);
        $("#chkUseLocalTime").prop("disabled", !enableLogging);
        $("#txtLogFolderPath").prop("disabled", !enableLogging);
    });

    $("#chkDnssecValidation").on("click", function () {
        $("#chkDnssecAggressiveNsec").prop("disabled", !$("#chkDnssecValidation").prop("checked"));
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
    if (!confirm(tr("Ohne Update-Hinweise zeigt die Weboberfläche nach der Anmeldung keine neuen Versionen mehr an.\r\n\r\nUpdate-Hinweise wirklich ausblenden?")))
        return;

    localStorage.setItem("disableUpdateNotification", true);
    $("#mnuDisableCheckForUpdateNotification").hide();
    $("#mnuEnableCheckForUpdateNotification").show();
    $("#lnkUpdateAvailable").hide();

    showAlert("success", tr("Hinweise ausgeblendet"), tr("Update-Hinweise werden nicht mehr angezeigt."));
}

function enableUpdateNotification() {
    localStorage.setItem("disableUpdateNotification", false);
    $("#mnuEnableCheckForUpdateNotification").hide();
    $("#mnuDisableCheckForUpdateNotification").show();

    showAlert("success", tr("Hinweise eingeblendet"), tr("Update-Hinweise werden wieder angezeigt."));
}

function setAboutVersionInfo(info) {
    $("#lblAboutVersion").text(info.version);
    $("#lblAboutUptime").text(moment(info.uptimestamp).local().format("lll") + " (" + moment(info.uptimestamp).fromNow() + ")");

    if (info.technitiumVersion != null)
        $("#lblAboutTechnitiumVersion").text(info.technitiumVersion);

    if (info.runtimeVersion != null)
        $("#lblAboutRuntime").text(tr("{0} auf {1} ({2})", info.runtimeVersion, info.osDescription, info.osArchitecture));
}

function renderReleaseNotesInline(text) {
    var html = htmlEncode(text);

    html = html.replace(/`([^`]+)`/g, "<code>$1</code>");
    html = html.replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>");
    html = html.replace(/\[([^\]]+)\]\((https:\/\/[^\s)"]+)\)/g, "<a href=\"$2\" target=\"_blank\" rel=\"noopener noreferrer\">$1</a>");

    return html;
}

function renderReleaseNotes(markdown) {
    if ((markdown == null) || (markdown.trim().length === 0))
        return "<p>" + tr("Für diese Version gibt es keine Beschreibung.") + "</p>";

    var lines = markdown.replace(/\r\n/g, "\n").split("\n");
    var html = "";
    var inList = false;
    var inCode = false;
    var paragraph = [];

    function flushParagraph() {
        if (paragraph.length > 0) {
            html += "<p>" + paragraph.map(renderReleaseNotesInline).join(" ") + "</p>";
            paragraph = [];
        }
    }

    function closeList() {
        if (inList) {
            html += "</ul>";
            inList = false;
        }
    }

    for (var i = 0; i < lines.length; i++) {
        var line = lines[i];

        if (/^```/.test(line.trim())) {
            flushParagraph();
            closeList();
            html += inCode ? "</pre>" : "<pre>";
            inCode = !inCode;
            continue;
        }

        if (inCode) {
            html += htmlEncode(line) + "\n";
            continue;
        }

        var heading = /^(#{1,6})\s+(.*)$/.exec(line);
        if (heading != null) {
            flushParagraph();
            closeList();
            html += "<h5>" + renderReleaseNotesInline(heading[2]) + "</h5>";
            continue;
        }

        var item = /^\s*[-*]\s+(.*)$/.exec(line);
        if (item != null) {
            flushParagraph();
            if (!inList) {
                html += "<ul>";
                inList = true;
            }

            html += "<li>" + renderReleaseNotesInline(item[1]) + "</li>";
            continue;
        }

        if (line.trim().length === 0) {
            flushParagraph();
            closeList();
            continue;
        }

        if (inList && /^\s+/.test(line)) {
            html = html.replace(/<\/li>$/, " " + renderReleaseNotesInline(line.trim()) + "</li>");
            continue;
        }

        closeList();
        paragraph.push(line.trim());
    }

    flushParagraph();
    closeList();

    if (inCode)
        html += "</pre>";

    return html;
}

function checkForUpdate(force) {
    if (!force) {
        var disableUpdateNotification = localStorage.getItem("disableUpdateNotification");
        if (disableUpdateNotification === "true")
            return;
    }

    HTTPRequest({
        url: "api/user/checkForUpdate" + (force ? "?force=true" : ""),
        token: sessionData.token,
        success: function (responseJSON) {
            var response = responseJSON.response;
            var lnkUpdateAvailable = $("#lnkUpdateAvailable");
            var lblAboutUpdateStatus = $("#lblAboutUpdateStatus");

            if (!response.dnsServerEnableCheckForUpdate) {
                lnkUpdateAvailable.hide();
                lblAboutUpdateStatus.text(tr("Die Update-Prüfung ist in den Einstellungen ausgeschaltet."));

                if (force)
                    showAlert("warning", tr("Update-Prüfung ausgeschaltet"), tr("Die Update-Prüfung ist unter Einstellungen > Server ausgeschaltet."));

                return;
            }

            if (response.updateCheckError != null) {
                lnkUpdateAvailable.hide();
                lblAboutUpdateStatus.text(tr("GitHub ist gerade nicht erreichbar: {0}", response.updateCheckError));

                if (force)
                    showAlert("warning", tr("Update-Prüfung fehlgeschlagen"), tr("GitHub ist gerade nicht erreichbar: {0}", response.updateCheckError));

                return;
            }

            if (!response.updateAvailable) {
                lnkUpdateAvailable.hide();
                lblAboutUpdateStatus.text(tr("Die installierte Version ist aktuell. Neueste Version auf GitHub: {0}.", response.updateVersion));

                if (force)
                    showAlert("success", tr("Kein Update verfügbar"), tr("Die installierte Version {0} ist aktuell.", response.currentVersion));

                return;
            }

            $("#lblUpdateAvailableTitle").text(response.updateTitle);
            $("#lblUpdateVersion").text(response.updateVersion);
            $("#lblCurrentVersion").text(response.currentVersion);
            $("#lblUpdatePublished").text(response.publishedAt == null ? "" : tr(", veröffentlicht am {0}", moment(response.publishedAt).local().format("LL")));
            $("#divUpdateReleaseNotes").html(renderReleaseNotes(response.releaseNotes));

            if (response.releaseUrl == null)
                $("#lnkUpdateRelease").hide();
            else
                $("#lnkUpdateRelease").attr("href", response.releaseUrl).show();

            if (response.downloadLink == null) {
                $("#divUpdateInstall").hide();
            }
            else {
                $("#lnkUpdateDownload").attr("href", response.downloadLink).text(response.downloadName + " (" + formatNumber(response.downloadSize / 1048576, 1) + " MB)");
                $("#preUpdateInstall").text("wget " + response.downloadLink + "\nsudo apt install ./" + response.downloadName);

                if (response.checksumsLink == null)
                    $("#lnkUpdateChecksums").hide();
                else
                    $("#lnkUpdateChecksums").attr("href", response.checksumsLink).show();

                $("#divUpdateInstall").show();
            }

            lnkUpdateAvailable.html("<span class=\"fa fa-arrow-circle-up\" aria-hidden=\"true\"></span> " + tr("Version {0} verfügbar", htmlEncode(response.updateVersion)));
            lnkUpdateAvailable.show();
            lblAboutUpdateStatus.html(tr("Version {0} ist verfügbar.", "<b>" + htmlEncode(response.updateVersion) + "</b>") + " <a href=\"#\" data-toggle=\"modal\" data-target=\"#modalUpdateAvailable\">" + tr("Änderungen und Installation ansehen") + "</a>");

            if (force)
                $("#modalUpdateAvailable").modal("show");
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
            showAlert("danger", tr("Fehler"), tr("Die Blocklisten-Schnellauswahl konnte nicht geladen werden: {0}", jqXHR.status + " " + jqXHR.statusText));
        }
    });
}

function loadQuickBlockListsFrom(responseJSON) {
    var htmlList = "<option value=\"blank\" selected></option><option value=\"none\">" + tr("Leeren") + "</option>";
    var currentGroup = null;

    for (var i = 0; i < responseJSON.length; i++) {
        var group = responseJSON[i].group == null ? null : responseJSON[i].group;

        if (group !== currentGroup) {
            if (currentGroup !== null)
                htmlList += "</optgroup>";

            if (group !== null)
                htmlList += "<optgroup label=\"" + htmlEncode(tr(group)) + "\">";

            currentGroup = group;
        }

        htmlList += "<option value=\"" + htmlEncode(responseJSON[i].name) + "\">" + htmlEncode(tr(responseJSON[i].name)) + "</option>";
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
                    showAlert("danger", tr("Fehler"), tr("Die Forwarder-Schnellauswahl konnte nicht geladen werden: {0}", jqXHR.status + " " + jqXHR.statusText));
                }
            });
        }
    });
}

function loadQuickForwardersListFrom(responseJSON) {
    var htmlList = "<option value=\"blank\" selected></option><option value=\"none\">" + tr("Leeren") + "</option>";

    for (var i = 0; i < responseJSON.length; i++) {
        htmlList += "<option>" + htmlEncode(responseJSON[i].name) + "</option>";
    }

    quickForwardersList = responseJSON;
    $("#optQuickForwarders").html(htmlList);
}

function renderLanguageOptions(importedLanguages, selected) {
    var optLanguage = $("#optLanguage");
    optLanguage.find("option.imported-language").remove();

    var list = $("#divImportedLanguages");
    list.empty();

    if (importedLanguages != null) {
        for (var i = 0; i < importedLanguages.length; i++) {
            var item = importedLanguages[i];

            optLanguage.append($("<option class=\"imported-language\"></option>").val(item.code).attr("lang", item.code).text(item.name + " (" + item.code + ")"));

            var row = $("<div class=\"imported-language-row\"></div>");
            row.append($("<span></span>").text(item.name + " (" + item.code + ")"));
            row.append(" ");
            row.append($("<button type=\"button\" class=\"btn btn-default btn-xs\"></button>").text(tr("Entfernen")).attr("data-code", item.code).on("click", function () {
                deleteImportedLanguage(this, $(this).attr("data-code"));
            }));

            list.append(row);
        }
    }

    if ((importedLanguages == null) || (importedLanguages.length === 0))
        list.append($("<span class=\"text-muted\"></span>").text(tr("Keine")));

    optLanguage.val(selected);
}

function importLanguage(objBtn) {
    var code = $("#txtImportLanguageCode").val().trim();
    var name = $("#txtImportLanguageName").val().trim();
    var fileInput = $("#fileImportLanguage")[0];

    if (!/^[a-z]{2,3}(-[A-Za-z0-9]{2,8})?$/.test(code)) {
        showAlert("warning", tr("Ungültige Angabe"), tr("Der Sprachcode muss aus 2 oder 3 Kleinbuchstaben bestehen, optional mit Region, z. B. fr oder pt-BR."));
        $("#txtImportLanguageCode").trigger("focus");
        return;
    }

    if (name === "") {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte den Namen der Sprache eingeben."));
        $("#txtImportLanguageName").trigger("focus");
        return;
    }

    if ((fileInput.files == null) || (fileInput.files.length === 0)) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte eine Sprachdatei auswählen."));
        return;
    }

    var formData = new FormData();
    formData.append("code", code);
    formData.append("name", name);
    formData.append("fileLanguage", fileInput.files[0]);

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/settings/languages/import",
        method: "POST",
        data: formData,
        processData: false,
        contentType: false,
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");

            var r = responseJSON.response;
            var message = tr("{0} von {1} Texten übernommen.", r.translated, r.total);

            if (r.rejected > 0)
                message += " " + tr("{0} Einträge verworfen, weil Markup oder Platzhalter nicht zum Original passen.", r.rejected);

            if (r.unknown > 0)
                message += " " + tr("{0} unbekannte Einträge ignoriert.", r.unknown);

            showAlert("success", tr("Sprache importiert"), message);

            $("#txtImportLanguageCode").val("");
            $("#txtImportLanguageName").val("");
            $("#fileImportLanguage").val("");

            refreshDnsSettings();
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

function deleteImportedLanguage(objBtn, code) {
    if (!confirm(tr("Sprache {0} wirklich entfernen?", code)))
        return;

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/settings/languages/delete?code=" + encodeURIComponent(code),
        token: sessionData.token,
        success: function () {
            if (code === zdnsI18n.language) {
                window.location.reload();
                return;
            }

            refreshDnsSettings();
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
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
            $("#btnShowBackupSettingsModal").toggle(sessionData.info.permissions.Settings.canDelete);
            $("#btnShowRestoreSettingsModal").toggle(sessionData.info.permissions.Settings.canDelete);
            $("#btnSettingsLock").toggle(sessionData.info.permissions.Settings.canModify);
            applySettingsLockState();

            refreshIpv6UpstreamStatus();
            refreshBlockListStatus();

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
        div.html("<span class=\"label label-default\">" + tr("IPv6 deaktiviert") + "</span>");
    }
    else if (serverStatus.ipv6UpstreamAvailable) {
        div.html("<span class=\"label label-success\">" + tr("IPv6 wird genutzt") + "</span>");
    }
    else if (serverStatus.ipv6UpstreamUnavailableUntil != null) {
        div.html("<span class=\"label label-warning\">" + tr("IPv6 ausgesetzt") + "</span> " + htmlEncode(tr("bis {0} ({1}), bis dahin nur IPv4", moment(serverStatus.ipv6UpstreamUnavailableUntil).local().format("LTS"), moment(serverStatus.ipv6UpstreamUnavailableUntil).fromNow())));
    }
    else {
        div.html("<span class=\"label label-warning\">" + tr("IPv6 ausgesetzt") + "</span>");
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
            var r = responseJSON.response;
            renderIpv6UpstreamStatus(r.serverStatus != null ? r.serverStatus : r);

            var available = (r.serverStatus != null) ? r.serverStatus.ipv6UpstreamAvailable : r.ipv6UpstreamAvailable;
            var lastResponse = (r.lastIPv6ResponseSecondsAgo == null) ? "" : " " + tr("Letzte Antwort eines Nameservers über IPv6: vor {0} s.", r.lastIPv6ResponseSecondsAgo);

            if (r.probeSucceeded)
                showAlert("success", tr("IPv6 erreichbar"), tr("Die IPv6-Root-Server antworten. Ausgehende IPv6-Anfragen sind aktiv.") + lastResponse);
            else if (available)
                showAlert("warning", tr("IPv6 aktiv, Root-Server-Prüfung fehlgeschlagen"), tr("Nameserver antworten über IPv6, deshalb bleibt IPv6 aktiv. Die IPv6-Root-Server waren bei der Prüfung aber nicht erreichbar: {0}", (r.probeError == null ? tr("unbekannter Fehler") : r.probeError)) + lastResponse);
            else
                showAlert("warning", tr("IPv6 nicht erreichbar"), tr("Weder die IPv6-Root-Server noch andere Nameserver antworten über IPv6. Ausgehende Anfragen laufen vorerst nur über IPv4.") + (r.probeError == null ? "" : " " + r.probeError));
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
    setAboutVersionInfo(responseJSON.response);
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

    renderLanguageOptions(responseJSON.response.importedLanguages, responseJSON.response.language);

    $("#chkDnsServerEnableCheckForUpdate").prop("checked", responseJSON.response.dnsServerEnableCheckForUpdate);

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
        $("#lblClientBlockListStatus").text(tr("Keine Listen eingetragen."));
    else
        $("#lblClientBlockListStatus").text(tr("{0} Adressbereiche geladen, zuletzt aktualisiert {1}, {2} Anfragen oder Verbindungen seit dem Start verworfen.", formatNumber(responseJSON.response.clientBlockListAddressRanges), (responseJSON.response.clientBlockListLastUpdatedOn == null ? tr("noch nie") : tr("am {0}", moment(responseJSON.response.clientBlockListLastUpdatedOn).local().format(tr("DD.MM.YYYY HH:mm")))), formatNumber(responseJSON.response.clientBlockListDrops)));

    $(".rule-hits").each(function () {
        var matches = responseJSON.response.requestFilterMatches == null ? null : responseJSON.response.requestFilterMatches[$(this).attr("data-rule")];
        $(this).text(matches == null ? "" : tr("{0} Treffer", formatNumber(matches)));
    });

    $("#chkEnableUdpSocketPool").prop("checked", responseJSON.response.enableUdpSocketPool);
    $("#txtUdpSocketPoolExcludedPorts").prop("disabled", !responseJSON.response.enableUdpSocketPool);
    $("#txtUdpSocketPoolExcludedPorts").val(getArrayAsString(responseJSON.response.socketPoolExcludedPorts));
    $("#txtEdnsUdpPayloadSize").val(responseJSON.response.udpPayloadSize);
    $("#chkDnssecValidation").prop("checked", responseJSON.response.dnssecValidation);
    $("#chkDnssecPostQuantumDowngradeProtection").prop("checked", responseJSON.response.dnssecPostQuantumDowngradeProtection !== false);
    $("#chkDnssecAggressiveNsec").prop("checked", responseJSON.response.dnssecAggressiveNsec !== false);
    $("#chkDnssecAggressiveNsec").prop("disabled", !responseJSON.response.dnssecValidation);

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

    $("#chkMetricsEnabled").prop("checked", responseJSON.response.metricsEnabled);
    $("#txtMetricsAllowedNetworks").val(getArrayAsString(responseJSON.response.metricsAllowedNetworks));
    $("#txtMetricsToken").val(responseJSON.response.metricsToken == null ? "" : responseJSON.response.metricsToken);
    updateMetricsOptions();

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
    $("#chkDdrProxyDoh").prop("checked", responseJSON.response.ddrProxyDoh);
    $("#txtDdrProxyDohPort").val(responseJSON.response.ddrProxyDohPort);
    $("#chkDdrProxyDohHttp3").prop("checked", responseJSON.response.ddrProxyDohHttp3);

    switch (responseJSON.response.do53Mode) {
        case "DdrOnlyDrop":
            $("#rdDo53ModeDdrOnlyDrop").prop("checked", true);
            break;

        case "DdrOnlyRefused":
            $("#rdDo53ModeDdrOnlyRefused").prop("checked", true);
            break;

        case "Disabled":
            $("#rdDo53ModeDisabled").prop("checked", true);
            break;

        default:
            $("#rdDo53ModeEnabled").prop("checked", true);
            break;
    }

    updateDo53ModeState();

    switch (responseJSON.response.eDnsPaddingMode) {
        case "Always":
            $("#rdEDnsPaddingModeAlways").prop("checked", true);
            break;

        case "Disabled":
            $("#rdEDnsPaddingModeDisabled").prop("checked", true);
            break;

        default:
            $("#rdEDnsPaddingModeWhenRequested").prop("checked", true);
            break;
    }

    if ((responseJSON.response.ddrRecords == null) || (responseJSON.response.ddrRecords.length === 0))
        $("#preDdrRecords").text(tr("Keine Einträge: Es ist kein TLS-Zertifikat geladen oder kein verschlüsselter Dienst aktiv."));
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
    $("#chkEnableDnsCookies").prop("checked", responseJSON.response.enableDnsCookies);
    $("#txtDnsCookieSecret").val(responseJSON.response.dnsCookieSecret == null ? "" : responseJSON.response.dnsCookieSecret);
    $("#txtDnsCookieSecret").prop("disabled", !responseJSON.response.enableDnsCookies);
    $("#chkQnameMinimization").prop("checked", responseJSON.response.qnameMinimization);
    $("#chkQnameMinimizationFallback").prop("checked", responseJSON.response.qnameMinimizationFallback);
    $("#lblQnameMinimizationFallbackZones").text(responseJSON.response.qnameMinimizationFallbackZones);
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

    $("#chkEnableCache").prop("checked", responseJSON.response.enableCache !== false);
    updateCacheDependentSettings();
    $("#txtCacheMaximumEntries").val(responseJSON.response.cacheMaximumEntries);
    $("#txtCacheMaximumMemory").val(responseJSON.response.cacheMaximumMemory);
    $("#txtCacheMinimumRecordTtl").val(responseJSON.response.cacheMinimumRecordTtl);
    $("#txtCacheMaximumRecordTtl").val(responseJSON.response.cacheMaximumRecordTtl);
    $("#txtCacheNegativeRecordTtl").val(responseJSON.response.cacheNegativeRecordTtl);
    $("#txtCacheMaximumNegativeRecordTtl").val(responseJSON.response.cacheMaximumNegativeRecordTtl);
    $("#txtCacheFailureRecordTtl").val(responseJSON.response.cacheFailureRecordTtl);

    $("#txtCachePrefetchEligibility").val(responseJSON.response.cachePrefetchEligibility);
    $("#txtCachePrefetchTrigger").val(responseJSON.response.cachePrefetchTrigger);
    $("#txtCachePrefetchTriggerPercent").val(responseJSON.response.cachePrefetchTriggerPercent);

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
        $("#lblTemporaryDisableBlockingTill").text(tr("nicht pausiert"));
    else
        $("#lblTemporaryDisableBlockingTill").text(moment(responseJSON.response.temporaryDisableBlockingTill).local().format(tr("DD.MM.YYYY HH:mm:ss")));

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
    $("#chkBlockFirefoxCanaryDomain").prop("checked", responseJSON.response.blockFirefoxCanaryDomain);
    $("#chkEnableLiveMonitoring").prop("checked", responseJSON.response.enableLiveMonitoring);
    $("#chkEnableWatchdog").prop("checked", responseJSON.response.enableWatchdog);
    renderIanaData(responseJSON.response.ianaData);
    $("#chkForceChromePreflight").prop("checked", responseJSON.response.forceChromePreflight);

    if ((responseJSON.response.autoAllowedNames == null) || (responseJSON.response.autoAllowedNames.length === 0))
        $("#lblAutoAllowedNames").text(tr("Keine: Der Serverdomainname ist kein vollständiger Domainname und es ist kein TLS-Zertifikat geladen."));
    else
        $("#lblAutoAllowedNames").text(responseJSON.response.autoAllowedNames.join(", "));
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
        $("#lblBlockListNextUpdatedOn").text(tr("nicht geplant"));
    }
    else {
        var blockListNextUpdatedOn = moment(responseJSON.response.blockListNextUpdatedOn);

        if (moment().utc().isBefore(blockListNextUpdatedOn))
            $("#lblBlockListNextUpdatedOn").text(blockListNextUpdatedOn.local().format(tr("DD.MM.YYYY HH:mm:ss")));
        else
            $("#lblBlockListNextUpdatedOn").text(tr("wird gerade aktualisiert"));
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

    $("#txtHttpUserAgent").val(responseJSON.response.httpUserAgent == null ? "" : responseJSON.response.httpUserAgent);
    $("#txtHttpUserAgent").attr("placeholder", responseJSON.response.httpUserAgentDefault);

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
    $("#chkHideClientAddresses").prop("disabled", !enableLogging);
    $("#chkLogQueries").prop("disabled", !enableLogging);
    $("#chkUseLocalTime").prop("disabled", !enableLogging);
    $("#txtLogFolderPath").prop("disabled", !enableLogging);

    $("#chkIgnoreResolverLogs").prop("checked", responseJSON.response.ignoreResolverLogs);
    $("#chkNoStackTrace").prop("checked", responseJSON.response.noStackTrace);
    $("#chkHideClientAddresses").prop("checked", responseJSON.response.hideClientAddresses);
    $("#chkLogQueries").prop("checked", responseJSON.response.logQueries);
    $("#chkUseLocalTime").prop("checked", responseJSON.response.useLocalTime);
    $("#txtLogFolderPath").val(responseJSON.response.logFolder);
    $("#txtMaxLogFileDays").val(responseJSON.response.maxLogFileDays);

    $("#chkEnableInMemoryStats").prop("checked", responseJSON.response.enableInMemoryStats);
    $("#txtMaxStatFileDays").val(responseJSON.response.maxStatFileDays);
}

function updateMetricsOptions() {
    var metricsEnabled = $("#chkMetricsEnabled").prop("checked");

    $("#txtMetricsAllowedNetworks").prop("disabled", !metricsEnabled);
    $("#txtMetricsToken").prop("disabled", !metricsEnabled);
    $("#btnGenerateMetricsToken").prop("disabled", !metricsEnabled);

    updateMetricsScrapeConfig();
}

function generateMetricsToken() {
    var bytes = new Uint8Array(24);
    window.crypto.getRandomValues(bytes);

    var token = btoa(String.fromCharCode.apply(null, bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

    $("#txtMetricsToken").val(token);
    updateMetricsScrapeConfig();
}

function updateMetricsScrapeConfig() {
    var scheme = window.location.protocol === "https:" ? "https" : "http";
    var port = window.location.port;

    if ((port == null) || (port === ""))
        port = scheme === "https" ? "443" : "80";

    var token = $("#txtMetricsToken").val();
    token = token == null ? "" : token.trim();

    var lines = [
        "- job_name: zenitiumdns",
        "  scheme: " + scheme,
        "  metrics_path: /metrics"
    ];

    if (token.length > 0) {
        lines.push("  authorization:");
        lines.push("    credentials: " + token);
    }

    lines.push("  static_configs:");
    lines.push("    - targets: [\"" + window.location.hostname.replace(/^([0-9a-f:]*:[0-9a-f:]*)$/i, "[$1]") + ":" + port + "\"]");

    $("#preMetricsScrapeConfig").text(lines.join("\n"));
}

function saveDnsSettings(objBtn) {
    var formData = "";

    var dnsServerDomain = $("#txtDnsServerDomain").val();

    if ((dnsServerDomain === null) || (dnsServerDomain === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte die Server-Domain eingeben."));
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

    formData += "&defaultRecordTtl=" + encodeURIComponent(defaultRecordTtl) + "&defaultResponsiblePerson=" + encodeURIComponent(defaultResponsiblePerson) + "&dnsServerEnableCheckForUpdate=" + dnsServerEnableCheckForUpdate;

    var language = $("#optLanguage").val();
    if ((language != null) && /^[a-z]{2,3}(-[A-Za-z0-9]{2,8})?$/.test(language))
        formData += "&language=" + encodeURIComponent(language);

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
    var dnssecAggressiveNsec = $("#chkDnssecAggressiveNsec").prop("checked");

    var eDnsClientSubnet = $("#chkEDnsClientSubnet").prop("checked");

    var eDnsClientSubnetIPv4PrefixLength = $("#txtEDnsClientSubnetIPv4PrefixLength").val();
    if ((eDnsClientSubnetIPv4PrefixLength == null) || (eDnsClientSubnetIPv4PrefixLength === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte die IPv4-Präfixlänge für ECS eingeben."));
        $("#txtEDnsClientSubnetIPv4PrefixLength").trigger("focus");
        return;
    }

    var eDnsClientSubnetIPv6PrefixLength = $("#txtEDnsClientSubnetIPv6PrefixLength").val();
    if ((eDnsClientSubnetIPv6PrefixLength == null) || (eDnsClientSubnetIPv6PrefixLength === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte die IPv6-Präfixlänge für ECS eingeben."));
        $("#txtEDnsClientSubnetIPv6PrefixLength").trigger("focus");
        return;
    }

    var eDnsClientSubnetIpv4Override = $("#txtEDnsClientSubnetIpv4Override").val();
    var eDnsClientSubnetIpv6Override = $("#txtEDnsClientSubnetIpv6Override").val();

    if (!validateQpsPrefixLimits($("#tableQpsPrefixLimitsIPv4"), 32) || !validateQpsPrefixLimits($("#tableQpsPrefixLimitsIPv6"), 128))
        return;

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
    if (!isIntegerInRange(rateLimitBurstSeconds, 1, 60)) {
        showAlert("warning", tr("Ungültige Angabe"), tr("Die Burst-Dauer muss zwischen 1 und 60 Sekunden liegen."));
        $("#txtRateLimitBurstSeconds").trigger("focus");
        return;
    }

    var rateLimitUdpTruncationPercentage = $("#txtRateLimitUdpTruncation").val();
    if (!isIntegerInRange(rateLimitUdpTruncationPercentage, 0, 100)) {
        showAlert("warning", tr("Ungültige Angabe"), tr("Der Anteil der TC-Antworten muss zwischen 0 und 100 % liegen."));
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
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte einen Wert für das Client-Zeitlimit eingeben."));
        $("#txtClientTimeout").trigger("focus");
        return;
    }

    var tcpSendTimeout = $("#txtTcpSendTimeout").val();
    if ((tcpSendTimeout == null) || (tcpSendTimeout === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte einen Wert für das TCP-Sendezeitlimit eingeben."));
        $("#txtTcpSendTimeout").trigger("focus");
        return;
    }

    var tcpReceiveTimeout = $("#txtTcpReceiveTimeout").val();
    if ((tcpReceiveTimeout == null) || (tcpReceiveTimeout === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte einen Wert für das TCP-Empfangszeitlimit eingeben."));
        $("#txtTcpReceiveTimeout").trigger("focus");
        return;
    }

    var quicIdleTimeout = $("#txtQuicIdleTimeout").val();
    if ((quicIdleTimeout == null) || (quicIdleTimeout === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte einen Wert für die QUIC-Leerlaufzeit eingeben."));
        $("#txtQuicIdleTimeout").trigger("focus");
        return;
    }

    var quicMaxInboundStreams = $("#txtQuicMaxInboundStreams").val();
    if ((quicMaxInboundStreams == null) || (quicMaxInboundStreams === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte einen Wert für die QUIC-Streams je Verbindung eingeben."));
        $("#txtQuicMaxInboundStreams").trigger("focus");
        return;
    }

    var listenBacklog = $("#txtListenBacklog").val();
    if ((listenBacklog == null) || (listenBacklog === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte einen Wert für das Listen-Backlog eingeben."));
        $("#txtListenBacklog").trigger("focus");
        return;
    }

    var udpSendBufferSizeKB = $("#txtUdpSendBufferSizeKB").val();
    if ((udpSendBufferSizeKB == null) || (udpSendBufferSizeKB === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte einen Wert für den UDP-Sendepuffer eingeben."));
        $("#txtUdpSendBufferSizeKB").trigger("focus");
        return;
    }

    var udpReceiveBufferSizeKB = $("#txtUdpReceiveBufferSizeKB").val();
    if ((udpReceiveBufferSizeKB == null) || (udpReceiveBufferSizeKB === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte einen Wert für den UDP-Empfangspuffer eingeben."));
        $("#txtUdpReceiveBufferSizeKB").trigger("focus");
        return;
    }

    var maxConcurrentResolutionsPerCore = $("#txtMaxConcurrentResolutionsPerCore").val();
    if ((maxConcurrentResolutionsPerCore == null) || (maxConcurrentResolutionsPerCore === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte einen Wert für die gleichzeitigen Auflösungen eingeben."));
        $("#txtMaxConcurrentResolutionsPerCore").trigger("focus");
        return;
    }

    formData += "&udpPayloadSize=" + udpPayloadSize + "&dnssecValidation=" + dnssecValidation + "&dnssecPostQuantumDowngradeProtection=" + dnssecPostQuantumDowngradeProtection + "&dnssecAggressiveNsec=" + dnssecAggressiveNsec;
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

    var metricsEnabled = $("#chkMetricsEnabled").prop("checked");
    var metricsAllowedNetworks = cleanTextList($("#txtMetricsAllowedNetworks").val());

    if ((metricsAllowedNetworks.length === 0) || (metricsAllowedNetworks === ","))
        metricsAllowedNetworks = false;
    else
        $("#txtMetricsAllowedNetworks").val(metricsAllowedNetworks.replace(/,/g, "\n"));

    var metricsToken = $("#txtMetricsToken").val().trim();

    if ((metricsToken.length > 0) && ((metricsToken.length < 16) || (metricsToken.length > 255) || !/^[\x21-\x7e]+$/.test(metricsToken))) {
        showAlert("warning", tr("Ungültige Angabe"), tr("Das Metrik-Token muss aus 16 bis 255 sichtbaren ASCII-Zeichen ohne Leerzeichen bestehen."));
        $("#settingsTabListWebService a").tab("show");
        $("#txtMetricsToken").trigger("focus");
        return;
    }

    var webServiceTlsCertificatePath = $("#txtWebServiceTlsCertificatePath").val();
    var webServiceTlsCertificatePassword = $("#txtWebServiceTlsCertificatePassword").val();
    var webServiceTlsCertificateKeyPath = $("#txtWebServiceTlsCertificateKeyPath").val();

    formData += "&webServiceLocalAddresses=" + encodeURIComponent(webServiceLocalAddresses) + "&webServiceHttpPort=" + webServiceHttpPort + "&webServiceEnableHttpUnixSocket=" + webServiceEnableHttpUnixSocket + "&webServiceHttpUnixSocket=" + encodeURIComponent(webServiceHttpUnixSocket) + "&webServiceEnableTlsUnixSocket=" + webServiceEnableTlsUnixSocket + "&webServiceTlsUnixSocket=" + encodeURIComponent(webServiceTlsUnixSocket) + "&webServiceEnableTls=" + webServiceEnableTls + "&webServiceEnableHttp3=" + webServiceEnableHttp3 + "&webServiceHttpToTlsRedirect=" + webServiceHttpToTlsRedirect + "&webServiceUseSelfSignedTlsCertificate=" + webServiceUseSelfSignedTlsCertificate + "&webServiceTlsPort=" + webServiceTlsPort + "&webServiceReverseProxyAddresses=" + encodeURIComponent(webServiceReverseProxyAddresses) + "&webServiceRealIpHeader=" + encodeURIComponent(webServiceRealIpHeader) + "&webServiceCspFrameAncestorsHeader=" + encodeURIComponent(webServiceCspFrameAncestorsHeader) + "&webServiceTlsCertificatePath=" + encodeURIComponent(webServiceTlsCertificatePath) + "&webServiceTlsCertificatePassword=" + encodeURIComponent(webServiceTlsCertificatePassword) + "&webServiceTlsCertificateKeyPath=" + encodeURIComponent(webServiceTlsCertificateKeyPath);
    formData += "&metricsEnabled=" + metricsEnabled + "&metricsAllowedNetworks=" + encodeURIComponent(metricsAllowedNetworks) + "&metricsToken=" + encodeURIComponent(metricsToken);

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
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte den Port für DNS-over-UDP-PROXY eingeben."));
        $("#txtDnsOverUdpProxyPort").trigger("focus");
        return;
    }

    var dnsOverTcpProxyPort = $("#txtDnsOverTcpProxyPort").val();
    if ((dnsOverTcpProxyPort == null) || (dnsOverTcpProxyPort === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte den Port für DNS-over-TCP-PROXY eingeben."));
        $("#txtDnsOverTcpProxyPort").trigger("focus");
        return;
    }

    var dnsOverHttpPort = $("#txtDnsOverHttpPort").val();
    if ((dnsOverHttpPort == null) || (dnsOverHttpPort === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte den Port für DNS-over-HTTP eingeben."));
        $("#txtDnsOverHttpPort").trigger("focus");
        return;
    }

    var dnsOverHttpUnixSocket = $("#txtDnsOverHttpUnixSocket").val();
    var dnsOverHttpsUnixSocket = $("#txtDnsOverHttpsUnixSocket").val();

    var dnsOverTlsPort = $("#txtDnsOverTlsPort").val();
    if ((dnsOverTlsPort == null) || (dnsOverTlsPort === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte den Port für DNS-over-TLS eingeben."));
        $("#txtDnsOverTlsPort").trigger("focus");
        return;
    }

    var dnsOverHttpsPort = $("#txtDnsOverHttpsPort").val();
    if ((dnsOverHttpsPort == null) || (dnsOverHttpsPort === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte den Port für DNS-over-HTTPS eingeben."));
        $("#txtDnsOverHttpsPort").trigger("focus");
        return;
    }

    var dnsOverQuicPort = $("#txtDnsOverQuicPort").val();
    if ((dnsOverQuicPort == null) || (dnsOverQuicPort === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte den Port für DNS-over-QUIC eingeben."));
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
    var do53Mode = $("input[name=rdDo53Mode]:checked").val();

    formData += "&enableEDnsClientSubnetSourceAddress=" + enableEDnsClientSubnetSourceAddress + "&enableDnsOverUdpProxy=" + enableDnsOverUdpProxy + "&enableDnsOverTcpProxy=" + enableDnsOverTcpProxy + "&enableDnsOverHttp=" + enableDnsOverHttp + "&enableDnsOverHttpUnixSocket=" + enableDnsOverHttpUnixSocket + "&enableDnsOverHttpsUnixSocket=" + enableDnsOverHttpsUnixSocket + "&enableDnsOverTls=" + enableDnsOverTls + "&enableDnsOverHttps=" + enableDnsOverHttps + "&enableDnsOverHttp3=" + enableDnsOverHttp3 + "&enableDnsOverQuic=" + enableDnsOverQuic + "&enableDnsOverHttpHelpRedirect=" + enableDnsOverHttpHelpRedirect + "&dnsOverUdpProxyPort=" + dnsOverUdpProxyPort + "&dnsOverTcpProxyPort=" + dnsOverTcpProxyPort + "&dnsOverHttpPort=" + dnsOverHttpPort + "&dnsOverHttpUnixSocket=" + encodeURIComponent(dnsOverHttpUnixSocket) + "&dnsOverHttpsUnixSocket=" + encodeURIComponent(dnsOverHttpsUnixSocket) + "&dnsOverTlsPort=" + dnsOverTlsPort + "&dnsOverHttpsPort=" + dnsOverHttpsPort + "&dnsOverQuicPort=" + dnsOverQuicPort + "&dnsReverseProxyNetworkACL=" + encodeURIComponent(dnsReverseProxyNetworkACL) + "&dnsOverHttpRealIpHeader=" + encodeURIComponent(dnsOverHttpRealIpHeader) + "&dnsTlsCertificatePath=" + encodeURIComponent(dnsTlsCertificatePath) + "&dnsTlsCertificatePassword=" + encodeURIComponent(dnsTlsCertificatePassword) + "&dnsTlsCertificateKeyPath=" + encodeURIComponent(dnsTlsCertificateKeyPath) + "&enableDdr=" + enableDdr + "&ddrOnlyUnencrypted=" + ddrOnlyUnencrypted + "&ddrProxyDoh=" + $("#chkDdrProxyDoh").prop("checked") + "&ddrProxyDohPort=" + encodeURIComponent($("#txtDdrProxyDohPort").val()) + "&ddrProxyDohHttp3=" + $("#chkDdrProxyDohHttp3").prop("checked") + "&do53Mode=" + do53Mode + "&eDnsPaddingMode=" + $("input[name=rdEDnsPaddingMode]:checked").val();

    var recursion = $("input[name=rdRecursion]:checked").val();

    var recursionNetworkACL = cleanTextList($("#txtRecursionNetworkACL").val());

    if ((recursionNetworkACL.length === 0) || (recursionNetworkACL === ","))
        recursionNetworkACL = false;
    else
        $("#txtRecursionNetworkACL").val(recursionNetworkACL.replace(/,/g, "\n"));

    var randomizeName = $("#chkRandomizeName").prop("checked");
    var enableDnsCookies = $("#chkEnableDnsCookies").prop("checked");
    var dnsCookieSecret = $("#txtDnsCookieSecret").val().trim();

    if ((dnsCookieSecret.length > 0) && !/^[0-9a-fA-F]{32}$/.test(dnsCookieSecret)) {
        showAlert("warning", tr("Ungültige Angabe"), tr("Das Cookie-Geheimnis muss aus 32 Hexadezimalzeichen (16 Byte) bestehen."));
        $("#settingsTabListRecursion a").tab("show");
        $("#txtDnsCookieSecret").trigger("focus");
        return;
    }
    var qnameMinimization = $("#chkQnameMinimization").prop("checked");
    var locallyServedDnsZones = $("#chkLocallyServedDnsZones").prop("checked");

    var resolverRetries = $("#txtResolverRetries").val();
    if ((resolverRetries == null) || (resolverRetries === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte die Wiederholungen des Resolvers eingeben."));
        $("#txtResolverRetries").trigger("focus");
        return;
    }

    var resolverTimeout = $("#txtResolverTimeout").val();
    if ((resolverTimeout == null) || (resolverTimeout === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte das Zeitlimit des Resolvers eingeben."));
        $("#txtResolverTimeout").trigger("focus");
        return;
    }

    var resolverConcurrency = $("#txtResolverConcurrency").val();
    if ((resolverConcurrency == null) || (resolverConcurrency === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte die parallelen Anfragen des Resolvers eingeben."));
        $("#txtResolverConcurrency").trigger("focus");
        return;
    }

    var resolverMaxStackCount = $("#txtResolverMaxStackCount").val();
    if ((resolverMaxStackCount == null) || (resolverMaxStackCount === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte die maximale Verschachtelung des Resolvers eingeben."));
        $("#txtResolverMaxStackCount").trigger("focus");
        return;
    }

    formData += "&recursion=" + recursion + "&recursionNetworkACL=" + encodeURIComponent(recursionNetworkACL)  + "&randomizeName=" + randomizeName + "&enableDnsCookies=" + enableDnsCookies + "&dnsCookieSecret=" + encodeURIComponent(dnsCookieSecret)  + "&qnameMinimization=" + qnameMinimization + "&qnameMinimizationFallback=" + $("#chkQnameMinimizationFallback").prop("checked") + "&locallyServedDnsZones=" + locallyServedDnsZones + "&resolverRetries=" + resolverRetries + "&resolverTimeout=" + resolverTimeout + "&resolverConcurrency=" + resolverConcurrency + "&resolverMaxStackCount=" + resolverMaxStackCount;

    var saveCache = $("#chkSaveCache").prop("checked");

    var serveStale = $("#chkServeStale").prop("checked");
    var serveStaleTtl = $("#txtServeStaleTtl").val();
    var serveStaleAnswerTtl = $("#txtServeStaleAnswerTtl").val();
    var serveStaleResetTtl = $("#txtServeStaleResetTtl").val();
    var serveStaleMaxWaitTime = $("#txtServeStaleMaxWaitTime").val();

    var cacheMaximumEntries = $("#txtCacheMaximumEntries").val();
    if ((cacheMaximumEntries === null) || (cacheMaximumEntries === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte die maximalen Cache-Einträge eingeben."));
        $("#txtCacheMaximumEntries").trigger("focus");
        return;
    }

    var cacheMinimumRecordTtl = $("#txtCacheMinimumRecordTtl").val();
    if ((cacheMinimumRecordTtl === null) || (cacheMinimumRecordTtl === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte die minimale Cache-TTL eingeben."));
        $("#txtCacheMinimumRecordTtl").trigger("focus");
        return;
    }

    var cacheMaximumRecordTtl = $("#txtCacheMaximumRecordTtl").val();
    if ((cacheMaximumRecordTtl === null) || (cacheMaximumRecordTtl === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte die maximale Cache-TTL eingeben."));
        $("#txtCacheMaximumRecordTtl").trigger("focus");
        return;
    }

    var cacheNegativeRecordTtl = $("#txtCacheNegativeRecordTtl").val();
    if ((cacheNegativeRecordTtl === null) || (cacheNegativeRecordTtl === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte die negative Cache-TTL eingeben."));
        $("#txtCacheNegativeRecordTtl").trigger("focus");
        return;
    }

    var cacheMaximumNegativeRecordTtl = $("#txtCacheMaximumNegativeRecordTtl").val();
    if ((cacheMaximumNegativeRecordTtl === null) || (cacheMaximumNegativeRecordTtl === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte die maximale negative TTL für den Cache eingeben."));
        $("#txtCacheMaximumNegativeRecordTtl").trigger("focus");
        return;
    }

    var cacheFailureRecordTtl = $("#txtCacheFailureRecordTtl").val();
    if ((cacheFailureRecordTtl === null) || (cacheFailureRecordTtl === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte die Fehler-TTL eingeben."));
        $("#txtCacheFailureRecordTtl").trigger("focus");
        return;
    }

    var cachePrefetchEligibility = $("#txtCachePrefetchEligibility").val();
    if ((cachePrefetchEligibility === null) || (cachePrefetchEligibility === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte die Mindest-TTL für Prefetch eingeben."));
        $("#txtCachePrefetchEligibility").trigger("focus");
        return;
    }

    var cachePrefetchTrigger = $("#txtCachePrefetchTrigger").val();
    if ((cachePrefetchTrigger === null) || (cachePrefetchTrigger === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte den Prefetch-Auslöser eingeben."));
        $("#txtCachePrefetchTrigger").trigger("focus");
        return;
    }

    formData += "&saveCache=" + saveCache + "&serveStale=" + serveStale + "&serveStaleTtl=" + serveStaleTtl + "&serveStaleAnswerTtl=" + serveStaleAnswerTtl + "&serveStaleResetTtl=" + serveStaleResetTtl + "&serveStaleMaxWaitTime=" + serveStaleMaxWaitTime + "&enableCache=" + $("#chkEnableCache").prop("checked") + "&cacheMaximumEntries=" + cacheMaximumEntries + "&cacheMaximumMemory=" + encodeURIComponent($("#txtCacheMaximumMemory").val() || "0") + "&cacheMinimumRecordTtl=" + cacheMinimumRecordTtl + "&cacheMaximumRecordTtl=" + cacheMaximumRecordTtl  + "&cacheNegativeRecordTtl=" + cacheNegativeRecordTtl + "&cacheMaximumNegativeRecordTtl=" + cacheMaximumNegativeRecordTtl + "&cacheFailureRecordTtl=" + cacheFailureRecordTtl + "&cachePrefetchEligibility=" + cachePrefetchEligibility + "&cachePrefetchTrigger=" + cachePrefetchTrigger + "&cachePrefetchTriggerPercent=" + encodeURIComponent($("#txtCachePrefetchTriggerPercent").val());

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

    formData += "&enableBlocking=" + enableBlocking + "&allowTxtBlockingReport=" + allowTxtBlockingReport + "&blockingBypassList=" + encodeURIComponent(blockingBypassList) + "&blockingType=" + blockingType + "&customBlockingAddresses=" + encodeURIComponent(customBlockingAddresses) + "&blockingAnswerTtl=" + blockingAnswerTtl + "&blockingNegativeTtl=" + blockingNegativeTtl  + "&blockingReportText=" + encodeURIComponent(blockingReportText) + "&blockFirefoxCanaryDomain=" + $("#chkBlockFirefoxCanaryDomain").prop("checked") + "&forceChromePreflight=" + $("#chkForceChromePreflight").prop("checked") + "&enableLiveMonitoring=" + $("#chkEnableLiveMonitoring").prop("checked") + "&enableWatchdog=" + $("#chkEnableWatchdog").prop("checked") + "&rootZoneMode=" + $("input[name=rdRootZoneMode]:checked").val() + "&arpaZoneMode=" + $("input[name=rdArpaZoneMode]:checked").val() + "&trustAnchorMode=" + $("input[name=rdTrustAnchorMode]:checked").val() + "&blockListUrls=" + encodeURIComponent(blockListUrls) + "&blockListUpdateIntervalHours=" + blockListUpdateIntervalHours;

    var proxy;

    var proxyType = $("input[name=rdProxyType]:checked").val().toLowerCase();
    if (proxyType === "none") {
        proxy = "&proxyType=" + proxyType;
    }
    else {
        var proxyAddress = $("#txtProxyAddress").val();

        if ((proxyAddress === null) || (proxyAddress === "")) {
            showAlert("warning", tr("Angabe fehlt"), tr("Bitte die Proxy-Adresse eingeben."));
            $("#txtProxyAddress").trigger("focus");
            return;
        }

        var proxyPort = $("#txtProxyPort").val();

        if ((proxyPort === null) || (proxyPort === "")) {
            showAlert("warning", tr("Angabe fehlt"), tr("Bitte den Proxy-Port eingeben."));
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
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte die Wiederholungen je Forwarder eingeben."));
        $("#txtForwarderRetries").trigger("focus");
        return;
    }

    var forwarderTimeout = $("#txtForwarderTimeout").val();
    if ((forwarderTimeout == null) || (forwarderTimeout === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte das Zeitlimit je Forwarder eingeben."));
        $("#txtForwarderTimeout").trigger("focus");
        return;
    }

    var forwarderConcurrency = $("#txtForwarderConcurrency").val();
    if ((forwarderConcurrency == null) || (forwarderConcurrency === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte die Zahl gleichzeitiger Forwarder eingeben."));
        $("#txtForwarderConcurrency").trigger("focus");
        return;
    }

    formData += proxy + "&httpUserAgent=" + encodeURIComponent($("#txtHttpUserAgent").val().trim()) + "&forwarders=" + encodeURIComponent(forwarders) + "&forwarderProtocol=" + forwarderProtocol + "&concurrentForwarding=" + concurrentForwarding + "&forwarderRetries=" + forwarderRetries + "&forwarderTimeout=" + forwarderTimeout + "&forwarderConcurrency=" + forwarderConcurrency;

    var loggingType = $("input[name=rdLoggingType]:checked").val();
    var ignoreResolverLogs = $("#chkIgnoreResolverLogs").prop("checked");
    var noStackTrace = $("#chkNoStackTrace").prop("checked");
    var hideClientAddresses = $("#chkHideClientAddresses").prop("checked");
    var logQueries = $("#chkLogQueries").prop("checked");
    var useLocalTime = $("#chkUseLocalTime").prop("checked");
    var logFolder = $("#txtLogFolderPath").val();
    var maxLogFileDays = $("#txtMaxLogFileDays").val();

    var enableInMemoryStats = $("#chkEnableInMemoryStats").prop("checked");
    var maxStatFileDays = $("#txtMaxStatFileDays").val();

    formData += "&loggingType=" + loggingType + "&ignoreResolverLogs=" + ignoreResolverLogs + "&noStackTrace=" + noStackTrace + "&hideClientAddresses=" + hideClientAddresses + "&logQueries=" + logQueries + "&useLocalTime=" + useLocalTime + "&logFolder=" + encodeURIComponent(logFolder) + "&maxLogFileDays=" + maxLogFileDays + "&enableInMemoryStats=" + enableInMemoryStats + "&maxStatFileDays=" + maxStatFileDays;

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
            showAlert("success", tr("Gespeichert"), tr("Die Einstellungen wurden übernommen."));
            relockSettings();

            var redirecting = false;

            if (sessionData.info.dnsServerDomain == responseJSON.server)
                redirecting = checkForWebConsoleRedirection(responseJSON);

            if (!redirecting && (responseJSON.response.language !== zdnsI18n.language)) {
                setTimeout(function () {
                    window.location.reload();
                }, 800);
            }
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

function isIntegerInRange(value, min, max) {
    if ((value == null) || !/^[0-9]+$/.test(String(value).trim()))
        return false;

    var number = parseInt(value, 10);

    return (number >= min) && (number <= max);
}

function validateQpsPrefixLimits(table, maxPrefix) {
    var rows = table.find("tr");
    var prefixes = {};

    for (var i = 0; i < rows.length; i++) {
        var inputs = $(rows[i]).find("input");
        var prefix = $(inputs[0]);

        if (!isIntegerInRange(prefix.val(), 0, maxPrefix)) {
            showAlert("warning", tr("Ungültige Angabe"), tr("Die Präfixlänge muss zwischen 0 und {0} liegen.", maxPrefix));
            prefix.trigger("focus");
            return false;
        }

        if (prefixes[prefix.val().trim()]) {
            showAlert("warning", tr("Doppelter Eintrag"), tr("Das Präfix /{0} ist mehrfach eingetragen.", prefix.val().trim()));
            prefix.trigger("focus");
            return false;
        }

        prefixes[prefix.val().trim()] = true;

        for (var j = 1; j < 3; j++) {
            var limit = $(inputs[j]);

            if (!isIntegerInRange(limit.val(), 0, 1000000)) {
                showAlert("warning", tr("Ungültige Angabe"), tr("Das Limit muss zwischen 0 und 1.000.000 Anfragen pro Sekunde liegen, 0 bedeutet unbegrenzt."));
                limit.trigger("focus");
                return false;
            }
        }
    }

    return true;
}

function setRecommendedQpsPrefixLimits() {
    $("#tableQpsPrefixLimitsIPv4").html("");
    addQpsPrefixLimitsIPv4Row(32, 1000, 5000);

    $("#tableQpsPrefixLimitsIPv6").html("");
    addQpsPrefixLimitsIPv6Row(64, 1000, 5000);
    addQpsPrefixLimitsIPv6Row(48, 10000, 50000);

    $("#txtRateLimitBurstSeconds").val(5);
    $("#txtRateLimitUdpTruncation").val(100);
}

function addQpsPrefixLimitsIPv4Row(prefix, udpLimit, tcpLimit) {
    var id = Math.floor(Math.random() * 10000);

    var tableHtmlRows = "<tr id=\"tableQpsPrefixLimitsIPv4Row" + id + "\"><td><input type=\"number\" class=\"form-control\" min=\"0\" max=\"32\" step=\"1\" placeholder=\"32\" value=\"" + htmlEncode(prefix) + "\"></td>";
    tableHtmlRows += "<td><input type=\"number\" class=\"form-control\" min=\"0\" max=\"1000000\" step=\"1\" placeholder=\"" + tr("0 = unbegrenzt") + "\" value=\"" + htmlEncode(udpLimit) + "\"></td>";
    tableHtmlRows += "<td><input type=\"number\" class=\"form-control\" min=\"0\" max=\"1000000\" step=\"1\" placeholder=\"" + tr("0 = unbegrenzt") + "\" value=\"" + htmlEncode(tcpLimit) + "\"></td>";

    tableHtmlRows += "<td><button type=\"button\" class=\"btn btn-danger\" onclick=\"$('#tableQpsPrefixLimitsIPv4Row" + id + "').remove();\">" + tr("Löschen") + "</button></td></tr>";

    $("#tableQpsPrefixLimitsIPv4").append(tableHtmlRows);
}

function addQpsPrefixLimitsIPv6Row(prefix, udpLimit, tcpLimit) {
    var id = Math.floor(Math.random() * 10000);

    var tableHtmlRows = "<tr id=\"tableQpsPrefixLimitsIPv6Row" + id + "\"><td><input type=\"number\" class=\"form-control\" min=\"0\" max=\"128\" step=\"1\" placeholder=\"64\" value=\"" + htmlEncode(prefix) + "\"></td>";
    tableHtmlRows += "<td><input type=\"number\" class=\"form-control\" min=\"0\" max=\"1000000\" step=\"1\" placeholder=\"" + tr("0 = unbegrenzt") + "\" value=\"" + htmlEncode(udpLimit) + "\"></td>";
    tableHtmlRows += "<td><input type=\"number\" class=\"form-control\" min=\"0\" max=\"1000000\" step=\"1\" placeholder=\"" + tr("0 = unbegrenzt") + "\" value=\"" + htmlEncode(tcpLimit) + "\"></td>";

    tableHtmlRows += "<td><button type=\"button\" class=\"btn btn-danger\" onclick=\"$('#tableQpsPrefixLimitsIPv6Row" + id + "').remove();\">" + tr("Löschen") + "</button></td></tr>";

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
        return false;

    if (location.protocol == "https:") {
        if (!responseJSON.response.webServiceEnableTls) {
            setTimeout(function () {
                window.open("http://" + window.location.hostname + ":" + responseJSON.response.webServiceHttpPort, "_self");
            }, 2500);

            return true;
        }

        var currentPort = window.location.port;

        if ((currentPort == 0) || (currentPort == ""))
            currentPort = 443;

        if (currentPort != responseJSON.response.webServiceTlsPort) {
            setTimeout(function () {
                window.open("https://" + window.location.hostname + ":" + responseJSON.response.webServiceTlsPort, "_self");
            }, 2500);

            return true;
        }
    }
    else {
        if (responseJSON.response.webServiceEnableTls && responseJSON.response.webServiceHttpToTlsRedirect) {
            setTimeout(function () {
                window.open("https://" + window.location.hostname + ":" + responseJSON.response.webServiceTlsPort, "_self");
            }, 2500);

            return true;
        }

        var currentPort = window.location.port;

        if ((currentPort == 0) || (currentPort == ""))
            currentPort = 80;

        if (currentPort != responseJSON.response.webServiceHttpPort) {
            setTimeout(function () {
                window.open("http://" + window.location.hostname + ":" + responseJSON.response.webServiceHttpPort, "_self");
            }, 2500);

            return true;
        }
    }

    return false;
}

function deriveBlockListName(url) {
    try {
        var parsed = new URL(url);
        var segments = parsed.pathname.split("/").filter(function (segment) { return segment !== ""; });
        var file = segments.length > 0 ? segments[segments.length - 1] : "";

        file = file.replace(/\.(txt|list|hosts|conf)$/i, "");

        if (parsed.protocol === "file:")
            return file !== "" ? file : parsed.pathname;

        return (file !== "") ? (file + " (" + parsed.hostname + ")") : parsed.hostname;
    }
    catch (e) {
        return url;
    }
}

function formatBlockListTime(value) {
    if (value == null)
        return "–";

    return moment(value).local().format(tr("DD.MM.YYYY HH:mm"));
}

function formatBlockListSize(bytes) {
    if ((bytes == null) || (bytes < 0))
        return "";

    if (bytes >= 1048576)
        return (bytes / 1048576).toFixed(1) + " MB";

    if (bytes >= 1024)
        return Math.round(bytes / 1024) + " KB";

    return bytes + " B";
}

function getBlockListStatusBadge(item) {
    if (item.loadError != null)
        return "<span class=\"label label-warning\" title=\"" + htmlEncode(item.loadError) + "\">" + tr("Lesefehler") + "</span>";

    switch (item.lastResult) {
        case "updated":
            return "<span class=\"label label-success\">" + tr("Aktualisiert") + "</span>";

        case "notModified":
            return "<span class=\"label label-success\">" + tr("Unverändert") + "</span>";

        case "notFound":
            return "<span class=\"label label-danger\" title=\"" + htmlEncode(item.lastError || "") + "\">" + tr("Nicht gefunden") + "</span>";

        case "failed":
            return "<span class=\"label label-danger\" title=\"" + htmlEncode(item.lastError || "") + "\">" + tr("Fehler") + "</span>";

        default:
            return "<span class=\"label label-default\">" + tr("Noch nicht geprüft") + "</span>";
    }
}

function refreshBlockListStatus() {
    var div = $("#divBlockListStatus");

    HTTPRequest({
        url: "api/settings/blockLists/status",
        token: sessionData.token,
        success: function (responseJSON) {
            var lists = responseJSON.response.lists;

            if ((lists == null) || (lists.length === 0)) {
                div.html("<span class=\"text-muted\">" + tr("Keine Listen eingetragen.") + "</span>");
                return;
            }

            var html = "<table class=\"table table-condensed blocklist-status-table\"><thead><tr><th>" + tr("Aktiv") + "</th><th>" + tr("Liste") + "</th><th>" + tr("Domains") + "</th><th>" + tr("Geprüft") + "</th><th>" + tr("Geändert") + "</th><th>" + tr("Status") + "</th><th></th></tr></thead><tbody>";

            for (var i = 0; i < lists.length; i++) {
                var item = lists[i];
                var url = htmlEncode(item.url);
                var domains = (item.domains != null) ? item.domains.toLocaleString(zdnsI18n.locale) : "–";

                if ((item.exceptions != null) && (item.exceptions > 0))
                    domains += "<br><small class=\"text-muted\">" + htmlEncode(tr("{0} Ausnahmen", item.exceptions.toLocaleString(zdnsI18n.locale))) + "</small>";

                if ((item.regexes != null) && (item.regexes > 0))
                    domains += "<br><small class=\"text-muted\">" + htmlEncode(tr("{0} Muster", item.regexes.toLocaleString(zdnsI18n.locale))) + "</small>";

                if ((item.ips != null) && (item.ips > 0))
                    domains += "<br><small class=\"text-muted\">" + htmlEncode(tr("{0} IP-Einträge", item.ips.toLocaleString(zdnsI18n.locale))) + "</small>";

                if ((item.skipped != null) && (item.skipped > 0))
                    domains += "<br><small class=\"text-muted\" title=\"" + htmlEncode(tr("Regeln für Browser-Filter wie Element-Ausblendung oder unbekannte Modifikatoren wirken nicht auf DNS und werden übersprungen.")) + "\">" + htmlEncode(tr("{0} übersprungen", item.skipped.toLocaleString(zdnsI18n.locale))) + "</small>";

                var errorLine = "";
                if ((item.lastError != null) && ((item.lastResult === "failed") || (item.lastResult === "notFound")))
                    errorLine = "<div class=\"blocklist-error\">" + htmlEncode(item.lastError) + "</div>";
                else if (item.loadError != null)
                    errorLine = "<div class=\"blocklist-error\">" + htmlEncode(item.loadError) + "</div>";

                var isGlobal = (item.global !== false);
                var profileLabels = "";

                if ((item.profiles != null) && (item.profiles.length > 0)) {
                    for (var k = 0; k < item.profiles.length; k++)
                        profileLabels += "<span class=\"label label-default\" title=\"" + htmlEncode(tr("Clientprofil")) + "\">" + htmlEncode(item.profiles[k]) + "</span> ";
                }

                html += "<tr" + (item.enabled ? "" : " class=\"blocklist-disabled\"") + ">" +
                    "<td><input type=\"checkbox\" class=\"blocklist-enabled\" data-url=\"" + url + "\"" + (item.enabled ? " checked" : "") + (isGlobal ? "" : " disabled title=\"" + htmlEncode(tr("Nur in Clientprofilen eingetragen, dort bearbeiten.")) + "\"") + " aria-label=\"" + htmlEncode(tr("Aktiv")) + "\"></td>" +
                    "<td class=\"blocklist-name-cell\"><input type=\"text\" class=\"form-control input-sm blocklist-name\" data-url=\"" + url + "\" maxlength=\"60\" value=\"" + htmlEncode(item.name || "") + "\" placeholder=\"" + htmlEncode(deriveBlockListName(item.url)) + "\" aria-label=\"" + htmlEncode(tr("Name")) + "\">" +
                    "<div class=\"blocklist-url\">" + (isGlobal ? "" : "<span class=\"label label-warning\">" + tr("Nur Profile") + "</span> ") + profileLabels + (item.allowList ? "<span class=\"label label-info\">" + tr("Erlaubnisliste") + "</span> " : "") + "<a href=\"" + url + "\" target=\"_blank\" rel=\"noopener noreferrer\">" + url + "</a></div>" +
                    "<div class=\"blocklist-path\" title=\"" + htmlEncode(tr("Lokale Datei")) + "\">" + htmlEncode(item.localPath) + (item.fileSize != null ? " · " + formatBlockListSize(item.fileSize) : "") + "</div>" + errorLine + "</td>" +
                    "<td class=\"text-right\">" + domains + "</td>" +
                    "<td>" + formatBlockListTime(item.lastCheckedOn) + "</td>" +
                    "<td>" + formatBlockListTime(item.lastUpdatedOn || item.fileModifiedOn) + "</td>" +
                    "<td>" + getBlockListStatusBadge(item) + "</td>" +
                    "<td class=\"blocklist-actions\"><button type=\"button\" class=\"btn btn-default btn-xs blocklist-update\" data-url=\"" + url + "\" data-loading-text=\"" + htmlEncode(tr("Aktualisiere...")) + "\"" + (item.enabled ? "" : " disabled") + ">" + tr("Aktualisieren") + "</button>" + (isGlobal ? " <button type=\"button\" class=\"btn btn-default btn-xs blocklist-remove\" data-url=\"" + url + "\">" + tr("Entfernen") + "</button>" : "") + "</td>" +
                    "</tr>";
            }

            html += "</tbody></table>";
            div.html(html);

            div.find("input.blocklist-enabled").on("change", function () {
                blockListAction("api/settings/blockLists/setEnabled?url=" + encodeURIComponent($(this).attr("data-url")) + "&enabled=" + $(this).prop("checked"), null, true);
            });

            div.find("input.blocklist-name").on("change", function () {
                blockListAction("api/settings/blockLists/setName?url=" + encodeURIComponent($(this).attr("data-url")) + "&name=" + encodeURIComponent($(this).val().trim()), null, false);
            });

            div.find("button.blocklist-update").on("click", function () {
                blockListAction("api/settings/blockLists/update?url=" + encodeURIComponent($(this).attr("data-url")), $(this), false);
            });

            div.find("button.blocklist-remove").on("click", function () {
                if (!confirm(tr("Liste {0} entfernen?", $(this).attr("data-url"))))
                    return;

                blockListAction("api/settings/blockLists/remove?url=" + encodeURIComponent($(this).attr("data-url")), $(this), true);
            });
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function blockListAction(url, btn, reloadSettings) {
    if (btn != null)
        btn.button("loading");

    HTTPRequest({
        url: url,
        token: sessionData.token,
        success: function (responseJSON) {
            if (btn != null)
                btn.button("reset");

            if ((responseJSON.response != null) && (responseJSON.response.success === false))
                showAlert("warning", tr("Aktualisierung fehlgeschlagen"), tr("Die Liste konnte nicht abgerufen werden. Details stehen in der Tabelle und im Serverprotokoll."));

            if (reloadSettings)
                refreshDnsSettings();
            else
                refreshBlockListStatus();
        },
        error: function () {
            if (btn != null)
                btn.button("reset");

            refreshBlockListStatus();
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function forceUpdateBlockLists() {
    if (!confirm(tr("Blocklisten jetzt herunterladen und aktualisieren?")))
        return;

    var btn = $("#btnUpdateBlockListsNow");
    btn.button("loading");

    HTTPRequest({
        url: "api/settings/forceUpdateBlockLists",
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");

            $("#lblBlockListNextUpdatedOn").text(tr("wird gerade aktualisiert"));

            showAlert("success", tr("Blocklisten werden aktualisiert"), tr("Die Aktualisierung der Blocklisten wurde gestartet."));
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
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte angeben, wie viele Minuten die Blockierung pausieren soll."));
        $("#txtTemporaryDisableBlockingMinutes").trigger("focus");
        return;
    }

    if (!confirm(tr("Blockierung für {0} Minute(n) pausieren?", minutes)))
        return;

    var btn = $("#btnTemporaryDisableBlockingNow");
    btn.button("loading");

    HTTPRequest({
        url: "api/settings/temporaryDisableBlocking?minutes=" + minutes,
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");

            $("#chkEnableBlocking").prop("checked", false);
            $("#lblTemporaryDisableBlockingTill").text(moment(responseJSON.response.temporaryDisableBlockingTill).local().format(tr("DD.MM.YYYY HH:mm:ss")));
            updateBlockingState();

            showAlert("success", tr("Blockierung aus"), tr("Die Blockierung ist pausiert für {0} Minute(n).", minutes));

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
            showAlert("success", tr("Aktualisierung gestartet"), tr("Die Client-Sperrlisten werden im Hintergrund heruntergeladen und neu geladen."));
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
    if (!confirm(tr("Blockierung aktivieren?")))
        return;

    HTTPRequest({
        url: "api/settings/set?enableBlocking=true",
        token: sessionData.token,
        success: function (responseJSON) {
            showAlert("success", tr("Blockierung aktiv"), tr("Die Blockierung ist aktiviert."));
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function disableBlocking() {
    if (!confirm(tr("Blockierung deaktivieren?")))
        return;

    HTTPRequest({
        url: "api/settings/set?enableBlocking=false",
        token: sessionData.token,
        success: function (responseJSON) {
            showAlert("success", tr("Blockierung aus"), tr("Die Blockierung ist deaktiviert."));
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function temporaryDisableBlockingForMenu(minutes) {
    if (!confirm(tr("Blockierung für {0} Minute(n) pausieren?", minutes)))
        return;

    HTTPRequest({
        url: "api/settings/temporaryDisableBlocking?minutes=" + minutes,
        token: sessionData.token,
        success: function (responseJSON) {
            showAlert("success", tr("Blockierung aus"), tr("Die Blockierung ist pausiert für {0} Minute(n).", minutes));
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
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte mindestens einen Bestandteil für die Sicherung auswählen."), divBackupSettingsAlert);
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
            showAlert("success", tr("Gesichert"), tr("Die Sicherung wurde erstellt."));
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
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte eine Sicherungsdatei (ZIP) auswählen."), divRestoreSettingsAlert);
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
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte mindestens einen Bestandteil zum Wiederherstellen auswählen."), divRestoreSettingsAlert);
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

            showAlert("success", tr("Wiederhergestellt"), tr("Die Sicherung wurde wiederhergestellt."));

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
            if ((currentTheme != null) && ((currentTheme.indexOf("custom:") === 0) || (currentTheme.indexOf("preset:") === 0)))
                return;

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
    changeTheme(currentTheme, false);
}

function changeTheme(newTheme, persist) {
    clearCustomThemeColors();

    if ((newTheme != null) && (newTheme.indexOf("custom:") === 0)) {
        if (applyCustomTheme(newTheme.substring(7))) {
            localStorage.setItem("theme", newTheme);
            updateDashboardChartTheme();

            if (persist !== false)
                saveActiveThemePreference(newTheme);

            return;
        }

        newTheme = "system";
    }

    if ((newTheme != null) && (newTheme.indexOf("preset:") === 0)) {
        if (applyThemePreset(newTheme.substring(7))) {
            localStorage.setItem("theme", newTheme);
            updateDashboardChartTheme();

            if (persist !== false)
                saveActiveThemePreference(newTheme);

            return;
        }

        newTheme = "system";
    }

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

    if (persist !== false)
        saveActiveThemePreference(newTheme == null ? "system" : newTheme);
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
            $("#rdChangeThemeSystem").prop("checked", (currentTheme == null) || ((currentTheme.indexOf("custom:") !== 0) && (currentTheme.indexOf("preset:") !== 0)));
            break;
    }

    $("#divCustomThemeEditor").hide();
    renderCustomThemeList();

    $("#modalChangeTheme").modal("show");
}

function updateDo53ModeState() {
    var do53Mode = $("input[name=rdDo53Mode]:checked").val();
    var ddrOnly = (do53Mode === "DdrOnlyDrop") || (do53Mode === "DdrOnlyRefused");

    if (ddrOnly)
        $("#chkEnableDdr").prop("checked", true);

    $("#chkEnableDdr").prop("disabled", ddrOnly);
}

var ianaDataEditorItem = null;

function formatIanaDate(value) {
    if (value == null)
        return null;

    return moment(value).local().format(tr("DD.MM.YYYY HH:mm"));
}

function renderIanaZoneStatus(target, status) {
    var div = $(target);
    var html;

    if (status.error != null) {
        html = "<span class=\"iana-state iana-state-error\">" + tr("Fehler") + "</span> " + htmlEncode(status.error);

        if (status.active)
            html += " " + tr("Die zuletzt geprüfte Version ist weiter aktiv.");
    }
    else if (status.mode === "Disabled") {
        html = "<span class=\"iana-state\">" + tr("Aus") + "</span>";
    }
    else if (status.active) {
        html = "<span class=\"iana-state iana-state-ok\">" + tr("Aktiv") + "</span> " + htmlEncode(tr("Seriennummer {0}, {1} Delegationen, Quelle {2}.", String(status.serial), formatNumber(status.delegations), status.source)) + " " + htmlEncode(status.message);

        if (status.validUntil != null)
            html += " " + tr("Signaturen gültig bis {0}.", formatIanaDate(status.validUntil));
    }
    else if (status.loadedOn == null) {
        html = "<span class=\"iana-state\">" + tr("Wird geladen") + "</span> " + tr("Die Zone wird kurz nach dem Start geladen und geprüft.");
    }
    else {
        html = "<span class=\"iana-state iana-state-warning\">" + tr("Nicht aktiv") + "</span> " + htmlEncode(status.message == null ? "" : status.message);
    }

    if (status.lastCheck != null)
        html += " <span class=\"iana-checked\">" + tr("Zuletzt geprüft {0}.", formatIanaDate(status.lastCheck)) + "</span>";

    div.html(html);
}

function renderIanaData(ianaData) {
    if (ianaData == null)
        return;

    $("input[name=rdRootZoneMode]").filter(function () { return this.value === ianaData.rootZone.mode; }).prop("checked", true);
    $("input[name=rdArpaZoneMode]").filter(function () { return this.value === ianaData.arpaZone.mode; }).prop("checked", true);
    $("input[name=rdTrustAnchorMode]").filter(function () { return this.value === ianaData.trustAnchors.mode; }).prop("checked", true);

    $("input[name=rdRootZoneMode][value=Custom]").prop("disabled", !ianaData.rootZone.hasCustom);
    $("input[name=rdArpaZoneMode][value=Custom]").prop("disabled", !ianaData.arpaZone.hasCustom);
    $("input[name=rdTrustAnchorMode][value=Custom]").prop("disabled", !ianaData.trustAnchors.hasCustom);

    renderIanaZoneStatus("#divIanaStatusRootZone", ianaData.rootZone);
    renderIanaZoneStatus("#divIanaStatusArpaZone", ianaData.arpaZone);

    var anchors = ianaData.trustAnchors;
    var html;

    if (anchors.error != null)
        html = "<span class=\"iana-state iana-state-error\">" + tr("Fehler") + "</span> " + htmlEncode(anchors.error);
    else if (anchors.source == null)
        html = "<span class=\"iana-state\">" + tr("Wird geladen") + "</span>";
    else
        html = "<span class=\"iana-state iana-state-ok\">" + tr("Aktiv") + "</span> " + htmlEncode(tr("Quelle {0}.", anchors.source)) + " " + htmlEncode(anchors.message);

    html += " " + htmlEncode(tr("Schlüssel: {0}.", anchors.keyTags.join(", ")));

    if (anchors.lastCheck != null)
        html += " <span class=\"iana-checked\">" + tr("Zuletzt geprüft {0}.", formatIanaDate(anchors.lastCheck)) + "</span>";

    $("#divIanaStatusTrustAnchors").html(html);
}

function updateIanaData(objBtn) {
    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/settings/iana/update",
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");
            renderIanaData(responseJSON.response.ianaData);
            showAlert("success", tr("Geprüft"), tr("Root-Zone, arpa-Zone und Vertrauensanker wurden geprüft und, falls nötig, aktualisiert."));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function showIanaDataEditor(objBtn, item) {
    var btn = $(objBtn);
    btn.button("loading");

    var titles = { RootZone: tr("Eigene Root-Zone"), ArpaZone: tr("Eigene arpa-Zone"), TrustAnchors: tr("Eigene Vertrauensanker (Root-KSK)") };
    var hints = {
        RootZone: tr("Zonendatei im Standardformat. Vorbelegt ist die aktuell verwendete Version. Nach dem Speichern wird sie geprüft und sofort verwendet; ist sie nicht gültig signiert, gelten ihre Top-Level-Domains als unsigniert, was mit eingeschalteter DNSSEC-Validierung zu Fehlern führen kann."),
        ArpaZone: tr("Zonendatei der arpa-Zone im Standardformat. Nach dem Speichern wird sie geprüft und sofort verwendet."),
        TrustAnchors: tr("Ein DS-Eintrag pro Zeile für die Root-Zone, zum Beispiel: . IN DS 20326 8 2 E06D44B8… Nach dem Speichern werden ausschließlich diese Anker für die DNSSEC-Validierung verwendet.")
    };

    HTTPRequest({
        url: "api/settings/iana/get?item=" + encodeURIComponent(item),
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");

            ianaDataEditorItem = item;
            $("#divIanaDataAlert").html("");
            $("#lblIanaDataTitle").text(titles[item]);
            $("#lblIanaDataHint").text(hints[item]);
            $("#txtIanaData").val(responseJSON.response.content);
            $("#btnIanaDataSave").button("reset");
            $("#modalIanaData").modal("show");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function saveIanaData() {
    var divIanaDataAlert = $("#divIanaDataAlert");
    var content = $("#txtIanaData").val();

    if (content.trim().length === 0) {
        showAlert("warning", tr("Angabe fehlt"), tr("Der Inhalt darf nicht leer sein."), divIanaDataAlert);
        return;
    }

    var btn = $("#btnIanaDataSave");
    btn.button("loading");

    HTTPRequest({
        url: "api/settings/iana/set",
        token: sessionData.token,
        method: "POST",
        data: "item=" + encodeURIComponent(ianaDataEditorItem) + "&content=" + encodeURIComponent(content),
        processData: false,
        success: function (responseJSON) {
            $("#modalIanaData").modal("hide");
            renderIanaData(responseJSON.response.ianaData);
            showAlert("success", tr("Gespeichert"), tr("Die eigene Version wurde gespeichert und wird jetzt verwendet."));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalIanaData").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divIanaDataAlert
    });
}

