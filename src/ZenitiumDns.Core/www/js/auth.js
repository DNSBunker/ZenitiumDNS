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

var sessionData = null;
var localGroups = null;
var otpTimerHandle = null;

$(function () {
    var hash = window.location.hash;
    if (hash.length > 0)
        hash = "?" + hash.substr(1);

    var urlParams = new URLSearchParams(hash);
    window.history.replaceState(null, '', window.location.protocol + "//" + window.location.host + window.location.pathname);

    var errorMessage = urlParams.get("error");
    if (errorMessage != null) {
        showPageLogin();
        showAlert("danger", tr("Fehler"), errorMessage);
    }
    else {
        var token = getCookie("token");
        if (token != null)
            setCookie("token", "", 0);
        else
            token = localStorage.getItem("token");

        if (token == null) {
            showPageLogin(true);
        }
        else {
            HTTPRequest({
                url: "api/user/session/get",
                token: token,
                success: function (responseJSON) {
                    applySessionData(responseJSON);
                    $("#chkDnssecValidation").prop("checked", sessionData.info.dnssecValidation);

                    showPageMain();

                    if (consumeChangePasswordPrompt() && !languageChooserVisible)
                        showChangePasswordModal("admin");
                },
                error: function () {
                    showPageLogin(true);
                }
            });
        }
    }

    $("#txt2FATOTP").on("input", function () {
        var totp = $("#txt2FATOTP").val();
        if (totp.length == 6)
            login();
    });

    $("#optGroupDetailsUserList").on("change", function () {
        var selectedUser = $("#optGroupDetailsUserList").val();

        switch (selectedUser) {
            case "blank":
                break;

            case "none":
                $("#txtGroupDetailsMembers").val("");
                break;

            default:
                var existingUsers = $("#txtGroupDetailsMembers").val();
                var existingUsersArray = existingUsers.split("\n");
                var found = false;

                for (var i = 0; i < existingUsersArray.length; i++) {
                    if (existingUsersArray[i] === selectedUser) {
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    if ((existingUsers.length > 0) && !existingUsers.endsWith("\n"))
                        existingUsers += "\n";

                    existingUsers += selectedUser + "\n";
                    $("#txtGroupDetailsMembers").val(existingUsers);
                }
                break;
        }
    });

    $("#optUserDetailsGroupList").on("change", function () {
        var selectedGroup = $("#optUserDetailsGroupList").val();

        switch (selectedGroup) {
            case "blank":
                break;

            case "none":
                $("#txtUserDetailsMemberOf").val("");
                break;

            default:
                var existingGroups = $("#txtUserDetailsMemberOf").val();
                var existingGroupsArray = existingGroups.split("\n");
                var found = false;

                for (var i = 0; i < existingGroupsArray.length; i++) {
                    if (existingGroupsArray[i] === selectedGroup) {
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    if ((existingGroups.length > 0) && !existingGroups.endsWith("\n"))
                        existingGroups += "\n";

                    existingGroups += selectedGroup + "\n";
                    $("#txtUserDetailsMemberOf").val(existingGroups);
                }
                break;
        }
    });

    $("#optEditPermissionsUserList").on("change", function () {
        var selectedUser = $("#optEditPermissionsUserList").val();

        switch (selectedUser) {
            case "blank":
                break;

            case "none":
                $("#tbodyEditPermissionsUser").html("");
                break;

            default:
                var data = serializeTableData($("#tableEditPermissionsUser"), 4);
                var parts = data.split("|");
                var found = false;

                for (var i = 0; i < parts.length; i += 4) {
                    if (parts[i] === selectedUser) {
                        found = true;
                        break;
                    }
                }

                if (!found)
                    addEditPermissionUserRow(null, selectedUser, false, false, false);

                break;
        }
    });

    $("#optEditPermissionsGroupList").on("change", function () {
        var selectedGroup = $("#optEditPermissionsGroupList").val();

        switch (selectedGroup) {
            case "blank":
                break;

            case "none":
                $("#tbodyEditPermissionsGroup").html("");
                break;

            default:
                var data = serializeTableData($("#tableEditPermissionsGroup"), 4);
                var parts = data.split("|");
                var found = false;

                for (var i = 0; i < parts.length; i += 4) {
                    if (parts[i] === selectedGroup) {
                        found = true;
                        break;
                    }
                }

                if (!found)
                    addEditPermissionGroupRow(null, selectedGroup, false, false, false);

                break;
        }
    });

    $("#chkAdminSsoAllowSignup").on("click", function () {
        var ssoAllowSignup = $("#chkAdminSsoAllowSignup").prop("checked");

        $("#chkAdminSsoAllowSignupOnlyForMappedUsers").prop("disabled", !ssoAllowSignup);
    });

    $("input[type=radio][name=rdLdapSslOption]").on("change", function () {
        var rdLdapSslOption = $("input[name=rdLdapSslOption]:checked").val();

        $("#chkAdminLdapIgnoreSslErrors").prop("disabled", rdLdapSslOption == "None");
    });

    $("#chkAdminLdapAllowSignup").on("click", function () {
        var ldapAllowSignup = $("#chkAdminLdapAllowSignup").prop("checked");

        $("#chkAdminLdapAllowSignupOnlyForMappedUsers").prop("disabled", !ldapAllowSignup);
    });
});

function applySessionData(responseJSON) {
    sessionData = responseJSON;
    localStorage.setItem("token", sessionData.token);

    setUserDisplayName(sessionData.displayName);
    document.title = sessionData.info.dnsServerDomain + " – ZenitiumDNS";
    setAboutVersionInfo(sessionData.info);
    $("#lblDnsServerDomain").text(sessionData.info.dnsServerDomain);
}

function setUserDisplayName(displayName) {
    $("#mnuUserDisplayName").text(displayName);

    var initials = "";
    var parts = (displayName || "").trim().split(/\s+/);

    for (var i = 0; (i < parts.length) && (initials.length < 2); i++) {
        if (parts[i].length > 0)
            initials += parts[i].charAt(0).toUpperCase();
    }

    $("#lblUserInitials").text(initials);
}

function login(username, password) {
    if (otpTimerHandle != null)
        clearTimeout(otpTimerHandle);

    const OTP_TIMEOUT_INTERVAL = 30000;

    var autoLogin = false;

    if (username == null) {
        username = $("#txtUser").val().toLowerCase();
        password = $("#txtPass").val();
    }
    else {
        autoLogin = true;
    }

    if ((username === null) || (username === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte den Benutzernamen eingeben."));
        $("#txtUser").trigger("focus");
        return;
    }

    if ((password === null) || (password === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte das Passwort eingeben."));
        $("#txtPass").trigger("focus");
        return;
    }

    var totp = $("#txt2FATOTP").val();

    if ($("#div2FAOTP").is(":visible")) {
        if ((totp == null) || (totp.length != 6)) {
            showAlert("warning", tr("Angabe fehlt"), tr("Bitte den 6-stelligen Code aus der Authenticator-App eingeben."));
            $("#txt2FATOTP").trigger("focus");
            otpTimerHandle = setTimeout(showPageLogin, OTP_TIMEOUT_INTERVAL);
            return;
        }
    }

    var btn = $("#btnLogin").button("loading");

    HTTPRequest({
        url: "api/user/login",
        method: "POST",
        data: "user=" + encodeURIComponent(username) + "&pass=" + encodeURIComponent(password) + "&totp=" + encodeURIComponent(totp) + "&includeInfo=true",
        procecssData: false,
        success: function (responseJSON) {
            applySessionData(responseJSON);

            showPageMain();

            if (!sessionData.totpEnabled && (username === "admin") && (password === "admin")) {
                if (languageChooserVisible)
                    languageChooserPasswordPrompt = password;
                else
                    showChangePasswordModal(password);
            }
        },
        error: function () {
            btn.button("reset");

            if ($("#div2FAOTP").is(":visible")) {
                $("#txt2FATOTP").val("");
                $("#txt2FATOTP").trigger("focus");
                otpTimerHandle = setTimeout(showPageLogin, OTP_TIMEOUT_INTERVAL);
            }
            else {
                $("#txtUser").trigger("focus");
            }

            if (autoLogin)
                hideAlert();
        },
        twoFactorAuthRequired: function () {
            btn.button("reset");

            if (autoLogin) {
                $("#txtUser").trigger("focus");
            }
            else {
                $("#txtPass").prop("disabled", true);
                $("#div2FAOTP").show();
                $("#txt2FATOTP").trigger("focus");
                otpTimerHandle = setTimeout(showPageLogin, OTP_TIMEOUT_INTERVAL);
            }
        }
    });
}

function logout() {
    HTTPRequest({
        url: "api/user/logout",
        token: sessionData.token,
        success: function (responseJSON) {
            sessionData = null;
            showPageLogin();
        },
        error: function () {
            sessionData = null;
            showPageLogin();
        }
    });
}

function showChangePasswordModal(currentPassword) {
    $("#titleChangePassword").text(tr("Passwort ändern"));

    hideAlert($("#divChangePasswordAlert"));
    $("#txtChangePasswordUsername").val(sessionData.username);

    var txtChangePasswordCurrentPassword = $("#txtChangePasswordCurrentPassword");

    if (currentPassword == null) {
        txtChangePasswordCurrentPassword.val("");
        txtChangePasswordCurrentPassword.prop("disabled", false);
    }
    else {
        txtChangePasswordCurrentPassword.val(currentPassword);
        txtChangePasswordCurrentPassword.prop("disabled", true);
    }

    $("#divChangePasswordCurrentPassword").show();

    $("#txtChangePasswordNewPassword").val("");
    $("#txtChangePasswordConfirmPassword").val("");

    $("#txtChangePassword2FATOTP").val("");

    if (sessionData.totpEnabled)
        $("#divChangePassword2FATOTP").show();
    else
        $("#divChangePassword2FATOTP").hide();

    var btnChangePassword = $("#btnChangePassword");
    btnChangePassword.text(tr("Ändern"));
    btnChangePassword.attr("onclick", "changePassword(this); return false;");
    btnChangePassword.show();

    $("#modalChangePassword").modal("show");

    setTimeout(function () {
        if (currentPassword == null)
            $("#txtChangePasswordCurrentPassword").trigger("focus");
        else
            $("#txtChangePasswordNewPassword").trigger("focus");
    }, 1000);
}

function changePassword(objBtn) {
    var btn = $(objBtn);

    var divChangePasswordAlert = $("#divChangePasswordAlert");

    var password = $("#txtChangePasswordCurrentPassword").val();
    var newPassword = $("#txtChangePasswordNewPassword").val();
    var confirmPassword = $("#txtChangePasswordConfirmPassword").val();
    var totp = $("#txtChangePassword2FATOTP").val();

    if ((password === null) || (password === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte das aktuelle Passwort eingeben."), divChangePasswordAlert);
        $("#txtChangePasswordCurrentPassword").trigger("focus");
        return;
    }

    if ((newPassword === null) || (newPassword === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte das neue Passwort eingeben."), divChangePasswordAlert);
        $("#txtChangePasswordNewPassword").trigger("focus");
        return;
    }

    if ((confirmPassword === null) || (confirmPassword === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte das neue Passwort wiederholen."), divChangePasswordAlert);
        $("#txtChangePasswordConfirmPassword").trigger("focus");
        return;
    }

    if (newPassword !== confirmPassword) {
        showAlert("warning", tr("Keine Übereinstimmung"), tr("Die Passwörter stimmen nicht überein."), divChangePasswordAlert);
        $("#txtChangePasswordNewPassword").trigger("focus");
        return;
    }

    if (sessionData.totpEnabled) {
        if ((totp == null) || (totp.length != 6)) {
            showAlert("warning", tr("Angabe fehlt"), tr("Bitte den 6-stelligen Code aus der Authenticator-App eingeben."), divChangePasswordAlert);
            $("#txtChangePassword2FATOTP").trigger("focus");
            return;
        }
    }

    btn.button("loading");

    HTTPRequest({
        url: "api/user/changePassword",
        token: sessionData.token,
        method: "POST",
        data: "pass=" + encodeURIComponent(password) + "&newPass=" + encodeURIComponent(newPassword) + "&totp=" + encodeURIComponent(totp),
        processData: false,
        success: function (responseJSON) {
            $("#modalChangePassword").modal("hide");
            $("#txtChangePasswordCurrentPassword").val("");
            $("#txtChangePasswordNewPassword").val("");
            $("#txtChangePasswordConfirmPassword").val("");
            $("#txtChangePassword2FATOTP").val("");
            btn.button("reset");

            showAlert("success", tr("Passwort geändert"), tr("Das Passwort wurde geändert."));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalChangePassword").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divChangePasswordAlert
    });
}

function showConfigure2FAModal() {
    var divConfigure2FAAlert = $("#divConfigure2FAAlert");
    var divConfigure2FALoader = $("#divConfigure2FALoader");
    var divConfigure2FAViewer = $("#divConfigure2FAViewer");
    var btnEnable2FA = $("#btnEnable2FA");
    var btnDisable2FA = $("#btnDisable2FA");

    divConfigure2FALoader.show();
    divConfigure2FAViewer.hide();

    btnEnable2FA.hide();
    btnDisable2FA.hide();

    var modalConfigure2FA = $("#modalConfigure2FA");
    modalConfigure2FA.modal("show");

    HTTPRequest({
        url: "api/user/2fa/init",
        token: sessionData.token,
        success: function (responseJSON) {
            $("#txtConfigure2FAUsername").val(sessionData.username);
            $("#lblConfigure2FAStatus").text(responseJSON.response.totpEnabled ? tr("Aktiv") : tr("Inaktiv"));

            if (responseJSON.response.totpEnabled) {
                $("#divConfigure2FAInitialize").hide();

                divConfigure2FALoader.hide();
                divConfigure2FAViewer.show();

                btnDisable2FA.show();
            }
            else {
                var secret = "";

                for (var i = 0; i < responseJSON.response.secret.length; i++) {
                    if ((i > 0) && (i % 4) == 0)
                        secret += " ";

                    secret += responseJSON.response.secret.substring(i, i + 1);
                }

                $("#lblConfigure2FAQRCode").html("<img src=\"data:image/png;base64, " + responseJSON.response.qrCodePngImage + "\" />");
                $("#lblConfigure2FASecret").text(secret);
                $("#txtConfigure2FATOTP").val("");

                $("#divConfigure2FAInitialize").show();

                divConfigure2FALoader.hide();
                divConfigure2FAViewer.show();

                btnEnable2FA.show();

                setTimeout(function () {
                    $("#txtConfigure2FATOTP").trigger("focus");
                }, 1000);
            }
        },
        error: function () {
            divConfigure2FALoader.hide();
        },
        invalidToken: function () {
            modalConfigure2FA.modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divConfigure2FAAlert,
        objLoaderPlaceholder: divConfigure2FALoader
    });
}

function enable2FA(objBtn) {
    var btn = $(objBtn);

    var divConfigure2FAAlert = $("#divConfigure2FAAlert");
    var totp = $("#txtConfigure2FATOTP").val();

    if ((totp == null) || (totp.length != 6)) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte den 6-stelligen Code aus der Authenticator-App eingeben."), divConfigure2FAAlert);
        $("#txtConfigure2FATOTP").trigger("focus");
        return;
    }

    btn.button("loading");

    HTTPRequest({
        url: "api/user/2fa/enable",
        token: sessionData.token,
        method: "POST",
        data: "totp=" + encodeURIComponent(totp),
        processData: false,
        success: function (responseJSON) {
            sessionData.totpEnabled = true;

            $("#modalConfigure2FA").modal("hide");
            btn.button("reset");

            showAlert("success", tr("2FA aktiviert"), tr("Die Zwei-Faktor-Anmeldung ist aktiv."));
        },
        error: function () {
            btn.button("reset");
            $("#txtConfigure2FATOTP").val("");
            $("#txtConfigure2FATOTP").trigger("focus");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalConfigure2FA").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divConfigure2FAAlert
    });
}

function disable2FA(objBtn) {
    if (!confirm(tr("Zwei-Faktor-Anmeldung deaktivieren?")))
        return;

    var btn = $(objBtn);

    var divConfigure2FAAlert = $("#divConfigure2FAAlert");

    btn.button("loading");

    HTTPRequest({
        url: "api/user/2fa/disable",
        token: sessionData.token,
        success: function (responseJSON) {
            sessionData.totpEnabled = false;

            $("#modalConfigure2FA").modal("hide");
            btn.button("reset");

            showAlert("success", tr("2FA deaktiviert"), tr("Die Zwei-Faktor-Anmeldung ist deaktiviert."));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalConfigure2FA").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divConfigure2FAAlert
    });
}

function showMyProfileModal() {
    var divMyProfileAlert = $("#divMyProfileAlert");
    var divMyProfileLoader = $("#divMyProfileLoader");
    var divMyProfileViewer = $("#divMyProfileViewer");

    divMyProfileLoader.show();
    divMyProfileViewer.hide();

    var modalMyProfile = $("#modalMyProfile");
    modalMyProfile.modal("show");

    HTTPRequest({
        url: "api/user/profile/get",
        token: sessionData.token,
        success: function (responseJSON) {
            sessionData.displayName = responseJSON.response.displayName;
            sessionData.username = responseJSON.response.username;
            sessionData.totpEnabled = responseJSON.response.totpEnabled;

            setUserDisplayName(sessionData.displayName);

            $("#txtMyProfileDisplayName").val(responseJSON.response.displayName);
            $("#txtMyProfileUsername").val(responseJSON.response.username);

            switch (responseJSON.response.type) {
                case "RemoteSSO":
                    $("#txtMyProfileDisplayName").prop("disabled", true);
                    $("#lblMyProfileUserType").text("Remote/SSO");
                    $("#lblMyProfile2FAStatus").text(tr("über SSO verwaltet"));
                    break;

                case "RemoteLDAP":
                    $("#txtMyProfileDisplayName").prop("disabled", true);
                    $("#lblMyProfileUserType").text("Remote/LDAP");
                    $("#lblMyProfile2FAStatus").text(responseJSON.response.totpEnabled ? tr("Aktiv") : tr("Inaktiv"));
                    break;

                case "Local":
                default:
                    $("#txtMyProfileDisplayName").prop("disabled", false);
                    $("#lblMyProfileUserType").text(responseJSON.response.type);
                    $("#lblMyProfile2FAStatus").text(responseJSON.response.totpEnabled ? tr("Aktiv") : tr("Inaktiv"));
                    break;
            }

            $("#txtMyProfileSessionTimeout").val(responseJSON.response.sessionTimeoutSeconds);

            {
                var groupHtmlRows = "";

                for (var i = 0; i < responseJSON.response.memberOfGroups.length; i++) {
                    groupHtmlRows += "<tr><td>" + htmlEncode(responseJSON.response.memberOfGroups[i]) + "</td></tr>";
                }

                $("#tbodyMyProfileMemberOf").html(groupHtmlRows);
                $("#tfootMyProfileMemberOf").html(tr("Gruppen gesamt: {0}", responseJSON.response.memberOfGroups.length));
            }

            {
                var sessionHtmlRows = "";

                for (var i = 0; i < responseJSON.response.sessions.length; i++) {
                    var session;

                    if (responseJSON.response.sessions[i].tokenName == null)
                        session = htmlEncode("[" + responseJSON.response.sessions[i].partialToken + "]");
                    else
                        session = htmlEncode(responseJSON.response.sessions[i].tokenName) + "<br />[" + htmlEncode(responseJSON.response.sessions[i].partialToken) + "]";

                    if (responseJSON.response.sessions[i].isCurrentSession)
                        session += "<br />(" + tr("diese Sitzung") + ")";

                    switch (responseJSON.response.sessions[i].type) {
                        case "Standard":
                            session += "<br /><span class=\"label label-default\">Standard</span>";
                            break;

                        case "ApiToken":
                            session += "<br /><span class=\"label label-info\">" + tr("API Token") + "</span>";
                            break;

                        default:
                            session += "<br /><span class=\"label label-warning\">" + tr("Unbekannt") + "</span>";
                            break;
                    }

                    sessionHtmlRows += "<tr id=\"trMyProfileActiveSessions" + i + "\"><td style=\"min-width: 155px; word-wrap: anywhere;\">" + session + "</td><td>" +
                        htmlEncode(moment(responseJSON.response.sessions[i].lastSeen).local().format(tr("DD.MM.YYYY HH:mm:ss"))) + "<br /><span style=\"font-size: 12px\">" + htmlEncode("(" + moment(responseJSON.response.sessions[i].lastSeen).fromNow() + ")") + "</span></td><td>" +
                        htmlEncode(responseJSON.response.sessions[i].lastSeenRemoteAddress) + "</td><td style=\"word-wrap: anywhere;\">" +
                        htmlEncode(responseJSON.response.sessions[i].lastSeenUserAgent);

                    sessionHtmlRows += "</td><td align=\"right\"><div class=\"dropdown\"><a href=\"#\" id=\"btnMyProfileActiveSessionRowOption" + i + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
                    sessionHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" data-session-type=\"" + htmlEncode(responseJSON.response.sessions[i].type) + "\" data-partial-token=\"" + htmlEncode(responseJSON.response.sessions[i].partialToken) + "\" onclick=\"deleteMySession(this); return false;\">" + tr("Sitzung beenden") + "</a></li>";
                    sessionHtmlRows += "</ul></div></td></tr>";
                }

                $("#tbodyMyProfileActiveSessions").html(sessionHtmlRows);
                $("#tfootMyProfileActiveSessions").html(tr("Sitzungen gesamt: {0}", responseJSON.response.sessions.length));
            }

            divMyProfileLoader.hide();
            divMyProfileViewer.show();

            setTimeout(function () {
                $("#txtMyProfileDisplayName").trigger("focus");
            }, 1000);
        },
        error: function () {
            divMyProfileLoader.hide();
        },
        invalidToken: function () {
            modalMyProfile.modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divMyProfileAlert,
        objLoaderPlaceholder: divMyProfileLoader
    });
}

function saveMyProfile(objBtn) {
    var btn = $(objBtn);
    var divMyProfileAlert = $("#divMyProfileAlert");

    var sessionTimeoutSeconds = $("#txtMyProfileSessionTimeout").val();
    if (sessionTimeoutSeconds === "")
        sessionTimeoutSeconds = 1800;

    var params = "sessionTimeoutSeconds=" + encodeURIComponent(sessionTimeoutSeconds);

    if (!$("#txtMyProfileDisplayName").prop("disabled")) {
        var displayName = $("#txtMyProfileDisplayName").val();
        params += "&displayName=" + encodeURIComponent(displayName);
    }

    btn.button("loading");

    HTTPRequest({
        url: "api/user/profile/set?" + params,
        token: sessionData.token,
        success: function (responseJSON) {
            sessionData.displayName = responseJSON.response.displayName;
            setUserDisplayName(sessionData.displayName);

            btn.button("reset");
            $("#modalMyProfile").modal("hide");

            showAlert("success", tr("Profil gespeichert"), tr("Das Profil wurde gespeichert."));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalMyProfile").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divMyProfileAlert
    });
}

function deleteMySession(objMenuItem) {
    var divMyProfileAlert = $("#divMyProfileAlert");
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var sessionType = mnuItem.attr("data-session-type");
    var partialToken = mnuItem.attr("data-partial-token");

    if (!confirm(tr("Sitzung [{0}] beenden?", partialToken)))
        return;

    var apiUrl = "api/user/session/delete?partialToken=" + encodeURIComponent(partialToken);

    var btn = $("#btnMyProfileActiveSessionRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<span class='spinner spinner-sm' role='status' aria-label='" + tr("Wird geladen") + "'></span>");

    HTTPRequest({
        url: apiUrl,
        token: sessionData.token,
        success: function (responseJSON) {
            $("#trMyProfileActiveSessions" + id).remove();

            var totalSessions = $('#tableMyProfileActiveSessions >tbody >tr').length;
            $("#tfootMyProfileActiveSessions").html(tr("Sitzungen gesamt: {0}", totalSessions));

            showAlert("success", tr("Sitzung beendet"), tr("Die Sitzung wurde beendet."), divMyProfileAlert);
        },
        error: function () {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);
        },
        invalidToken: function () {
            $("#modalMyProfile").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divMyProfileAlert
    });
}

function refreshAdminTab() {
    if ($("#adminTabListSessions").hasClass("active"))
        refreshAdminSessions();
    else if ($("#adminTabListUsers").hasClass("active"))
        refreshAdminUsers();
    else if ($("#adminTabListGroups").hasClass("active"))
        refreshAdminGroups();
    else if ($("#adminTabListPermissions").hasClass("active"))
        refreshAdminPermissions();
    else if ($("#adminTabListSso").hasClass("active"))
        refreshAdminSsoConfig();
    else if ($("#adminTabListLdap").hasClass("active"))
        refreshAdminLdapConfig();
    else
        refreshAdminSessions();
}

function refreshAdminSessions() {
    var divAdminSessionsLoader = $("#divAdminSessionsLoader");
    var divAdminSessionsView = $("#divAdminSessionsView");

    divAdminSessionsLoader.show();
    divAdminSessionsView.hide();

    HTTPRequest({
        url: "api/admin/sessions/list",
        token: sessionData.token,
        success: function (responseJSON) {
            var tableHtmlRows = "";

            for (var i = 0; i < responseJSON.response.sessions.length; i++) {
                var session;

                if (responseJSON.response.sessions[i].tokenName == null)
                    session = "[" + htmlEncode(responseJSON.response.sessions[i].partialToken) + "]";
                else
                    session = htmlEncode(responseJSON.response.sessions[i].tokenName) + "<br />[" + htmlEncode(responseJSON.response.sessions[i].partialToken) + "]";

                if (responseJSON.response.sessions[i].isCurrentSession)
                    session += "<br />(" + tr("diese Sitzung") + ")";

                switch (responseJSON.response.sessions[i].type) {
                    case "Standard":
                        session += "<br /><span class=\"label label-default\">Standard</span>";
                        break;

                    case "ApiToken":
                        session += "<br /><span class=\"label label-info\">" + tr("API Token") + "</span>";
                        break;

                    default:
                        session += "<br /><span class=\"label label-warning\">" + tr("Unbekannt") + "</span>";
                        break;
                }

                tableHtmlRows += "<tr id=\"trAdminSessions" + i + "\"><td><a href=\"#\" data-username=\"" + htmlEncode(responseJSON.response.sessions[i].username) + "\" onclick=\"showUserDetailsModal(this); return false;\">" + htmlEncode(responseJSON.response.sessions[i].username) + "</a></td><td style=\"min-width: 155px; word-wrap: anywhere;\">" +
                    session + "</td><td>" +
                    htmlEncode(moment(responseJSON.response.sessions[i].lastSeen).local().format(tr("DD.MM.YYYY HH:mm:ss"))) + "<br /><span style=\"font-size: 12px\">" + htmlEncode("(" + moment(responseJSON.response.sessions[i].lastSeen).fromNow() + ")") + "</span></td><td>" +
                    htmlEncode(responseJSON.response.sessions[i].lastSeenRemoteAddress) + "</td><td style=\"word-wrap: anywhere;\">" +
                    htmlEncode(responseJSON.response.sessions[i].lastSeenUserAgent);

                tableHtmlRows += "</td><td align=\"right\"><div class=\"dropdown\"><a href=\"#\" id=\"btnAdminSessionRowOption" + i + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
                tableHtmlRows += "<li><a href=\"#\" data-username=\"" + htmlEncode(responseJSON.response.sessions[i].username) + "\" onclick=\"showUserDetailsModal(this); return false;\">" + tr("Benutzer anzeigen") + "</a></li>";
                tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" data-session-type=\"" + htmlEncode(responseJSON.response.sessions[i].type) + "\" data-partial-token=\"" + htmlEncode(responseJSON.response.sessions[i].partialToken) + "\" onclick=\"deleteAdminSession(this); return false;\">" + tr("Sitzung beenden") + "</a></li>";
                tableHtmlRows += "</ul></div></td></tr>";
            }

            $("#tbodyAdminSessions").html(tableHtmlRows);
            $("#tfootAdminSessions").html(tr("Sitzungen gesamt: {0}", responseJSON.response.sessions.length));

            divAdminSessionsLoader.hide();
            divAdminSessionsView.show();
        },
        error: function () {
            divAdminSessionsLoader.hide();
            divAdminSessionsView.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divAdminSessionsLoader
    });
}

function deleteAdminSession(objMenuItem) {
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var sessionType = mnuItem.attr("data-session-type");
    var partialToken = mnuItem.attr("data-partial-token");

    if (!confirm(tr("Sitzung [{0}] beenden?", partialToken)))
        return;

    var apiUrl = "api/admin/sessions/delete?partialToken=" + encodeURIComponent(partialToken);

    var btn = $("#btnAdminSessionRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<span class='spinner spinner-sm' role='status' aria-label='" + tr("Wird geladen") + "'></span>");

    HTTPRequest({
        url: apiUrl,
        token: sessionData.token,
        success: function (responseJSON) {
            $("#trAdminSessions" + id).remove();

            var totalSessions = $('#tableAdminSessions >tbody >tr').length;
            $("#tfootAdminSessions").html(tr("Sitzungen gesamt: {0}", totalSessions));

            showAlert("success", tr("Sitzung beendet"), tr("Die Sitzung wurde beendet."));
        },
        error: function () {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function refreshAdminUsers() {
    var divAdminUsersLoader = $("#divAdminUsersLoader");
    var divAdminUsersView = $("#divAdminUsersView");

    divAdminUsersLoader.show();
    divAdminUsersView.hide();

    HTTPRequest({
        url: "api/admin/users/list",
        token: sessionData.token,
        success: function (responseJSON) {
            var tableHtmlRows = "";

            for (var i = 0; i < responseJSON.response.users.length; i++) {
                tableHtmlRows += getAdminUsersRowHtml(i, responseJSON.response.users[i]);
            }

            $("#tbodyAdminUsers").html(tableHtmlRows);
            $("#tfootAdminUsers").html(tr("Benutzer gesamt: {0}", responseJSON.response.users.length));

            divAdminUsersLoader.hide();
            divAdminUsersView.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divAdminUsersLoader
    });
}

function getAdminUsersRowHtml(id, user) {
    var userType;
    var totpStatus;

    switch (user.type) {
        case "RemoteSSO":
            userType = "Remote/SSO";
            totpStatus = "<span class=\"label label-info\">" + tr("über SSO verwaltet") + "</span>"
            break;

        case "RemoteLDAP":
            userType = "Remote/LDAP";

            if (user.totpEnabled)
                totpStatus = "<span class=\"label label-success\">" + tr("Aktiv") + "</span>";
            else
                totpStatus = "<span class=\"label label-default\">" + tr("Deaktiviert") + "</span>";

            break;

        case "Local":
        default:
            userType = user.type;

            if (user.totpEnabled)
                totpStatus = "<span class=\"label label-success\">" + tr("Aktiv") + "</span>";
            else
                totpStatus = "<span class=\"label label-default\">" + tr("Deaktiviert") + "</span>";

            break;
    }

    var status;
    if (user.disabled)
        status = "<span class=\"label label-default\">" + tr("Deaktiviert") + "</span>";
    else
        status = "<span class=\"label label-success\">" + tr("Aktiv") + "</span>";

    var tableHtmlRows = "<tr id=\"trAdminUsers" + id + "\"><td style=\"word-wrap: anywhere;\"><a href=\"#\" data-id=\"" + id + "\" data-username=\"" + htmlEncode(user.username) + "\" onclick=\"showUserDetailsModal(this); return false;\">" + htmlEncode(user.username) + "</a></td><td style=\"word-wrap: anywhere;\">" +
        htmlEncode(user.displayName) + "</td><td>" +
        htmlEncode(userType) + "</td><td>" +
        totpStatus + "</td><td>" +
        status + "</td><td>" +
        htmlEncode(tr("{0} von {1}", moment(user.recentSessionLoggedOn).local().format(tr("DD.MM.YYYY HH:mm:ss")), user.recentSessionRemoteAddress)) + "</td><td>" +
        htmlEncode(tr("{0} von {1}", moment(user.previousSessionLoggedOn).local().format(tr("DD.MM.YYYY HH:mm:ss")), user.previousSessionRemoteAddress));

    tableHtmlRows += "</td><td align=\"right\"><div class=\"dropdown\"><a href=\"#\" id=\"btnAdminUserRowOption" + id + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
    tableHtmlRows += "<li><a href=\"#\" data-id=\"" + id + "\" data-username=\"" + htmlEncode(user.username) + "\" onclick=\"showUserDetailsModal(this); return false;\">Details</a></li>";
    tableHtmlRows += "<li id=\"mnuAdminUserRowEnable" + id + "\"" + (user.disabled ? "" : " style=\"display: none;\"") + "><a href=\"#\" data-id=\"" + id + "\" data-username=\"" + htmlEncode(user.username) + "\" onclick=\"enableUser(this); return false;\">" + tr("Aktivieren") + "</a></li>";
    tableHtmlRows += "<li id=\"mnuAdminUserRowDisable" + id + "\"" + (!user.disabled ? "" : " style=\"display: none;\"") + "><a href=\"#\" data-id=\"" + id + "\" data-username=\"" + htmlEncode(user.username) + "\" onclick=\"disableUser(this); return false;\">" + tr("Deaktivieren") + "</a></li>";

    if (user.type == "Local")
        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + id + "\" data-username=\"" + htmlEncode(user.username) + "\" onclick=\"showResetUserPasswordModal(this); return false;\">" + tr("Passwort zurücksetzen") + "</a></li>";

    switch (user.type) {
        case "RemoteLDAP":
        case "Local":
            if (user.totpEnabled)
                tableHtmlRows += "<li><a href=\"#\" data-id=\"" + id + "\" data-username=\"" + htmlEncode(user.username) + "\" onclick=\"adminDisable2FA(this); return false;\">" + tr("2FA deaktivieren") + "</a></li>";

            break;
    }

    tableHtmlRows += "<li role=\"separator\" class=\"divider\"></li>";
    tableHtmlRows += "<li><a href=\"#\" data-id=\"" + id + "\" data-username=\"" + htmlEncode(user.username) + "\" onclick=\"deleteUser(this); return false;\">" + tr("Benutzer löschen") + "</a></li>";
    tableHtmlRows += "</ul></div></td></tr>";

    return tableHtmlRows;
}

function showAddUserModal() {
    $("#divAddUserAlert").html("");

    $("#txtAddUserDisplayName").val("");
    $("#txtAddUserUsername").val("");
    $("#txtAddUserPassword").val("");
    $("#txtAddUserConfirmPassword").val("");

    $("#modalAddUser").modal("show");

    setTimeout(function () {
        $("#txtAddUserDisplayName").trigger("focus");
    }, 1000);
}

function addUser(objBtn) {
    var btn = $(objBtn);
    var divAddUserAlert = $("#divAddUserAlert");

    var user = $("#txtAddUserUsername").val();
    if (user === "") {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte einen Benutzernamen eingeben."), divAddUserAlert);
        $("#txtAddUserUsername").trigger("focus");
        return;
    }

    var pass = $("#txtAddUserPassword").val();
    if (pass === "") {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte ein Passwort eingeben."), divAddUserAlert);
        $("#txtAddUserPassword").trigger("focus");
        return;
    }

    var confirmPass = $("#txtAddUserConfirmPassword").val();
    if (confirmPass === "") {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte das neue Passwort wiederholen."), divAddUserAlert);
        $("#txtAddUserConfirmPassword").trigger("focus");
        return;
    }

    if (pass !== confirmPass) {
        showAlert("warning", tr("Keine Übereinstimmung"), tr("Die Passwörter stimmen nicht überein."), divAddUserAlert);
        $("#txtAddUserConfirmPassword").trigger("focus");
        return;
    }

    var displayName = $("#txtAddUserDisplayName").val();

    btn.button("loading");

    HTTPRequest({
        url: "api/admin/users/create",
        token: sessionData.token,
        method: "POST",
        data: "displayName=" + encodeURIComponent(displayName) + "&user=" + encodeURIComponent(user) + "&pass=" + encodeURIComponent(pass),
        processData: false,
        success: function (responseJSON) {
            btn.button("reset");
            $("#modalAddUser").modal("hide");

            var id = Math.floor(Math.random() * 1000000);
            var tableHtmlRow = getAdminUsersRowHtml(id, responseJSON.response);
            $("#tableAdminUsers").prepend(tableHtmlRow);

            var totalUsers = $('#tableAdminUsers >tbody >tr').length;
            $("#tfootAdminUsers").html(tr("Benutzer gesamt: {0}", totalUsers));

            showAlert("success", tr("Benutzer angelegt"), tr("Der Benutzer wurde angelegt."));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalAddUser").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divAddUserAlert
    });
}

function showUserDetailsModal(objMenuItem) {
    var divUserDetailsAlert = $("#divUserDetailsAlert");
    var divUserDetailsLoader = $("#divUserDetailsLoader");
    var divUserDetailsViewer = $("#divUserDetailsViewer");

    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var username = mnuItem.attr("data-username");

    divUserDetailsLoader.show();
    divUserDetailsViewer.hide();

    var modalUserDetails = $("#modalUserDetails");
    modalUserDetails.modal("show");

    HTTPRequest({
        url: "api/admin/users/get?user=" + encodeURIComponent(username) + "&includeGroups=true",
        token: sessionData.token,
        success: function (responseJSON) {
            $("#txtUserDetailsDisplayName").val(responseJSON.response.displayName);
            $("#txtUserDetailsUsername").val(responseJSON.response.username);

            switch (responseJSON.response.type) {
                case "RemoteSSO":
                    $("#txtUserDetailsDisplayName").prop("disabled", true);
                    $("#txtUserDetailsUsername").prop("disabled", true);
                    $("#lblUserDetailsUserType").text("Remote/SSO");
                    $("#lblUserDetails2FAStatus").text(tr("über SSO verwaltet"));
                    break;

                case "RemoteLDAP":
                    $("#txtUserDetailsDisplayName").prop("disabled", true);
                    $("#txtUserDetailsUsername").prop("disabled", true);
                    $("#lblUserDetailsUserType").text("Remote/LDAP");
                    $("#lblUserDetails2FAStatus").text(responseJSON.response.totpEnabled ? tr("Aktiv") : tr("Inaktiv"));
                    break;

                case "Local":
                default:
                    $("#txtUserDetailsDisplayName").prop("disabled", false);
                    $("#txtUserDetailsUsername").prop("disabled", false);
                    $("#lblUserDetailsUserType").text(responseJSON.response.type);
                    $("#lblUserDetails2FAStatus").text(responseJSON.response.totpEnabled ? tr("Aktiv") : tr("Inaktiv"));
                    break;
            }

            $("#chkUserDetailsDisableAccount").prop("checked", responseJSON.response.disabled);
            $("#txtUserDetailsSessionTimeout").val(responseJSON.response.sessionTimeoutSeconds);

            var memberOf = "";

            for (var i = 0; i < responseJSON.response.memberOfGroups.length; i++) {
                memberOf += htmlEncode(responseJSON.response.memberOfGroups[i]) + "\n";
            }

            $("#txtUserDetailsMemberOf").prop("disabled", responseJSON.response.remotelyManagedGroups)
            $("#optUserDetailsGroupList").prop("disabled", responseJSON.response.remotelyManagedGroups)

            $("#txtUserDetailsMemberOf").val(memberOf);

            var groupListHtml = "<option value=\"blank\" selected></option><option value=\"none\">" + tr("Leeren") + "</option>";

            for (var i = 0; i < responseJSON.response.groups.length; i++) {
                groupListHtml += "<option>" + htmlEncode(responseJSON.response.groups[i]) + "</option>";
            }

            $("#optUserDetailsGroupList").html(groupListHtml);

            var sessionHtmlRows = "";

            for (var i = 0; i < responseJSON.response.sessions.length; i++) {
                var session;

                if (responseJSON.response.sessions[i].tokenName == null)
                    session = htmlEncode("[" + responseJSON.response.sessions[i].partialToken + "]");
                else
                    session = htmlEncode(responseJSON.response.sessions[i].tokenName) + "<br />[" + htmlEncode(responseJSON.response.sessions[i].partialToken) + "]";

                if (responseJSON.response.sessions[i].isCurrentSession)
                    session += "<br />(" + tr("diese Sitzung") + ")";

                switch (responseJSON.response.sessions[i].type) {
                    case "Standard":
                        session += "<br /><span class=\"label label-default\">Standard</span>";
                        break;

                    case "ApiToken":
                        session += "<br /><span class=\"label label-info\">" + tr("API Token") + "</span>";
                        break;

                    default:
                        session += "<br /><span class=\"label label-warning\">" + tr("Unbekannt") + "</span>";
                        break;
                }

                sessionHtmlRows += "<tr id=\"trUserDetailsActiveSessions" + i + "\"><td style=\"min-width: 155px; word-wrap: anywhere;\">" + session + "</td><td>" +
                    htmlEncode(moment(responseJSON.response.sessions[i].lastSeen).local().format(tr("DD.MM.YYYY HH:mm:ss"))) + "<br /><span style=\"font-size: 12px\">" + htmlEncode("(" + moment(responseJSON.response.sessions[i].lastSeen).fromNow() + ")") + "</span></td><td>" +
                    htmlEncode(responseJSON.response.sessions[i].lastSeenRemoteAddress) + "</td><td style=\"word-wrap: anywhere;\">" +
                    htmlEncode(responseJSON.response.sessions[i].lastSeenUserAgent);

                sessionHtmlRows += "</td><td align=\"right\"><div class=\"dropdown\"><a href=\"#\" id=\"btnUserDetailsActiveSessionRowOption" + i + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
                sessionHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" data-session-type=\"" + htmlEncode(responseJSON.response.sessions[i].type) + "\" data-partial-token=\"" + htmlEncode(responseJSON.response.sessions[i].partialToken) + "\" onclick=\"deleteUserSession(this); return false;\">" + tr("Sitzung beenden") + "</a></li>";
                sessionHtmlRows += "</ul></div></td></tr>";
            }

            $("#tbodyUserDetailsActiveSessions").html(sessionHtmlRows);
            $("#tfootUserDetailsActiveSessions").html(tr("Sitzungen gesamt: {0}", responseJSON.response.sessions.length));

            var btnUserDetailsSave = $("#btnUserDetailsSave");

            if (id != null)
                btnUserDetailsSave.attr("data-id", id);

            btnUserDetailsSave.attr("data-username", username);

            divUserDetailsLoader.hide();
            divUserDetailsViewer.show();

            setTimeout(function () {
                $("#txtUserDetailsDisplayName").trigger("focus");
            }, 1000);
        },
        error: function () {
            divUserDetailsLoader.hide();
        },
        invalidToken: function () {
            modalUserDetails.modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divUserDetailsAlert,
        objLoaderPlaceholder: divUserDetailsLoader
    });
}

function deleteUserSession(objMenuItem) {
    var divUserDetailsAlert = $("#divUserDetailsAlert");
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var sessionType = mnuItem.attr("data-session-type");
    var partialToken = mnuItem.attr("data-partial-token");

    if (!confirm(tr("Sitzung [{0}] beenden?", partialToken)))
        return;

    var apiUrl = "api/admin/sessions/delete?partialToken=" + encodeURIComponent(partialToken);

    var btn = $("#btnUserDetailsActiveSessionRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<span class='spinner spinner-sm' role='status' aria-label='" + tr("Wird geladen") + "'></span>");

    HTTPRequest({
        url: apiUrl,
        token: sessionData.token,
        success: function (responseJSON) {
            $("#trUserDetailsActiveSessions" + id).remove();

            var totalSessions = $('#tableUserDetailsActiveSessions >tbody >tr').length;
            $("#tfootUserDetailsActiveSessions").html(tr("Sitzungen gesamt: {0}", totalSessions));

            showAlert("success", tr("Sitzung beendet"), tr("Die Sitzung wurde beendet."), divUserDetailsAlert);
        },
        error: function () {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);
        },
        invalidToken: function () {
            $("#modalUserDetails").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divUserDetailsAlert
    });
}

function saveUserDetails(objBtn) {
    var btn = $(objBtn);
    var divUserDetailsAlert = $("#divUserDetailsAlert");

    var id = btn.attr("data-id");
    var username = btn.attr("data-username");

    var disabled = $("#chkUserDetailsDisableAccount").prop("checked");

    var sessionTimeoutSeconds = $("#txtUserDetailsSessionTimeout").val();
    if (sessionTimeoutSeconds === "")
        sessionTimeoutSeconds = 1800;

    var params = "user=" + encodeURIComponent(username) + "&disabled=" + disabled + "&sessionTimeoutSeconds=" + encodeURIComponent(sessionTimeoutSeconds);

    if (!$("#txtUserDetailsDisplayName").prop("disabled")) {
        var displayName = $("#txtUserDetailsDisplayName").val();
        params += "&displayName=" + encodeURIComponent(displayName);
    }

    if (!$("#txtUserDetailsUsername").prop("disabled")) {
        var newUsername = $("#txtUserDetailsUsername").val();
        if (newUsername !== username)
            params += "&newUser=" + encodeURIComponent(newUsername);
    }

    if (!$("#txtUserDetailsMemberOf").prop("disabled")) {
        var memberOfGroups = cleanTextList($("#txtUserDetailsMemberOf").val());
        params += "&memberOfGroups=" + encodeURIComponent(memberOfGroups);
    }

    btn.button("loading");

    HTTPRequest({
        url: "api/admin/users/set?" + params,
        token: sessionData.token,
        success: function (responseJSON) {
            if (sessionData.username === username) {
                sessionData.displayName = responseJSON.response.displayName;
                sessionData.username = responseJSON.response.username;
                setUserDisplayName(sessionData.displayName);
            }

            if (id != null) {
                var tableHtmlRow = getAdminUsersRowHtml(id, responseJSON.response);
                $("#trAdminUsers" + id).replaceWith(tableHtmlRow);
            }

            btn.button("reset");
            $("#modalUserDetails").modal("hide");

            if (id == null)
                refreshAdminSessions();

            showAlert("success", tr("Benutzer gespeichert"), tr("Die Benutzerdaten wurden gespeichert."));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalUserDetails").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divUserDetailsAlert
    });
}

function disableUser(objMenuItem) {
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var username = mnuItem.attr("data-username");

    if (!confirm(tr("Benutzer [{0}] deaktivieren?", username)))
        return;

    var btn = $("#btnAdminUserRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<span class='spinner spinner-sm' role='status' aria-label='" + tr("Wird geladen") + "'></span>");

    HTTPRequest({
        url: "api/admin/users/set?user=" + encodeURIComponent(username) + "&disabled=true",
        token: sessionData.token,
        success: function (responseJSON) {
            var tableHtmlRow = getAdminUsersRowHtml(id, responseJSON.response);
            $("#trAdminUsers" + id).replaceWith(tableHtmlRow);

            showAlert("success", tr("Benutzer deaktiviert"), tr("Benutzer [{0}] ist deaktiviert.", username));
        },
        error: function () {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function enableUser(objMenuItem) {
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var username = mnuItem.attr("data-username");

    var btn = $("#btnAdminUserRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<span class='spinner spinner-sm' role='status' aria-label='" + tr("Wird geladen") + "'></span>");

    HTTPRequest({
        url: "api/admin/users/set?user=" + encodeURIComponent(username) + "&disabled=false",
        token: sessionData.token,
        success: function (responseJSON) {
            var tableHtmlRow = getAdminUsersRowHtml(id, responseJSON.response);
            $("#trAdminUsers" + id).replaceWith(tableHtmlRow);

            showAlert("success", tr("Benutzer aktiviert"), tr("Benutzer [{0}] ist aktiv.", username));
        },
        error: function () {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function showResetUserPasswordModal(objMenuItem) {
    var mnuItem = $(objMenuItem);

    var username = mnuItem.attr("data-username");

    $("#titleChangePassword").text(tr("Passwort zurücksetzen"));

    hideAlert($("#divChangePasswordAlert"));
    $("#txtChangePasswordUsername").val(username);
    $("#divChangePasswordCurrentPassword").hide();
    $("#txtChangePasswordNewPassword").val("");
    $("#txtChangePasswordConfirmPassword").val("");
    $("#divChangePassword2FATOTP").hide();

    var btnChangePassword = $("#btnChangePassword");
    btnChangePassword.text(tr("Zurücksetzen"));
    btnChangePassword.attr("onclick", "resetUserPassword(this); return false;");
    btnChangePassword.show();

    $("#modalChangePassword").modal("show");

    setTimeout(function () {
        $("#txtChangePasswordNewPassword").trigger("focus");
    }, 1000);
}

function resetUserPassword(objBtn) {
    var btn = $(objBtn);

    var divChangePasswordAlert = $("#divChangePasswordAlert");

    var user = $("#txtChangePasswordUsername").val();
    var newPassword = $("#txtChangePasswordNewPassword").val();
    var confirmPassword = $("#txtChangePasswordConfirmPassword").val();

    if (newPassword === "") {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte das neue Passwort eingeben."), divChangePasswordAlert);
        $("#txtChangePasswordNewPassword").trigger("focus");
        return;
    }

    if (confirmPassword === "") {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte das neue Passwort wiederholen."), divChangePasswordAlert);
        $("#txtChangePasswordConfirmPassword").trigger("focus");
        return;
    }

    if (newPassword !== confirmPassword) {
        showAlert("warning", tr("Keine Übereinstimmung"), tr("Die Passwörter stimmen nicht überein."), divChangePasswordAlert);
        $("#txtChangePasswordNewPassword").trigger("focus");
        return;
    }

    btn.button("loading");

    HTTPRequest({
        url: "api/admin/users/set",
        token: sessionData.token,
        method: "POST",
        data: "user=" + encodeURIComponent(user) + "&newPass=" + encodeURIComponent(newPassword),
        processData: false,
        success: function (responseJSON) {
            $("#modalChangePassword").modal("hide");
            $("#txtChangePasswordCurrentPassword").val("");
            $("#txtChangePasswordNewPassword").val("");
            $("#txtChangePasswordConfirmPassword").val("");
            $("#txtChangePassword2FATOTP").val("");
            btn.button("reset");

            showAlert("success", tr("Passwort zurückgesetzt"), tr("Das Passwort wurde zurückgesetzt."));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            showPageLogin();
        },
        objAlertPlaceholder: divChangePasswordAlert
    });
}

function adminDisable2FA(objMenuItem) {
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var username = mnuItem.attr("data-username");

    if (!confirm(tr("Zwei-Faktor-Anmeldung für Benutzer [{0}] deaktivieren?", username)))
        return;

    var btn = $("#btnAdminUserRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<span class='spinner spinner-sm' role='status' aria-label='" + tr("Wird geladen") + "'></span>");

    HTTPRequest({
        url: "api/admin/users/set?user=" + encodeURIComponent(username) + "&totpEnabled=false",
        token: sessionData.token,
        success: function (responseJSON) {
            if (username == sessionData.username)
                sessionData.totpEnabled = false;

            var tableHtmlRow = getAdminUsersRowHtml(id, responseJSON.response);
            $("#trAdminUsers" + id).replaceWith(tableHtmlRow);

            showAlert("success", tr("2FA deaktiviert"), tr("Die Zwei-Faktor-Anmeldung ist deaktiviert für Benutzer [{0}].", username));
        },
        error: function () {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function deleteUser(objMenuItem) {
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var username = mnuItem.attr("data-username");

    if (!confirm(tr("Benutzer [{0}] endgültig löschen?", username)))
        return;

    var btn = $("#btnAdminUserRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<span class='spinner spinner-sm' role='status' aria-label='" + tr("Wird geladen") + "'></span>");

    HTTPRequest({
        url: "api/admin/users/delete?user=" + encodeURIComponent(username),
        token: sessionData.token,
        success: function (responseJSON) {
            $("#trAdminUsers" + id).remove();

            var totalUsers = $('#tableAdminUsers >tbody >tr').length;
            $("#tfootAdminUsers").html(tr("Benutzer gesamt: {0}", totalUsers));

            showAlert("success", tr("Benutzer gelöscht"), tr("Der Benutzer wurde gelöscht."));
        },
        error: function () {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function refreshAdminGroups() {
    var divAdminGroupsLoader = $("#divAdminGroupsLoader");
    var divAdminGroupsView = $("#divAdminGroupsView");

    divAdminGroupsLoader.show();
    divAdminGroupsView.hide();

    HTTPRequest({
        url: "api/admin/groups/list",
        token: sessionData.token,
        success: function (responseJSON) {
            var tableHtmlRows = "";

            for (var i = 0; i < responseJSON.response.groups.length; i++) {
                tableHtmlRows += getAdminGroupsRowHtml(i, responseJSON.response.groups[i]);
            }

            $("#tbodyAdminGroups").html(tableHtmlRows);
            $("#tfootAdminGroups").html(tr("Gruppen gesamt: {0}", responseJSON.response.groups.length));

            divAdminGroupsLoader.hide();
            divAdminGroupsView.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divAdminGroupsLoader
    });
}

function getAdminGroupsRowHtml(id, group) {
    var tableHtmlRows = "<tr id=\"trAdminGroups" + id + "\"><td style=\"word-wrap: anywhere;\"><a href=\"#\" data-id=\"" + id + "\" data-group=\"" + htmlEncode(group.name) + "\" onclick=\"showGroupDetailsModal(this); return false;\">" + htmlEncode(group.name) + "</a></td><td style=\"word-wrap: anywhere;\">" +
        htmlEncode(group.description).replace(/\n/g, "<br />");

    tableHtmlRows += "</td><td align=\"right\"><div class=\"dropdown\"><a href=\"#\" id=\"btnAdminGroupRowOption" + id + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
    tableHtmlRows += "<li><a href=\"#\" data-id=\"" + id + "\" data-group=\"" + htmlEncode(group.name) + "\" onclick=\"showGroupDetailsModal(this); return false;\">Details</a></li>";
    tableHtmlRows += "<li role=\"separator\" class=\"divider\"></li>";
    tableHtmlRows += "<li><a href=\"#\" data-id=\"" + id + "\" data-group=\"" + htmlEncode(group.name) + "\" onclick=\"deleteGroup(this); return false;\">" + tr("Gruppe löschen") + "</a></li>";
    tableHtmlRows += "</ul></div></td></tr>";

    return tableHtmlRows;
}

function showAddGroupModal() {
    $("#divAddGroupAlert").html("");

    $("#txtAddGroupName").val("");
    $("#txtAddGroupDescription").val("");

    $("#modalAddGroup").modal("show");

    setTimeout(function () {
        $("#txtAddGroupName").trigger("focus");
    }, 1000);
}

function addGroup(objBtn) {
    var btn = $(objBtn);
    var divAddGroupAlert = $("#divAddGroupAlert");

    var group = $("#txtAddGroupName").val();
    if (group === "") {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte einen Gruppennamen eingeben."), divAddGroupAlert);
        $("#txtAddGroupName").trigger("focus");
        return;
    }

    var description = $("#txtAddGroupDescription").val();

    btn.button("loading");

    HTTPRequest({
        url: "api/admin/groups/create?group=" + encodeURIComponent(group) + "&description=" + encodeURIComponent(description),
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");
            $("#modalAddGroup").modal("hide");

            var id = Math.floor(Math.random() * 1000000);
            var tableHtmlRow = getAdminGroupsRowHtml(id, responseJSON.response);
            $("#tableAdminGroups").prepend(tableHtmlRow);

            var totalGroups = $('#tableAdminGroups >tbody >tr').length;
            $("#tfootAdminGroups").html(tr("Gruppen gesamt: {0}", totalGroups));

            showAlert("success", tr("Gruppe angelegt"), tr("Die Gruppe wurde angelegt."));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalAddGroup").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divAddGroupAlert
    });
}

function showGroupDetailsModal(objMenuItem) {
    var divGroupDetailsAlert = $("#divGroupDetailsAlert");
    var divGroupDetailsLoader = $("#divGroupDetailsLoader");
    var divGroupDetailsViewer = $("#divGroupDetailsViewer");

    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var group = mnuItem.attr("data-group");

    divGroupDetailsLoader.show();
    divGroupDetailsViewer.hide();

    var modalGroupDetails = $("#modalGroupDetails");
    modalGroupDetails.modal("show");

    HTTPRequest({
        url: "api/admin/groups/get?group=" + encodeURIComponent(group) + "&includeUsers=true",
        token: sessionData.token,
        success: function (responseJSON) {
            $("#txtGroupDetailsName").val(responseJSON.response.name);
            $("#txtGroupDetailsDescription").val(responseJSON.response.description);

            var members = "";

            for (var i = 0; i < responseJSON.response.members.length; i++) {
                members += htmlEncode(responseJSON.response.members[i]) + "\n";
            }

            $("#txtGroupDetailsMembers").val(members);

            var userListHtml = "<option value=\"blank\" selected></option><option value=\"none\">" + tr("Leeren") + "</option>";

            for (var i = 0; i < responseJSON.response.users.length; i++) {
                userListHtml += "<option>" + htmlEncode(responseJSON.response.users[i]) + "</option>";
            }

            $("#optGroupDetailsUserList").html(userListHtml);

            var btnGroupDetailsSave = $("#btnGroupDetailsSave");
            btnGroupDetailsSave.attr("data-id", id);
            btnGroupDetailsSave.attr("data-group", group);

            divGroupDetailsLoader.hide();
            divGroupDetailsViewer.show();

            setTimeout(function () {
                $("#txtGroupDetailsName").trigger("focus");
            }, 1000);
        },
        error: function () {
            divGroupDetailsLoader.hide();
        },
        invalidToken: function () {
            modalGroupDetails.modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divGroupDetailsAlert,
        objLoaderPlaceholder: divGroupDetailsLoader
    });
}

function saveGroupDetails(objBtn) {
    var btn = $(objBtn);
    var divGroupDetailsAlert = $("#divGroupDetailsAlert");

    var id = btn.attr("data-id");
    var group = btn.attr("data-group");

    var newGroup = $("#txtGroupDetailsName").val();
    var description = $("#txtGroupDetailsDescription").val();

    var members = cleanTextList($("#txtGroupDetailsMembers").val());

    var apiUrl = "api/admin/groups/set?group=" + encodeURIComponent(group) + "&description=" + encodeURIComponent(description) + "&members=" + encodeURIComponent(members);

    if (newGroup !== group)
        apiUrl += "&newGroup=" + encodeURIComponent(newGroup);

    btn.button("loading");

    HTTPRequest({
        url: apiUrl,
        token: sessionData.token,
        success: function (responseJSON) {
            var tableHtmlRow = getAdminGroupsRowHtml(id, responseJSON.response);
            $("#trAdminGroups" + id).replaceWith(tableHtmlRow);

            btn.button("reset");
            $("#modalGroupDetails").modal("hide");

            showAlert("success", tr("Gruppe gespeichert"), tr("Die Gruppe wurde gespeichert."));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalGroupDetails").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divGroupDetailsAlert
    });
}

function deleteGroup(objMenuItem) {
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var group = mnuItem.attr("data-group");

    if (!confirm(tr("Gruppe [{0}] endgültig löschen?", group)))
        return;

    var btn = $("#btnAdminGroupRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<span class='spinner spinner-sm' role='status' aria-label='" + tr("Wird geladen") + "'></span>");

    HTTPRequest({
        url: "api/admin/groups/delete?group=" + encodeURIComponent(group),
        token: sessionData.token,
        success: function (responseJSON) {
            $("#trAdminGroups" + id).remove();

            var totalGroups = $('#tableAdminGroups >tbody >tr').length;
            $("#tfootAdminGroups").html(tr("Gruppen gesamt: {0}", totalGroups));

            showAlert("success", tr("Gruppe gelöscht"), tr("Die Gruppe wurde gelöscht."));
        },
        error: function () {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function refreshAdminPermissions() {
    var divAdminPermissionsLoader = $("#divAdminPermissionsLoader");
    var divAdminPermissionsView = $("#divAdminPermissionsView");

    divAdminPermissionsLoader.show();
    divAdminPermissionsView.hide();

    HTTPRequest({
        url: "api/admin/permissions/list",
        token: sessionData.token,
        success: function (responseJSON) {
            var tableHtmlRows = "";

            for (var i = 0; i < responseJSON.response.permissions.length; i++) {
                tableHtmlRows += getAdminPermissionsRowHtml(i, responseJSON.response.permissions[i]);
            }

            $("#tbodyAdminPermissions").html(tableHtmlRows);
            $("#tfootAdminPermissions").html(tr("Bereiche gesamt: {0}", responseJSON.response.permissions.length));

            divAdminPermissionsLoader.hide();
            divAdminPermissionsView.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divAdminPermissionsLoader
    });
}

function getPermissionSectionLabel(section) {
    switch (section) {
        case "Dashboard":
            return tr("Übersicht");

        case "Zones":
            return tr("Weiterleitungszonen");

        case "Cache":
            return "Cache";

        case "Allowed":
            return tr("Erlaubte Domains");

        case "Blocked":
            return tr("Blockierte Domains");

        case "Apps":
            return "Apps";

        case "DnsClient":
            return "DNS-Client";

        case "Settings":
            return tr("Einstellungen");

        case "Administration":
            return tr("Verwaltung");

        case "Logs":
            return tr("Protokolle");

        default:
            return section;
    }
}

function getAdminPermissionsRowHtml(id, permission) {
    var userPermissionsHtml = "<table class=\"table\" style=\"background: transparent;\"><thead><tr><th>" + tr("Benutzername") + "</th><th style=\"width: 70px;\">" + tr("Lesen") + "</th><th style=\"width: 70px;\">" + tr("Ändern") + "</th><th style=\"width: 70px;\">" + tr("Löschen") + "</th></tr></thead><tbody>";

    for (var i = 0; i < permission.userPermissions.length; i++) {
        userPermissionsHtml += "<tr><td style=\"word-wrap: anywhere;\">" + htmlEncode(permission.userPermissions[i].username) + "</td><td>" +
            (permission.userPermissions[i].canView ? "<span class=\"glyphicon glyphicon-ok\"></span>" : "") + "</td><td>" +
            (permission.userPermissions[i].canModify ? "<span class=\"glyphicon glyphicon-ok\"></span>" : "") + "</td><td>" +
            (permission.userPermissions[i].canDelete ? "<span class=\"glyphicon glyphicon-ok\"></span>" : "") + "</td></tr>";
    }

    userPermissionsHtml += "</tbody>";

    if (permission.userPermissions.length == 0)
        userPermissionsHtml += "<tfoot><tr><th colspan=\"4\" style=\"text-align: center;\">" + tr("Keine Benutzerberechtigungen") + "</th></tfoot>";

    userPermissionsHtml += "</table>";

    var groupPermissionsHtml = "<table class=\"table\" style=\"background: transparent;\"><thead><tr><th>" + tr("Gruppe") + "</th><th style=\"width: 70px;\">" + tr("Lesen") + "</th><th style=\"width: 70px;\">" + tr("Ändern") + "</th><th style=\"width: 70px;\">" + tr("Löschen") + "</th></tr></thead><tbody>";

    for (var i = 0; i < permission.groupPermissions.length; i++) {
        groupPermissionsHtml += "<tr><td style=\"word-wrap: anywhere;\">" + htmlEncode(permission.groupPermissions[i].name) + "</td><td>" +
            (permission.groupPermissions[i].canView ? "<span class=\"glyphicon glyphicon-ok\"></span>" : "") + "</td><td>" +
            (permission.groupPermissions[i].canModify ? "<span class=\"glyphicon glyphicon-ok\"></span>" : "") + "</td><td>" +
            (permission.groupPermissions[i].canDelete ? "<span class=\"glyphicon glyphicon-ok\"></span>" : "") + "</td></tr>";
    }

    groupPermissionsHtml += "</tbody>";

    if (permission.groupPermissions.length == 0)
        groupPermissionsHtml += "<tfoot><tr><th colspan=\"4\" style=\"text-align: center;\">" + tr("Keine Gruppenberechtigungen") + "</th></tfoot>";

    groupPermissionsHtml += "</table>";

    var tableHtmlRows = "<tr id=\"trAdminPermissions" + id + "\"><td><a href=\"#\" data-id=\"" + id + "\" data-section=\"" + htmlEncode(permission.section) + "\" onclick=\"showEditSectionPermissionsModal(this); return false;\">" + htmlEncode(getPermissionSectionLabel(permission.section)) + "</a></td><td>" +
        userPermissionsHtml + "</td><td>" +
        groupPermissionsHtml;

    tableHtmlRows += "</td><td align=\"right\"><div class=\"dropdown\"><a href=\"#\" id=\"btnAdminPermissionRowOption" + id + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
    tableHtmlRows += "<li><a href=\"#\" data-id=\"" + id + "\" data-section=\"" + htmlEncode(permission.section) + "\" onclick=\"showEditSectionPermissionsModal(this); return false;\">" + tr("Berechtigungen bearbeiten") + "</a></li>";
    tableHtmlRows += "</ul></div></td></tr>";

    return tableHtmlRows;
}

function showEditSectionPermissionsModal(objMenuItem) {
    var divEditPermissionsAlert = $("#divEditPermissionsAlert");
    var divEditPermissionsLoader = $("#divEditPermissionsLoader");
    var divEditPermissionsViewer = $("#divEditPermissionsViewer");

    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var section = mnuItem.attr("data-section");

    $("#lblEditPermissionsName").text(getPermissionSectionLabel(section));
    $("#tbodyEditPermissionsUser").html("");
    $("#tbodyEditPermissionsGroup").html("");

    divEditPermissionsLoader.show();
    divEditPermissionsViewer.hide();

    var btnEditPermissionsSave = $("#btnEditPermissionsSave");
    btnEditPermissionsSave.attr("onclick", "saveSectionPermissions(this); return false;");
    btnEditPermissionsSave.show();

    var modalEditPermissions = $("#modalEditPermissions");
    modalEditPermissions.modal("show");

    HTTPRequest({
        url: "api/admin/permissions/get?section=" + section + "&includeUsersAndGroups=true",
        token: sessionData.token,
        success: function (responseJSON) {
            $("#lblEditPermissionsName").text(getPermissionSectionLabel(responseJSON.response.section));

            for (var i = 0; i < responseJSON.response.userPermissions.length; i++) {
                addEditPermissionUserRow(i, responseJSON.response.userPermissions[i].username, responseJSON.response.userPermissions[i].canView, responseJSON.response.userPermissions[i].canModify, responseJSON.response.userPermissions[i].canDelete);
            }

            var userListHtml = "<option value=\"blank\" selected></option><option value=\"none\">" + tr("Leeren") + "</option>";

            for (var i = 0; i < responseJSON.response.users.length; i++) {
                userListHtml += "<option>" + htmlEncode(responseJSON.response.users[i]) + "</option>";
            }

            $("#optEditPermissionsUserList").html(userListHtml);

            for (var i = 0; i < responseJSON.response.groupPermissions.length; i++) {
                addEditPermissionGroupRow(i, responseJSON.response.groupPermissions[i].name, responseJSON.response.groupPermissions[i].canView, responseJSON.response.groupPermissions[i].canModify, responseJSON.response.groupPermissions[i].canDelete);
            }

            var groupListHtml = "<option value=\"blank\" selected></option><option value=\"none\">" + tr("Leeren") + "</option>";

            for (var i = 0; i < responseJSON.response.groups.length; i++) {
                groupListHtml += "<option>" + htmlEncode(responseJSON.response.groups[i]) + "</option>";
            }

            $("#optEditPermissionsGroupList").html(groupListHtml);

            btnEditPermissionsSave.attr("data-id", id);
            btnEditPermissionsSave.attr("data-section", responseJSON.response.section);

            divEditPermissionsLoader.hide();
            divEditPermissionsViewer.show();
        },
        error: function () {
            divEditPermissionsLoader.hide();
        },
        invalidToken: function () {
            modalEditPermissions.modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divEditPermissionsAlert,
        objLoaderPlaceholder: divEditPermissionsLoader
    });
}

function addEditPermissionUserRow(id, username, canView, canModify, canDelete) {
    if (id == null)
        id = Math.floor(Math.random() * 10000);

    var tableHtmlRow = "<tr id=\"trEditPermissionsUserRow" + id + "\"><td style=\"word-wrap: anywhere;\">" + htmlEncode(username) + "<input type=\"hidden\" value=\"" + htmlEncode(username) + "\"></td>";
    tableHtmlRow += "<td><input type=\"checkbox\"" + (canView ? " checked" : "") + "></td>";
    tableHtmlRow += "<td><input type=\"checkbox\"" + (canModify ? " checked" : "") + "></td>";
    tableHtmlRow += "<td><input type=\"checkbox\"" + (canDelete ? " checked" : "") + "></td>";
    tableHtmlRow += "<td align=\"right\"><button type=\"button\" class=\"btn btn-warning\" style=\"font-size: 12px; padding: 2px 0px; width: 60px;\" onclick=\"$('#trEditPermissionsUserRow" + id + "').remove();\">" + tr("Entfernen") + "</button></td></tr>";

    $("#tbodyEditPermissionsUser").append(tableHtmlRow);
}

function addEditPermissionGroupRow(id, name, canView, canModify, canDelete) {
    if (id == null)
        id = Math.floor(Math.random() * 10000);

    var tableHtmlRow = "<tr id=\"trEditPermissionsGroupRow" + id + "\"><td style=\"word-wrap: anywhere;\">" + htmlEncode(name) + "<input type=\"hidden\" value=\"" + htmlEncode(name) + "\"></td>";
    tableHtmlRow += "<td><input type=\"checkbox\"" + (canView ? " checked" : "") + "></td>";
    tableHtmlRow += "<td><input type=\"checkbox\"" + (canModify ? " checked" : "") + "></td>";
    tableHtmlRow += "<td><input type=\"checkbox\"" + (canDelete ? " checked" : "") + "></td>";
    tableHtmlRow += "<td align=\"right\"><button type=\"button\" class=\"btn btn-warning\" style=\"font-size: 12px; padding: 2px 0px; width: 60px;\" onclick=\"$('#trEditPermissionsGroupRow" + id + "').remove();\">" + tr("Entfernen") + "</button></td></tr>";

    $("#tbodyEditPermissionsGroup").append(tableHtmlRow);
}

function saveSectionPermissions(objBtn) {
    var btn = $(objBtn);
    var divEditPermissionsAlert = $("#divEditPermissionsAlert");

    var id = btn.attr("data-id");
    var section = btn.attr("data-section");

    var userPermissions = serializeTableData($("#tableEditPermissionsUser"), 4);
    var groupPermissions = serializeTableData($("#tableEditPermissionsGroup"), 4);

    var apiUrl = "api/admin/permissions/set?section=" + encodeURIComponent(section) + "&userPermissions=" + encodeURIComponent(userPermissions) + "&groupPermissions=" + encodeURIComponent(groupPermissions);

    btn.button("loading");

    HTTPRequest({
        url: apiUrl,
        token: sessionData.token,
        success: function (responseJSON) {
            var tableHtmlRow = getAdminPermissionsRowHtml(id, responseJSON.response);
            $("#trAdminPermissions" + id).replaceWith(tableHtmlRow);

            btn.button("reset");
            $("#modalEditPermissions").modal("hide");

            showAlert("success", tr("Berechtigungen gespeichert"), tr("Die Berechtigungen wurden gespeichert."));
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalEditPermissions").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divEditPermissionsAlert
    });
}

function refreshAdminSsoConfig() {
    var divAdminSsoLoader = $("#divAdminSsoLoader");
    var divAdminSsoView = $("#divAdminSsoView");

    divAdminSsoLoader.show();
    divAdminSsoView.hide();

    HTTPRequest({
        url: "api/admin/sso/get?includeGroups=true",
        token: sessionData.token,
        success: function (responseJSON) {
            localGroups = responseJSON.response.localGroups;

            loadAdminSsoConfig(responseJSON);

            divAdminSsoLoader.hide();
            divAdminSsoView.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divAdminSsoLoader
    });
}

function loadAdminSsoConfig(responseJSON) {
    $("#chkAdminSsoEnabled").prop("checked", responseJSON.response.ssoEnabled);
    $("#txtAdminSsoAuthority").val(responseJSON.response.ssoAuthority);
    $("#txtAdminSsoClientId").val(responseJSON.response.ssoClientId);
    $("#txtAdminSsoClientSecret").val(responseJSON.response.ssoClientSecret);
    $("#txtAdminSsoMetadataAddress").val(responseJSON.response.ssoMetadataAddress);

    $("#tableAdminSsoScopes").html("");

    for (var i = 0; i < responseJSON.response.ssoScopes.length; i++)
        addAdminSsoScopesRow(responseJSON.response.ssoScopes[i]);

    $("#chkAdminSsoAllowSignup").prop("checked", responseJSON.response.ssoAllowSignup);
    $("#chkAdminSsoAllowSignupOnlyForMappedUsers").prop("disabled", !responseJSON.response.ssoAllowSignup);
    $("#chkAdminSsoAllowSignupOnlyForMappedUsers").prop("checked", responseJSON.response.ssoAllowSignupOnlyForMappedUsers);

    $("#tableAdminSsoGroupMap").html("");

    for (var i = 0; i < responseJSON.response.ssoGroupMap.length; i++)
        addAdminSsoGroupMapRow(responseJSON.response.ssoGroupMap[i].remoteGroup, responseJSON.response.ssoGroupMap[i].localGroup);

    var redirectUri = window.location.protocol + "//" + window.location.host + window.location.pathname;
    if (redirectUri.endsWith("/"))
        redirectUri += "sso/callback";
    else
        redirectUri += "/sso/callback";

    $("#lblAdminSsoRedirectUri").text(redirectUri);
}

function addAdminSsoGroupMapRow(remoteGroup, localGroup) {
    var id = Math.floor(Math.random() * 10000);

    var tableHtmlRows = "<tr id=\"tableAdminSsoGroupMapRow" + id + "\"><td><input type=\"text\" class=\"form-control\" value=\"" + htmlEncode(remoteGroup) + "\"></td>";

    tableHtmlRows += "<td><select class=\"form-control\">";

    for (var i = 0; i < localGroups.length; i++)
        tableHtmlRows += "<option" + (localGroups[i] == localGroup ? " selected" : "") + ">" + htmlEncode(localGroups[i]) + "</option>";

    tableHtmlRows += "</select></td>";

    tableHtmlRows += "<td><button type=\"button\" class=\"btn btn-danger\" onclick=\"$('#tableAdminSsoGroupMapRow" + id + "').remove();\">" + tr("Löschen") + "</button></td></tr>";

    $("#tableAdminSsoGroupMap").append(tableHtmlRows);
}

function addAdminSsoScopesRow(scope) {
    var id = Math.floor(Math.random() * 10000);

    var tableHtmlRows = "<tr id=\"tableAdminSsoScopesRow" + id + "\"><td><input type=\"text\" class=\"form-control\" value=\"" + htmlEncode(scope) + "\"></td>";

    tableHtmlRows += "<td><button type=\"button\" class=\"btn btn-danger\" onclick=\"$('#tableAdminSsoScopesRow" + id + "').remove();\">" + tr("Löschen") + "</button></td></tr>";

    $("#tableAdminSsoScopes").append(tableHtmlRows);
}

function saveAdminSsoConfig(objBtn) {
    var btn = $(objBtn);

    var ssoEnabled = $("#chkAdminSsoEnabled").prop("checked");

    var ssoAuthority = $("#txtAdminSsoAuthority").val();
    if (ssoEnabled && (ssoAuthority === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte die Authority-URL eingeben."));
        $("#txtAdminSsoAuthority").trigger("focus");
        return;
    }

    var ssoClientId = $("#txtAdminSsoClientId").val();
    if (ssoEnabled && (ssoClientId === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte die Client-ID eingeben."));
        $("#txtAdminSsoClientId").trigger("focus");
        return;
    }

    var ssoClientSecret = $("#txtAdminSsoClientSecret").val();
    if (ssoEnabled && ssoClientSecret === "") {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte das Client-Secret eingeben."));
        $("#txtAdminSsoClientSecret").trigger("focus");
        return;
    }

    var ssoMetadataAddress = $("#txtAdminSsoMetadataAddress").val();

    var ssoScopes = serializeTableData($("#tableAdminSsoScopes"), 1);
    if (ssoScopes === false)
        return;

    if (ssoScopes.length == 0)
        ssoScopes = false;

    var ssoAllowSignup = $("#chkAdminSsoAllowSignup").prop("checked");
    var ssoAllowSignupOnlyForMappedUsers = $("#chkAdminSsoAllowSignupOnlyForMappedUsers").prop("checked");

    var ssoGroupMap = serializeTableData($("#tableAdminSsoGroupMap"), 2);
    if (ssoGroupMap === false)
        return;

    if (ssoGroupMap.length == 0)
        ssoGroupMap = false;

    if (ssoAuthority.startsWith("http:")) {
        if (!confirm(tr("ACHTUNG: Im Produktivbetrieb muss die SSO-Authority 'https' verwenden.\n\nTrotzdem mit 'http' fortfahren?"))) {
            $("#txtAdminSsoAuthority").trigger("focus");
            return;
        }
    }

    if (ssoMetadataAddress.startsWith("http:")) {
        if (!confirm(tr("ACHTUNG: Im Produktivbetrieb muss die Metadaten-Adresse 'https' verwenden.\n\nTrotzdem mit 'http' fortfahren?"))) {
            $("#txtAdminSsoMetadataAddress").trigger("focus");
            return;
        }
    }

    btn.button("loading");

    HTTPRequest({
        url: "api/admin/sso/set",
        token: sessionData.token,
        method: "POST",
        data: "ssoEnabled=" + ssoEnabled + "&ssoAuthority=" + encodeURIComponent(ssoAuthority) + "&ssoClientId=" + encodeURIComponent(ssoClientId) + "&ssoClientSecret=" + encodeURIComponent(ssoClientSecret) + "&ssoMetadataAddress=" + encodeURIComponent(ssoMetadataAddress) + "&ssoScopes=" + encodeURIComponent(ssoScopes) + "&ssoAllowSignup=" + ssoAllowSignup + "&ssoAllowSignupOnlyForMappedUsers=" + ssoAllowSignupOnlyForMappedUsers + "&ssoGroupMap=" + encodeURIComponent(ssoGroupMap),
        success: function (responseJSON) {
            loadAdminSsoConfig(responseJSON);
            btn.button("reset");

            showAlert("success", tr("SSO gespeichert"), tr("Die SSO-Konfiguration wurde gespeichert."));
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

function refreshAdminLdapConfig() {
    var divAdminLdapLoader = $("#divAdminLdapLoader");
    var divAdminLdapView = $("#divAdminLdapView");

    divAdminLdapLoader.show();
    divAdminLdapView.hide();

    HTTPRequest({
        url: "api/admin/ldap/get?includeGroups=true",
        token: sessionData.token,
        success: function (responseJSON) {
            localGroups = responseJSON.response.localGroups;

            loadAdminLdapConfig(responseJSON);

            divAdminLdapLoader.hide();
            divAdminLdapView.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divAdminLdapLoader
    });
}

function loadAdminLdapConfig(responseJSON) {
    $("#chkAdminLdapEnabled").prop("checked", responseJSON.response.ldapEnabled);
    $("#txtAdminLdapServer").val(responseJSON.response.ldapServer);
    $("#txtAdminLdapPort").val(responseJSON.response.ldapPort);

    switch (responseJSON.response.ldapSslOption) {
        case "StartTLS":
            $("#rdLdapSslOptionStartTLS").prop("checked", true);
            break;

        case "LDAPS":
            $("#rdLdapSslOptionLDAPS").prop("checked", true);
            break;

        case "None":
        default:
            $("#rdLdapSslOptionNone").prop("checked", true);
            break;
    }

    $("#chkAdminLdapIgnoreSslErrors").prop("disabled", responseJSON.response.ldapSslOption == "None");
    $("#chkAdminLdapIgnoreSslErrors").prop("checked", responseJSON.response.ldapIgnoreSslErrors);

    $("#txtAdminLdapBindUsername").val(responseJSON.response.ldapBindUsername);
    $("#txtAdminLdapBindPassword").val(responseJSON.response.ldapBindPassword);
    $("#txtAdminLdapSearchBase").val(responseJSON.response.ldapSearchBase);
    $("#txtAdminLdapUserSearchFilter").val(responseJSON.response.ldapUserSearchFilter);
    $("#txtAdminLdapGroupAttribute").val(responseJSON.response.ldapGroupAttribute);

    $("#chkAdminLdapAllowSignup").prop("checked", responseJSON.response.ldapAllowSignup);
    $("#chkAdminLdapAllowSignupOnlyForMappedUsers").prop("disabled", !responseJSON.response.ldapAllowSignup);
    $("#chkAdminLdapAllowSignupOnlyForMappedUsers").prop("checked", responseJSON.response.ldapAllowSignupOnlyForMappedUsers);

    $("#tableAdminLdapGroupMap").html("");

    for (var i = 0; i < responseJSON.response.ldapGroupMap.length; i++)
        addAdminLdapGroupMapRow(responseJSON.response.ldapGroupMap[i].remoteGroup, responseJSON.response.ldapGroupMap[i].localGroup);
}

function addAdminLdapGroupMapRow(remoteGroup, localGroup) {
    var id = Math.floor(Math.random() * 10000);

    var tableHtmlRows = "<tr id=\"tableAdminLdapGroupMapRow" + id + "\"><td><input type=\"text\" class=\"form-control\" value=\"" + htmlEncode(remoteGroup) + "\"></td>";

    tableHtmlRows += "<td><select class=\"form-control\">";

    for (var i = 0; i < localGroups.length; i++)
        tableHtmlRows += "<option" + (localGroups[i] == localGroup ? " selected" : "") + ">" + htmlEncode(localGroups[i]) + "</option>";

    tableHtmlRows += "</select></td>";

    tableHtmlRows += "<td><button type=\"button\" class=\"btn btn-danger\" onclick=\"$('#tableAdminLdapGroupMapRow" + id + "').remove();\">" + tr("Löschen") + "</button></td></tr>";

    $("#tableAdminLdapGroupMap").append(tableHtmlRows);
}

function saveAdminLdapConfig(objBtn) {
    var btn = $(objBtn);

    var ldapEnabled = $("#chkAdminLdapEnabled").prop("checked");

    var ldapServer = $("#txtAdminLdapServer").val();
    if (ldapEnabled && (ldapServer === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte die Adresse des LDAP-Servers eingeben."));
        $("#txtAdminLdapServer").trigger("focus");
        return;
    }

    var ldapPort = $("#txtAdminLdapPort").val();
    if (ldapEnabled && (ldapPort === "")) {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte den LDAP-Port eingeben."));
        $("#txtAdminLdapPort").trigger("focus");
        return;
    }

    var ldapSslOption = $("input[name=rdLdapSslOption]:checked").val();
    var ldapIgnoreSslErrors = $("#chkAdminLdapIgnoreSslErrors").prop("checked");
    var ldapBindUsername = $("#txtAdminLdapBindUsername").val();
    var ldapBindPassword = $("#txtAdminLdapBindPassword").val();
    var ldapSearchBase = $("#txtAdminLdapSearchBase").val();
    var ldapUserSearchFilter = $("#txtAdminLdapUserSearchFilter").val();
    var ldapGroupAttribute = $("#txtAdminLdapGroupAttribute").val();
    var ldapAllowSignup = $("#chkAdminLdapAllowSignup").prop("checked");
    var ldapAllowSignupOnlyForMappedUsers = $("#chkAdminLdapAllowSignupOnlyForMappedUsers").prop("checked");

    var ldapGroupMap = serializeTableData($("#tableAdminLdapGroupMap"), 2);
    if (ldapGroupMap === false)
        return;

    if (ldapGroupMap.length == 0)
        ldapGroupMap = false;

    if (ldapIgnoreSslErrors && (ldapSslOption != "None")) {
        if (!confirm(tr("ACHTUNG: Im Produktivbetrieb dürfen Zertifikatsfehler nicht ignoriert werden.\n\nTrotzdem fortfahren?"))) {
            $("#chkAdminLdapIgnoreSslErrors").trigger("focus");
            return;
        }
    }

    btn.button("loading");

    HTTPRequest({
        url: "api/admin/ldap/set",
        token: sessionData.token,
        method: "POST",
        data: "ldapEnabled=" + ldapEnabled + "&ldapServer=" + encodeURIComponent(ldapServer) + "&ldapPort=" + ldapPort + "&ldapSslOption=" + ldapSslOption + "&ldapIgnoreSslErrors=" + ldapIgnoreSslErrors + "&ldapBindUsername=" + encodeURIComponent(ldapBindUsername) + "&ldapBindPassword=" + encodeURIComponent(ldapBindPassword) + "&ldapSearchBase=" + encodeURIComponent(ldapSearchBase) + "&ldapUserSearchFilter=" + encodeURIComponent(ldapUserSearchFilter) + "&ldapGroupAttribute=" + encodeURIComponent(ldapGroupAttribute) + "&ldapAllowSignup=" + ldapAllowSignup + "&ldapAllowSignupOnlyForMappedUsers=" + ldapAllowSignupOnlyForMappedUsers + "&ldapGroupMap=" + encodeURIComponent(ldapGroupMap),
        success: function (responseJSON) {
            loadAdminLdapConfig(responseJSON);
            btn.button("reset");

            showAlert("success", tr("LDAP gespeichert"), tr("Die LDAP-Konfiguration wurde gespeichert."));
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

function testAdminLdapConnection(objBtn) {
    var btn = $(objBtn);

    var ldapServer = $("#txtAdminLdapServer").val();
    if (ldapServer === "") {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte die Adresse des LDAP-Servers eingeben."));
        $("#txtAdminLdapServer").trigger("focus");
        return;
    }

    var ldapPort = $("#txtAdminLdapPort").val();
    if (ldapPort === "") {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte den LDAP-Port eingeben."));
        $("#txtAdminLdapPort").trigger("focus");
        return;
    }

    var ldapSslOption = $("input[name=rdLdapSslOption]:checked").val();
    var ldapIgnoreSslErrors = $("#chkAdminLdapIgnoreSslErrors").prop("checked");
    var ldapBindUsername = $("#txtAdminLdapBindUsername").val();
    var ldapBindPassword = $("#txtAdminLdapBindPassword").val();
    var ldapSearchBase = $("#txtAdminLdapSearchBase").val();
    var ldapUserSearchFilter = $("#txtAdminLdapUserSearchFilter").val();
    var ldapGroupAttribute = $("#txtAdminLdapGroupAttribute").val();

    btn.button("loading");

    HTTPRequest({
        url: "api/admin/ldap/test",
        token: sessionData.token,
        method: "POST",
        data: "ldapServer=" + encodeURIComponent(ldapServer) + "&ldapPort=" + ldapPort + "&ldapSslOption=" + ldapSslOption + "&ldapIgnoreSslErrors=" + ldapIgnoreSslErrors + "&ldapBindUsername=" + encodeURIComponent(ldapBindUsername) + "&ldapBindPassword=" + encodeURIComponent(ldapBindPassword) + "&ldapSearchBase=" + encodeURIComponent(ldapSearchBase) + "&ldapUserSearchFilter=" + encodeURIComponent(ldapUserSearchFilter) + "&ldapGroupAttribute=" + encodeURIComponent(ldapGroupAttribute),
        success: function (responseJSON) {
            btn.button("reset");
            showAlert("success", tr("Test erfolgreich"), tr("Die Verbindung zum LDAP-Server funktioniert."));
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
