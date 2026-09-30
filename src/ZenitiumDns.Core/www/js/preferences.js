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

var userPreferences = null;
var customThemeEditing = null;
var customThemeEditingIsNew = false;
var customThemeBeforeEditing = null;
var settingsTemporarilyUnlocked = false;

var MAX_CUSTOM_THEMES = 20;

var CUSTOM_THEME_DERIVED_TOKENS = {
    "brand-fill": ["brand-fill-hover"],
    "link": ["link-hover"],
    "ok": ["ok-fill"],
    "bad": ["bad-fill"],
    "side-accent": []
};

function getCustomThemeTokens() {
    return [
        { key: "canvas", label: tr("Hintergrund") },
        { key: "surface", label: tr("Flächen") },
        { key: "surface-2", label: tr("Flächen, abgesetzt") },
        { key: "ink", label: tr("Text") },
        { key: "ink-2", label: tr("Text, gedämpft") },
        { key: "line", label: tr("Linien") },
        { key: "brand-fill", label: tr("Akzent") },
        { key: "brand-ink", label: tr("Text auf Akzent") },
        { key: "link", label: tr("Links") },
        { key: "side-bg", label: tr("Seitenleiste") },
        { key: "side-ink", label: tr("Text in der Seitenleiste") },
        { key: "side-accent", label: tr("Akzent in der Seitenleiste") },
        { key: "ok", label: tr("Erfolg") },
        { key: "warn", label: tr("Warnung") },
        { key: "bad", label: tr("Fehler") },
        { key: "c1", label: tr("Diagrammfarbe {0}", 1) },
        { key: "c2", label: tr("Diagrammfarbe {0}", 2) },
        { key: "c3", label: tr("Diagrammfarbe {0}", 3) },
        { key: "c4", label: tr("Diagrammfarbe {0}", 4) },
        { key: "c5", label: tr("Diagrammfarbe {0}", 5) },
        { key: "c6", label: tr("Diagrammfarbe {0}", 6) },
        { key: "c7", label: tr("Diagrammfarbe {0}", 7) }
    ];
}

function isValidThemeColor(value) {
    return (typeof value === "string") && /^#[0-9a-fA-F]{6}$/.test(value);
}

function normalizeCssColor(value) {
    if (value == null)
        return null;

    value = value.trim();

    if (/^#[0-9a-fA-F]{6}$/.test(value))
        return value.toLowerCase();

    if (/^#[0-9a-fA-F]{3}$/.test(value))
        return ("#" + value[1] + value[1] + value[2] + value[2] + value[3] + value[3]).toLowerCase();

    var probe = document.createElement("span");
    probe.style.color = value;
    document.body.appendChild(probe);
    var computed = getComputedStyle(probe).color;
    document.body.removeChild(probe);

    var match = /^rgba?\((\d+),\s*(\d+),\s*(\d+)/.exec(computed);
    if (match == null)
        return null;

    return "#" + [match[1], match[2], match[3]].map(function (part) {
        return ("0" + parseInt(part, 10).toString(16)).slice(-2);
    }).join("");
}

function clearCustomThemeColors() {
    var style = document.body.style;

    for (var i = style.length - 1; i >= 0; i--) {
        var name = style[i];
        if (name.indexOf("--") === 0)
            style.removeProperty(name);
    }
}

function applyCustomThemeColors(theme) {
    clearCustomThemeColors();

    if ((theme == null) || (theme.colors == null))
        return;

    var style = document.body.style;

    for (var key in theme.colors) {
        if (!Object.prototype.hasOwnProperty.call(theme.colors, key) || !/^[a-z0-9-]+$/.test(key))
            continue;

        var value = theme.colors[key];
        if (!isValidThemeColor(value))
            continue;

        style.setProperty("--" + key, value);

        var derived = CUSTOM_THEME_DERIVED_TOKENS[key];
        if (derived != null) {
            for (var j = 0; j < derived.length; j++)
                style.setProperty("--" + derived[j], value);
        }

        if (key === "brand-fill")
            style.setProperty("--focus", "color-mix(in srgb, " + value + " 28%, transparent)");
    }
}

function applyThemeBase(base) {
    switch (base) {
        case "dark":
            applyDarkMode();
            break;

        case "amber":
            applyAmberMode();
            break;

        default:
            applyLightMode();
            break;
    }
}

function getCustomThemes() {
    if ((userPreferences != null) && Array.isArray(userPreferences.themes))
        return userPreferences.themes;

    return [];
}

function getCustomTheme(id) {
    var themes = getCustomThemes();

    for (var i = 0; i < themes.length; i++) {
        if (themes[i].id === id)
            return themes[i];
    }

    try {
        var cached = JSON.parse(localStorage.getItem("customTheme"));
        if ((cached != null) && (cached.id === id))
            return cached;
    }
    catch (e) {
    }

    return null;
}

function applyCustomTheme(id) {
    var theme = getCustomTheme(id);
    if (theme == null)
        return false;

    applyThemeBase(theme.base);
    applyCustomThemeColors(theme);

    try {
        localStorage.setItem("customTheme", JSON.stringify(theme));
    }
    catch (e) {
    }

    return true;
}

function saveUserPreferences(success) {
    if ((sessionData == null) || (userPreferences == null))
        return;

    HTTPRequest({
        url: "api/user/preferences/set",
        method: "POST",
        data: "preferences=" + encodeURIComponent(JSON.stringify(userPreferences)),
        token: sessionData.token,
        success: function () {
            if (success != null)
                success();
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function saveActiveThemePreference(theme) {
    if ((sessionData == null) || (userPreferences == null))
        return;

    if (userPreferences.activeTheme === theme)
        return;

    userPreferences.activeTheme = theme;
    saveUserPreferences();
}

function loadUserPreferences() {
    if (sessionData == null)
        return;

    HTTPRequest({
        url: "api/user/preferences/get",
        token: sessionData.token,
        success: function (responseJSON) {
            var preferences = responseJSON.response.preferences;

            if ((preferences == null) || (typeof preferences !== "object") || Array.isArray(preferences))
                preferences = {};

            if (!Array.isArray(preferences.themes))
                preferences.themes = [];

            userPreferences = preferences;
            settingsTemporarilyUnlocked = false;

            if ((typeof preferences.activeTheme === "string") && (preferences.activeTheme !== localStorage.getItem("theme")))
                changeTheme(preferences.activeTheme, false);
            else if ((typeof preferences.activeTheme === "string") && (preferences.activeTheme.indexOf("custom:") === 0))
                changeTheme(preferences.activeTheme, false);

            applySettingsLockState();
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function renderCustomThemeList() {
    var themes = getCustomThemes();
    var currentTheme = localStorage.getItem("theme");
    var html = "";

    for (var i = 0; i < themes.length; i++) {
        var theme = themes[i];
        var value = "custom:" + theme.id;

        html += "<div class=\"radio\"><label><input type=\"radio\" name=\"rdChangeTheme\" data-theme=\"" + htmlEncode(value) + "\"" + (currentTheme === value ? " checked" : "") + "> " + htmlEncode(theme.name) + "</label> <a href=\"#\" class=\"custom-theme-edit\" data-theme-id=\"" + htmlEncode(theme.id) + "\">" + tr("Bearbeiten") + "</a></div>";
    }

    $("#divCustomThemeList").html(html);

    $("#divCustomThemeList input[type=radio]").on("click", function () {
        changeTheme($(this).attr("data-theme"));
    });

    $("#divCustomThemeList a.custom-theme-edit").on("click", function (e) {
        e.preventDefault();
        editCustomTheme($(this).attr("data-theme-id"));
    });

    $("#btnNewCustomTheme").toggle((sessionData != null) && (userPreferences != null) && (themes.length < MAX_CUSTOM_THEMES));
}

function readCurrentThemeColors() {
    var computed = getComputedStyle(document.body);
    var colors = {};
    var tokens = getCustomThemeTokens();

    for (var i = 0; i < tokens.length; i++) {
        var value = normalizeCssColor(computed.getPropertyValue("--" + tokens[i].key));
        if (value != null)
            colors[tokens[i].key] = value;
    }

    return colors;
}

function renderCustomThemeEditor() {
    var tokens = getCustomThemeTokens();
    var html = "";

    for (var i = 0; i < tokens.length; i++) {
        var token = tokens[i];
        var value = customThemeEditing.colors[token.key] || "#000000";

        html += "<label class=\"theme-color-item\"><input type=\"color\" data-token=\"" + token.key + "\" value=\"" + value + "\"> <span>" + htmlEncode(token.label) + "</span></label>";
    }

    $("#divCustomThemeColors").html(html);

    $("#divCustomThemeColors input[type=color]").on("input change", function () {
        var value = $(this).val();
        if (!isValidThemeColor(value))
            return;

        customThemeEditing.colors[$(this).attr("data-token")] = value.toLowerCase();
        previewCustomTheme();
    });

    $("#txtCustomThemeName").val(customThemeEditing.name);
    $("#optCustomThemeBase").val(customThemeEditing.base);
    $("#btnDeleteCustomTheme").toggle(!customThemeEditingIsNew);
    $("#divCustomThemeEditor").show();
}

function previewCustomTheme() {
    applyThemeBase(customThemeEditing.base);
    applyCustomThemeColors(customThemeEditing);
    updateDashboardChartTheme();
}

function newCustomTheme() {
    customThemeBeforeEditing = localStorage.getItem("theme");
    customThemeEditingIsNew = true;

    var base = document.body.classList.contains("dark-mode") ? "dark" : (document.body.classList.contains("amber-mode") ? "amber" : "light");

    customThemeEditing = {
        id: "t" + Date.now().toString(36) + Math.floor(Math.random() * 1296).toString(36),
        name: tr("Eigenes Farbschema"),
        base: base,
        colors: readCurrentThemeColors()
    };

    renderCustomThemeEditor();
    $("#txtCustomThemeName").trigger("focus").trigger("select");
}

function editCustomTheme(id) {
    var theme = getCustomTheme(id);
    if (theme == null)
        return;

    customThemeBeforeEditing = localStorage.getItem("theme");
    customThemeEditingIsNew = false;
    customThemeEditing = JSON.parse(JSON.stringify(theme));

    if (customThemeEditing.colors == null)
        customThemeEditing.colors = {};

    renderCustomThemeEditor();
    previewCustomTheme();
}

function changeCustomThemeBase() {
    customThemeEditing.base = $("#optCustomThemeBase").val();

    clearCustomThemeColors();
    applyThemeBase(customThemeEditing.base);
    customThemeEditing.colors = readCurrentThemeColors();

    renderCustomThemeEditor();
    previewCustomTheme();
}

function closeCustomThemeEditor() {
    customThemeEditing = null;
    $("#divCustomThemeEditor").hide();
    $("#divCustomThemeColors").html("");
}

function cancelCustomTheme() {
    closeCustomThemeEditor();
    changeTheme(customThemeBeforeEditing, false);
    renderCustomThemeList();
}

function saveCustomTheme() {
    if ((customThemeEditing == null) || (userPreferences == null))
        return;

    var name = $("#txtCustomThemeName").val().trim();
    if (name === "") {
        showAlert("warning", tr("Angabe fehlt"), tr("Bitte einen Namen für das Farbschema eingeben."), $("#divChangeThemeAlert"));
        $("#txtCustomThemeName").trigger("focus");
        return;
    }

    customThemeEditing.name = name.substring(0, 40);

    var themes = getCustomThemes();
    var replaced = false;

    for (var i = 0; i < themes.length; i++) {
        if (themes[i].id === customThemeEditing.id) {
            themes[i] = customThemeEditing;
            replaced = true;
            break;
        }
    }

    if (!replaced) {
        if (themes.length >= MAX_CUSTOM_THEMES)
            return;

        themes.push(customThemeEditing);
    }

    userPreferences.themes = themes;

    var value = "custom:" + customThemeEditing.id;
    closeCustomThemeEditor();

    userPreferences.activeTheme = value;
    changeTheme(value, false);
    saveUserPreferences();
    renderCustomThemeList();
}

function deleteCustomTheme() {
    if ((customThemeEditing == null) || (userPreferences == null) || customThemeEditingIsNew)
        return;

    var id = customThemeEditing.id;
    var value = "custom:" + id;

    userPreferences.themes = getCustomThemes().filter(function (theme) {
        return theme.id !== id;
    });

    closeCustomThemeEditor();

    var nextTheme = customThemeBeforeEditing === value ? "system" : customThemeBeforeEditing;

    userPreferences.activeTheme = nextTheme;
    changeTheme(nextTheme, false);
    saveUserPreferences();
    renderCustomThemeList();
}

function isSettingsLockEnabled() {
    return (userPreferences != null) && (userPreferences.settingsLock === true);
}

function applySettingsLockState() {
    var enabled = isSettingsLockEnabled();
    var locked = enabled && !settingsTemporarilyUnlocked;

    $("#fsSettings").prop("disabled", locked);
    $("#divSettingsLockedNote").toggle(locked);
    $("#btnSaveSettings").prop("disabled", locked);
    $("#btnShowRestoreSettingsModal").prop("disabled", locked);

    var label;

    if (!enabled)
        label = tr("Schreibschutz einschalten");
    else if (locked)
        label = tr("Entsperren");
    else
        label = tr("Wieder sperren");

    $("#lblSettingsLock").text(label);
    $("#btnSettingsLock .fa").toggleClass("fa-lock", !locked).toggleClass("fa-unlock", locked);
}

function setSettingsLockPreference(enabled) {
    if (userPreferences == null)
        return;

    userPreferences.settingsLock = enabled;
    settingsTemporarilyUnlocked = false;

    saveUserPreferences();
    applySettingsLockState();
}

function toggleSettingsLock() {
    if (!isSettingsLockEnabled()) {
        setSettingsLockPreference(true);
        return;
    }

    settingsTemporarilyUnlocked = !settingsTemporarilyUnlocked;
    applySettingsLockState();
}

function relockSettings() {
    if (!settingsTemporarilyUnlocked)
        return;

    settingsTemporarilyUnlocked = false;
    applySettingsLockState();
}

$(function () {
    $(document).on("shown.bs.tab", "#mainPanelTabList a[data-toggle='tab'], .main-nav a[data-toggle='tab']", function (e) {
        if ($(e.target).attr("href") !== "#mainPanelTabPaneSettings")
            relockSettings();
    });

    $("#modalChangeTheme").on("hidden.bs.modal", function () {
        if (customThemeEditing != null)
            cancelCustomTheme();
    });
});
