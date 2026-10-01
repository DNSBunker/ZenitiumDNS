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

var THEME_PRESETS = [
    { id: "ocean", name: "Ozean", mode: "light", accent: "#1f6fb2", tint: "#1f6fb2", sidebar: "dark" },
    { id: "lavender", name: "Lavendel", mode: "light", accent: "#6a4fc0", tint: "#6a4fc0", sidebar: "accent" },
    { id: "sun", name: "Sonne", mode: "light", accent: "#b85c0f", tint: "#c98a2e", sidebar: "dark" },
    { id: "slate", name: "Schiefer", mode: "light", accent: "#3d5a80", tint: "#5c6b7a", sidebar: "light" },
    { id: "forest", name: "Wald", mode: "dark", accent: "#46b373", tint: "#2f7a52", sidebar: "dark" },
    { id: "nord", name: "Nord", mode: "dark", accent: "#88c0d0", tint: "#4c566a", sidebar: "dark" },
    { id: "berry", name: "Beere", mode: "dark", accent: "#e0679b", tint: "#6d3a5a", sidebar: "dark" },
    { id: "contrast", name: "Hoher Kontrast", mode: "dark", accent: "#ffd400", tint: "#000000", sidebar: "dark", contrast: true }
];

var THEME_STATUS = {
    light: { ok: "#1a7340", okFill: "#1a7a43", warn: "#8f5b00", warnFill: "#e8a317", bad: "#b8352a", badFill: "#c0392b", info: "#2463b8", infoFill: "#2463b8" },
    dark: { ok: "#5fd49a", okFill: "#1f9d5c", warn: "#f0b44c", warnFill: "#e8a317", bad: "#ff8a80", badFill: "#c9463d", info: "#7fb0ff", infoFill: "#3470c8" }
};

var THEME_CHART = {
    light: ["#00897b", "#eb6834", "#2a78d6", "#eda100", "#e87ba4", "#4a3aa7", "#e34948", "#5a8a2f"],
    dark: ["#149c8a", "#d95926", "#3987e5", "#c98500", "#d55181", "#9085e9", "#e66767", "#7fb85a"]
};

function themeHexToRgb(hex) {
    return [parseInt(hex.substring(1, 3), 16), parseInt(hex.substring(3, 5), 16), parseInt(hex.substring(5, 7), 16)];
}

function themeRgbToHex(rgb) {
    return "#" + rgb.map(function (part) {
        var value = Math.max(0, Math.min(255, Math.round(part)));
        return ("0" + value.toString(16)).slice(-2);
    }).join("");
}

function themeMix(a, b, t) {
    var x = themeHexToRgb(a);
    var y = themeHexToRgb(b);

    return themeRgbToHex([x[0] + ((y[0] - x[0]) * t), x[1] + ((y[1] - x[1]) * t), x[2] + ((y[2] - x[2]) * t)]);
}

function themeLuminance(hex) {
    var rgb = themeHexToRgb(hex).map(function (part) {
        var c = part / 255;
        return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
    });

    return (0.2126 * rgb[0]) + (0.7152 * rgb[1]) + (0.0722 * rgb[2]);
}

function themeContrast(a, b) {
    var x = themeLuminance(a);
    var y = themeLuminance(b);

    return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}

function themeEnsureContrast(foreground, background, minimum) {
    if (themeContrast(foreground, background) >= minimum)
        return foreground;

    var target = themeLuminance(background) > 0.18 ? "#000000" : "#ffffff";

    for (var t = 0.05; t < 1; t += 0.05) {
        var candidate = themeMix(foreground, target, t);

        if (themeContrast(candidate, background) >= minimum)
            return candidate;
    }

    return target;
}

function themeRgba(hex, alpha) {
    var rgb = themeHexToRgb(hex);
    return "rgba(" + rgb[0] + ", " + rgb[1] + ", " + rgb[2] + ", " + alpha + ")";
}

function themeHue(hex) {
    var rgb = themeHexToRgb(hex).map(function (part) { return part / 255; });
    var max = Math.max(rgb[0], rgb[1], rgb[2]);
    var min = Math.min(rgb[0], rgb[1], rgb[2]);
    var d = max - min;

    if (d === 0)
        return -1;

    var h;

    if (max === rgb[0])
        h = ((rgb[1] - rgb[2]) / d) % 6;
    else if (max === rgb[1])
        h = ((rgb[2] - rgb[0]) / d) + 2;
    else
        h = ((rgb[0] - rgb[1]) / d) + 4;

    h *= 60;
    return h < 0 ? h + 360 : h;
}

function themeHueDistance(a, b) {
    var x = themeHue(a);
    var y = themeHue(b);

    if ((x < 0) || (y < 0))
        return 180;

    var d = Math.abs(x - y);
    return d > 180 ? 360 - d : d;
}

function normalizeThemeSpec(spec) {
    var mode = spec.mode === "dark" ? "dark" : "light";
    var accent = isValidThemeColor(spec.accent) ? spec.accent.toLowerCase() : "#00796b";
    var tint = isValidThemeColor(spec.tint) ? spec.tint.toLowerCase() : accent;
    var sidebar = ((spec.sidebar === "light") || (spec.sidebar === "accent")) ? spec.sidebar : "dark";

    return { mode: mode, accent: accent, tint: tint, sidebar: sidebar, contrast: spec.contrast === true };
}

function generateThemePalette(input) {
    var spec = normalizeThemeSpec(input);
    var dark = spec.mode === "dark";
    var accent = spec.accent;
    var tint = spec.tint;
    var white = "#ffffff";
    var black = "#0b0f0f";
    var p = {};

    if (dark) {
        p.canvas = spec.contrast ? "#000000" : themeMix("#0b1010", tint, 0.1);
        p.surface = themeMix(p.canvas, white, spec.contrast ? 0.07 : 0.035);
        p["surface-2"] = themeMix(p.canvas, white, spec.contrast ? 0.1 : 0.065);
        p["surface-3"] = themeMix(p.canvas, white, spec.contrast ? 0.14 : 0.1);
        p.ink = spec.contrast ? white : themeMix("#e7eded", tint, 0.06);
    }
    else {
        p.canvas = themeMix("#eef1f1", tint, 0.06);
        p.surface = themeMix(white, tint, 0.01);
        p["surface-2"] = themeMix(p.surface, p.canvas, 0.6);
        p["surface-3"] = themeMix(p.canvas, "#000000", 0.03);
        p.ink = themeMix("#141a1a", tint, 0.12);
    }

    p.ink = themeEnsureContrast(p.ink, p.surface, spec.contrast ? 15 : 12);
    p["ink-2"] = themeEnsureContrast(themeMix(p.ink, p.surface, spec.contrast ? 0.15 : 0.32), p.surface, spec.contrast ? 10 : 6);
    p["ink-3"] = themeEnsureContrast(themeMix(p.ink, p.surface, spec.contrast ? 0.25 : 0.45), p.surface, spec.contrast ? 7 : 4.6);
    p.line = themeMix(p.canvas, p.ink, spec.contrast ? 0.35 : (dark ? 0.12 : 0.08));
    p["line-2"] = themeMix(p.canvas, p.ink, spec.contrast ? 0.5 : (dark ? 0.22 : 0.18));

    var brandInk = themeContrast(white, accent) >= themeContrast(black, accent) ? white : black;
    var fill = themeEnsureContrast(accent, brandInk, spec.contrast ? 7 : 4.5);

    p["brand-fill"] = fill;
    p["brand-ink"] = brandInk;
    p["brand-fill-hover"] = themeMix(fill, brandInk === white ? "#000000" : white, 0.12);
    p["brand-soft"] = themeMix(p.surface, accent, dark ? 0.16 : 0.12);
    p["brand-line"] = themeMix(p.surface, accent, dark ? 0.45 : 0.4);
    p.link = themeEnsureContrast(accent, p.surface, spec.contrast ? 7 : 4.6);
    p["link-hover"] = themeEnsureContrast(themeMix(p.link, dark ? white : "#000000", 0.2), p.surface, spec.contrast ? 7 : 4.6);
    p.focus = themeRgba(accent, spec.contrast ? 0.6 : 0.28);

    var status = dark ? THEME_STATUS.dark : THEME_STATUS.light;
    var softAmount = dark ? 0.18 : 0.12;

    p.ok = themeEnsureContrast(status.ok, p.surface, 4.5);
    p["ok-fill"] = status.okFill;
    p["ok-soft"] = themeMix(p.surface, status.okFill, softAmount);
    p.warn = themeEnsureContrast(status.warn, p.surface, 4.5);
    p["warn-fill"] = status.warnFill;
    p["warn-soft"] = themeMix(p.surface, status.warnFill, softAmount);
    p.bad = themeEnsureContrast(status.bad, p.surface, 4.5);
    p["bad-fill"] = status.badFill;
    p["bad-soft"] = themeMix(p.surface, status.badFill, softAmount);
    p.info = themeEnsureContrast(status.info, p.surface, 4.5);
    p["info-fill"] = status.infoFill;
    p["info-soft"] = themeMix(p.surface, status.infoFill, softAmount);

    var sideBg;

    switch (spec.sidebar) {
        case "light":
            sideBg = dark ? themeMix(p.canvas, white, 0.02) : p.surface;
            break;

        case "accent":
            sideBg = themeMix(accent, "#000000", dark ? 0.75 : 0.62);
            break;

        default:
            sideBg = dark ? themeMix(p.canvas, "#000000", 0.35) : themeMix("#0f1818", tint, 0.18);
            break;
    }

    var sideText = themeLuminance(sideBg) < 0.2 ? white : black;

    p["side-bg"] = sideBg;
    p["side-ink"] = themeEnsureContrast(themeMix(sideText, sideBg, 0.22), sideBg, 7);
    p["side-ink-2"] = themeEnsureContrast(themeMix(sideText, sideBg, 0.45), sideBg, 4.5);
    p["side-strong"] = sideText;
    p["side-accent"] = themeEnsureContrast(sideText === white ? themeMix(accent, white, 0.25) : accent, sideBg, 4.5);
    p["side-hover"] = themeRgba(sideText, 0.06);
    p["side-active"] = themeRgba(p["side-accent"], 0.16);
    p["side-line"] = themeRgba(sideText, 0.09);

    var shadow = dark ? "#000000" : themeMix("#0f1818", tint, 0.2);

    p["shadow-pop"] = "0 14px 36px " + themeRgba(shadow, dark ? 0.5 : 0.16) + ", 0 2px 6px " + themeRgba(shadow, dark ? 0.35 : 0.08);
    p["shadow-lift"] = "0 1px 2px " + themeRgba(shadow, dark ? 0.4 : 0.08);
    p.backdrop = themeRgba(dark ? "#000000" : themeMix("#081414", tint, 0.2), dark ? 0.6 : 0.45);

    var chart = dark ? THEME_CHART.dark : THEME_CHART.light;
    var colors = [themeEnsureContrast(accent, p.surface, 3)];

    for (var i = 0; (i < chart.length) && (colors.length < 7); i++) {
        if (themeHueDistance(chart[i], accent) > 25)
            colors.push(themeEnsureContrast(chart[i], p.surface, 3));
    }

    for (var j = 0; j < 7; j++)
        p["c" + (j + 1)] = colors[j];

    p["c-neutral"] = p["ink-3"];
    p.grid = themeMix(p.surface, p.ink, dark ? 0.1 : 0.07);
    p.axis = p["ink-3"];

    return p;
}

function applyThemePalette(palette, mode) {
    clearCustomThemeColors();
    applyThemeBase(mode === "dark" ? "dark" : "light");

    var style = document.body.style;

    for (var key in palette) {
        if (Object.prototype.hasOwnProperty.call(palette, key))
            style.setProperty("--" + key, palette[key]);
    }

    style.setProperty("color-scheme", mode === "dark" ? "dark" : "light");
}

function getThemePreset(id) {
    for (var i = 0; i < THEME_PRESETS.length; i++) {
        if (THEME_PRESETS[i].id === id)
            return THEME_PRESETS[i];
    }

    return null;
}

function applyThemePreset(id) {
    var preset = getThemePreset(id);
    if (preset == null)
        return false;

    applyThemePalette(generateThemePalette(preset), preset.mode);
    return true;
}

function getCustomThemePalette(theme) {
    var palette = generateThemePalette(theme);

    if (theme.colors != null) {
        for (var key in theme.colors) {
            if (Object.prototype.hasOwnProperty.call(theme.colors, key) && /^[a-z0-9-]+$/.test(key) && isValidThemeColor(theme.colors[key]))
                palette[key] = theme.colors[key];
        }
    }

    return palette;
}

function getThemeContrastChecks(palette) {
    var checks = [
        { label: tr("Text auf Flächen"), fg: palette.ink, bg: palette.surface, minimum: 7 },
        { label: tr("Gedämpfter Text"), fg: palette["ink-3"], bg: palette.surface, minimum: 4.5 },
        { label: tr("Text auf Akzent"), fg: palette["brand-ink"], bg: palette["brand-fill"], minimum: 4.5 },
        { label: tr("Links"), fg: palette.link, bg: palette.surface, minimum: 4.5 },
        { label: tr("Seitenleiste"), fg: palette["side-ink"], bg: palette["side-bg"], minimum: 4.5 },
        { label: tr("Akzent in der Seitenleiste"), fg: palette["side-accent"], bg: palette["side-bg"], minimum: 3 }
    ];

    for (var i = 0; i < checks.length; i++) {
        var fg = checks[i].fg;
        var bg = checks[i].bg;

        checks[i].ratio = (isValidThemeColor(fg) && isValidThemeColor(bg)) ? themeContrast(fg, bg) : null;
        checks[i].ok = (checks[i].ratio == null) || (checks[i].ratio >= checks[i].minimum);
    }

    return checks;
}
