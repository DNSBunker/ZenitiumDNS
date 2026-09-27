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

var zdnsI18n = (function () {
    var config = window.zdnsLanguage || {};
    var language = (config.language === "en") ? "en" : "de";
    var dictionary = ((language !== "de") && (config.dictionary != null)) ? config.dictionary : {};
    var missing = {};

    var TRANSLATED_ATTRIBUTES = ["title", "placeholder", "aria-label", "alt", "data-original-title", "data-loading-text", "label"];
    var BUTTON_INPUT_TYPES = { "button": true, "submit": true, "reset": true };
    var SKIPPED_TAGS = { "script": true, "style": true, "textarea": true, "pre": true, "code": true, "svg": true, "noscript": true, "template": true };
    var INLINE_TAGS = { "b": true, "strong": true, "i": true, "em": true, "code": true, "a": true, "br": true, "kbd": true, "small": true, "sup": true, "sub": true, "u": true, "abbr": true, "samp": true, "var": true, "mark": true, "span": true };
    var VOID_TAGS = { "br": true, "img": true, "wbr": true, "input": true, "hr": true };
    var WHITESPACE = /[ \t\n\r\f]+/g;
    var LETTER = /[A-Za-zÄÖÜäöüß]/;

    function normalize(text) {
        return text.replace(WHITESPACE, " ").trim();
    }

    function lookup(key) {
        if (Object.prototype.hasOwnProperty.call(dictionary, key))
            return dictionary[key];

        if (language !== "de")
            missing[key] = true;

        return null;
    }

    function translate(text) {
        if ((text == null) || (language === "de"))
            return text;

        var value = lookup(text);
        return (value == null) ? text : value;
    }

    function escapeText(text) {
        return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/ /g, "&nbsp;");
    }

    function escapeAttribute(text) {
        return text.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/ /g, "&nbsp;");
    }

    function serializeNode(node) {
        if (node.nodeType === 3)
            return escapeText(node.nodeValue.replace(WHITESPACE, " "));

        if (node.nodeType !== 1)
            return "";

        var name = node.nodeName.toLowerCase();
        var html = "<" + name;

        for (var i = 0; i < node.attributes.length; i++)
            html += " " + node.attributes[i].name + "=\"" + escapeAttribute(node.attributes[i].value) + "\"";

        html += ">";

        if (VOID_TAGS[name])
            return html;

        for (var j = 0; j < node.childNodes.length; j++)
            html += serializeNode(node.childNodes[j]);

        return html + "</" + name + ">";
    }

    function serializeChildren(element) {
        var html = "";

        for (var i = 0; i < element.childNodes.length; i++)
            html += serializeNode(element.childNodes[i]);

        return html.replace(/ {2,}/g, " ").trim();
    }

    function isInlineOnly(element) {
        if (!INLINE_TAGS[element.nodeName.toLowerCase()])
            return false;

        for (var i = 0; i < element.childNodes.length; i++) {
            var child = element.childNodes[i];

            if ((child.nodeType === 1) && !isInlineOnly(child))
                return false;
        }

        return true;
    }

    function isMixedUnit(element) {
        var hasOwnText = false;
        var hasElementText = false;

        for (var i = 0; i < element.childNodes.length; i++) {
            var child = element.childNodes[i];

            if (child.nodeType === 3) {
                if (/[^ \t\n\r\f]/.test(child.nodeValue))
                    hasOwnText = true;
            }
            else if (child.nodeType === 1) {
                if (!isInlineOnly(child))
                    return false;

                if (/[^ \t\n\r\f]/.test(child.textContent))
                    hasElementText = true;
            }
        }

        return hasOwnText && hasElementText;
    }

    function translateAttributes(element) {
        for (var i = 0; i < TRANSLATED_ATTRIBUTES.length; i++) {
            var name = TRANSLATED_ATTRIBUTES[i];
            var value = element.getAttribute(name);

            if ((value == null) || !LETTER.test(value))
                continue;

            var translated = lookup(normalize(value));
            if (translated != null)
                element.setAttribute(name, translated);
        }

        if ((element.nodeName.toLowerCase() === "input") && BUTTON_INPUT_TYPES[(element.getAttribute("type") || "").toLowerCase()]) {
            var buttonValue = element.getAttribute("value");

            if ((buttonValue != null) && LETTER.test(buttonValue)) {
                var translatedValue = lookup(normalize(buttonValue));
                if (translatedValue != null)
                    element.setAttribute("value", translatedValue);
            }
        }
    }

    function translateTextNode(node) {
        var text = node.nodeValue;
        if (!LETTER.test(text))
            return;

        var translated = lookup(normalize(text));
        if (translated == null)
            return;

        var leading = /^[ \t\n\r\f]+/.test(text) ? " " : "";
        var trailing = /[ \t\n\r\f]+$/.test(text) ? " " : "";

        node.nodeValue = leading + translated + trailing;
    }

    function translateElement(element) {
        var name = element.nodeName.toLowerCase();

        if (SKIPPED_TAGS[name] || (element.getAttribute("translate") === "no"))
            return;

        translateAttributes(element);

        var contextKey = element.getAttribute("data-i18n-key");
        if (contextKey != null) {
            var contextTranslation = lookup(contextKey);
            if (contextTranslation != null)
                element.textContent = contextTranslation;

            return;
        }

        if (isMixedUnit(element)) {
            var key = serializeChildren(element);

            if (LETTER.test(key)) {
                var translated = lookup(key);
                if (translated != null) {
                    element.innerHTML = translated;
                    return;
                }
            }
        }

        var children = Array.prototype.slice.call(element.childNodes);

        for (var i = 0; i < children.length; i++) {
            var child = children[i];

            if (child.nodeType === 3)
                translateTextNode(child);
            else if (child.nodeType === 1)
                translateElement(child);
        }
    }

    function translateTree(root) {
        if (language === "de")
            return;

        if ((typeof jQuery !== "undefined") && (root instanceof jQuery)) {
            root.each(function () {
                translateElement(this);
            });
        }
        else if (root != null) {
            translateElement(root);
        }
    }

    function setLanguageCookie(value) {
        document.cookie = "zdnsLanguage=" + value + ";Max-Age=31536000;path=/;SameSite=Lax";
    }

    document.documentElement.lang = language;

    if (language !== "de") {
        document.documentElement.className += " i18n-pending";

        document.addEventListener("DOMContentLoaded", function () {
            translateElement(document.body);

            var title = lookup(normalize(document.title));
            if (title != null)
                document.title = title;

            document.documentElement.className = document.documentElement.className.replace(/\s*i18n-pending/g, "");
        });
    }

    return {
        language: language,
        chosen: config.chosen === true,
        locale: (language === "de") ? "de-DE" : "en-US",
        translate: translate,
        translateTree: translateTree,
        setLanguageCookie: setLanguageCookie,
        missing: function () {
            return Object.keys(missing);
        }
    };
})();

function tr(text) {
    var result = zdnsI18n.translate(text);

    if (arguments.length > 1) {
        var args = arguments;

        result = result.replace(/\{(\d+)\}/g, function (match, index) {
            var value = args[Number(index) + 1];
            return (value == null) ? "" : String(value);
        });
    }

    return result;
}
