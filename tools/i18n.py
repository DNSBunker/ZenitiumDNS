#!/usr/bin/env python3
# ZenitiumDNS
# Copyright (C) 2026  xRuffKez
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import html.parser
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WWW = os.path.join(ROOT, "src", "ZenitiumDns.Core", "www")
DICTIONARY = os.path.join(WWW, "lang", "en.json")
HTML_FILES = [os.path.join(WWW, "index.html")]
JS_DIR = os.path.join(WWW, "js")
JSON_SOURCES = {
    os.path.join(WWW, "json", "quick-block-lists-builtin.json"): ["group", "name"],
}

TRANSLATED_ATTRIBUTES = ["title", "placeholder", "aria-label", "alt", "data-original-title", "data-loading-text", "label"]
BUTTON_INPUT_TYPES = {"button", "submit", "reset"}
SKIPPED_TAGS = {"script", "style", "textarea", "pre", "code", "svg", "noscript", "template"}
INLINE_TAGS = {"b", "strong", "i", "em", "code", "a", "br", "kbd", "small", "sup", "sub", "u", "abbr", "samp", "var", "mark", "span"}
VOID_TAGS = {"br", "img", "wbr", "input", "hr", "meta", "link", "area", "base", "col", "embed", "source", "track"}
SERIALIZED_VOID_TAGS = {"br", "img", "wbr", "input", "hr"}
WHITESPACE = re.compile(r"[ \t\n\r\f]+")
NON_WHITESPACE = re.compile(r"[^ \t\n\r\f]")
LETTER = re.compile(r"[A-Za-zÄÖÜäöüß]")
TR_CALL = re.compile(r"\btr\(\s*(\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*')")


class Element:
    def __init__(self, name, attrs):
        self.name = name
        self.attrs = attrs
        self.children = []

    def text_content(self):
        return "".join(c if isinstance(c, str) else c.text_content() for c in self.children)


class TreeBuilder(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = Element("#root", [])
        self.stack = [self.root]

    def handle_starttag(self, tag, attrs):
        element = Element(tag, [(k, "" if v is None else v) for k, v in attrs])
        self.stack[-1].children.append(element)
        if tag not in VOID_TAGS:
            self.stack.append(element)

    def handle_startendtag(self, tag, attrs):
        element = Element(tag, [(k, "" if v is None else v) for k, v in attrs])
        self.stack[-1].children.append(element)

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i].name == tag:
                del self.stack[i:]
                return

    def handle_data(self, data):
        parent = self.stack[-1]
        if parent.children and isinstance(parent.children[-1], str):
            parent.children[-1] += data
        else:
            parent.children.append(data)


def normalize(text):
    return WHITESPACE.sub(" ", text).strip()


def escape_text(text):
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace(" ", "&nbsp;")


def escape_attribute(text):
    return text.replace("&", "&amp;").replace("\"", "&quot;").replace(" ", "&nbsp;")


def serialize(node):
    if isinstance(node, str):
        return escape_text(WHITESPACE.sub(" ", node))
    result = "<" + node.name + "".join(" " + k + "=\"" + escape_attribute(v) + "\"" for k, v in node.attrs)
    result += ">"
    if node.name in SERIALIZED_VOID_TAGS:
        return result
    return result + "".join(serialize(c) for c in node.children) + "</" + node.name + ">"


def serialize_children(element):
    return re.sub(r" {2,}", " ", "".join(serialize(c) for c in element.children)).strip()


def is_inline_only(element):
    if element.name not in INLINE_TAGS:
        return False
    return all(isinstance(c, str) or is_inline_only(c) for c in element.children)


def is_mixed_unit(element):
    own_text = False
    element_text = False
    for child in element.children:
        if isinstance(child, str):
            if NON_WHITESPACE.search(child):
                own_text = True
        else:
            if not is_inline_only(child):
                return False
            if NON_WHITESPACE.search(child.text_content()):
                element_text = True
    return own_text and element_text


def html_keys(path):
    builder = TreeBuilder()
    with open(path, encoding="utf-8-sig") as f:
        builder.feed(f.read())
    builder.close()
    keys = []

    def attr(element, name):
        for k, v in element.attrs:
            if k == name:
                return v
        return None

    def visit(element):
        if element.name in SKIPPED_TAGS or attr(element, "translate") == "no":
            return
        for name in TRANSLATED_ATTRIBUTES:
            value = attr(element, name)
            if value is not None and LETTER.search(value):
                keys.append(normalize(value))
        context_key = attr(element, "data-i18n-key")
        if context_key is not None:
            keys.append(context_key)
            return
        if element.name == "input" and (attr(element, "type") or "").lower() in BUTTON_INPUT_TYPES:
            value = attr(element, "value")
            if value is not None and LETTER.search(value):
                keys.append(normalize(value))
        if is_mixed_unit(element):
            key = serialize_children(element)
            if LETTER.search(key):
                keys.append(key)
                return
        for child in element.children:
            if isinstance(child, str):
                if LETTER.search(child):
                    keys.append(normalize(child))
            elif child.name != "#root":
                visit(child)

    for child in builder.root.children:
        if not isinstance(child, str):
            visit(child)
    return keys


def decode_js_string(literal):
    quote = literal[0]
    body = literal[1:-1]
    result = []
    i = 0
    while i < len(body):
        c = body[i]
        if c != "\\":
            result.append(c)
            i += 1
            continue
        n = body[i + 1]
        if n == "n":
            result.append("\n")
            i += 2
        elif n == "r":
            result.append("\r")
            i += 2
        elif n == "t":
            result.append("\t")
            i += 2
        elif n == "u":
            result.append(chr(int(body[i + 2:i + 6], 16)))
            i += 6
        elif n == "x":
            result.append(chr(int(body[i + 2:i + 4], 16)))
            i += 4
        else:
            result.append(n)
            i += 2
    return "".join(result)


def js_keys(path):
    with open(path, encoding="utf-8-sig") as f:
        source = f.read()
    return [decode_js_string(m.group(1)) for m in TR_CALL.finditer(source)]


def json_keys(path, fields):
    keys = []

    def visit(value):
        if isinstance(value, dict):
            for k, v in value.items():
                if k in fields and isinstance(v, str) and LETTER.search(v):
                    keys.append(v)
                else:
                    visit(v)
        elif isinstance(value, list):
            for v in value:
                visit(v)

    with open(path, encoding="utf-8-sig") as f:
        visit(json.load(f))
    return keys


def collect():
    sources = []
    for path in HTML_FILES:
        sources.append((os.path.relpath(path, ROOT), html_keys(path)))
    for name in sorted(os.listdir(JS_DIR)):
        if name.endswith(".js") and ".min." not in name and name != "i18n.js":
            path = os.path.join(JS_DIR, name)
            sources.append((os.path.relpath(path, ROOT), js_keys(path)))
    for path, fields in JSON_SOURCES.items():
        if os.path.exists(path):
            sources.append((os.path.relpath(path, ROOT), json_keys(path, fields)))
    ordered = []
    seen = set()
    for source, keys in sources:
        for key in keys:
            if key not in seen:
                seen.add(key)
                ordered.append((source, key))
    return ordered


def load_dictionary():
    if not os.path.exists(DICTIONARY):
        return {}
    with open(DICTIONARY, encoding="utf-8") as f:
        return json.load(f)


def tag_signature(text):
    return sorted(re.findall(r"<[^>]+>", text))


def placeholder_signature(text):
    return sorted(re.findall(r"\{\d+\}", text))


def main():
    parser = argparse.ArgumentParser(description="Checks and maintains the English dictionary of the web UI.")
    parser.add_argument("command", choices=["check", "missing", "unused", "sort"])
    parser.add_argument("--output", help="write missing keys as JSON to this file")
    args = parser.parse_args()

    keys = collect()
    dictionary = load_dictionary()
    known = {key for _, key in keys}

    missing = [(source, key) for source, key in keys if key not in dictionary]
    unused = [key for key in dictionary if key not in known]
    broken = [key for key, value in dictionary.items() if tag_signature(key) != tag_signature(value) or placeholder_signature(key) != placeholder_signature(value)]

    if args.command == "missing":
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump({key: "" for _, key in missing}, f, ensure_ascii=False, indent=1)
        for source, key in missing:
            print(source + "\t" + key)
        return 0

    if args.command == "unused":
        for key in unused:
            print(key)
        return 0

    if args.command == "sort":
        ordered = {key: dictionary[key] for _, key in keys if key in dictionary}
        with open(DICTIONARY, "w", encoding="utf-8") as f:
            json.dump(ordered, f, ensure_ascii=False, indent=1)
            f.write("\n")
        print("%d entries written, %d unused removed" % (len(ordered), len(unused)))
        return 0

    for source, key in missing:
        print("missing\t" + source + "\t" + key)
    for key in unused:
        print("unused\t" + key)
    for key in broken:
        print("markup\t" + key)
    print("%d keys, %d missing, %d unused, %d with differing markup or placeholders" % (len(keys), len(missing), len(unused), len(broken)), file=sys.stderr)
    return 1 if missing or broken else 0


if __name__ == "__main__":
    sys.exit(main())
