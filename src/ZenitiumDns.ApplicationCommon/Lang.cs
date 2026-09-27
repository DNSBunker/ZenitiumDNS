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

using System;
using System.Globalization;

namespace ZenitiumDns.ApplicationCommon
{
    public static class Lang
    {
        public const string German = "de";
        public const string English = "en";

        static volatile bool _english = true;

        public static bool IsSupported(string code)
        {
            return (code == German) || (code == English);
        }

        public static string T(string german, string english)
        {
            return _english ? english : german;
        }

        public static LocalizedText L(string german, string english)
        {
            return new LocalizedText(german, english);
        }

        public static LocalizedText L(string text)
        {
            return new LocalizedText(text, text);
        }

        public static string Code
        {
            get { return _english ? English : German; }
            set
            {
                if (!IsSupported(value))
                    throw new ArgumentException("Unsupported language: " + value, nameof(value));

                _english = value == English;
            }
        }

        public static bool IsEnglish
        { get { return _english; } }

        public static CultureInfo Culture
        { get { return CultureInfo.GetCultureInfo(_english ? "en-US" : "de-DE"); } }
    }

    public sealed class LocalizedText
    {
        readonly string _german;
        readonly string _english;

        public LocalizedText(string? german, string? english)
        {
            _german = german ?? string.Empty;
            _english = english ?? string.Empty;
        }

        public static LocalizedText operator +(LocalizedText? a, LocalizedText? b)
        {
            if (a is null)
                return b ?? new LocalizedText(null, null);

            if (b is null)
                return a;

            return new LocalizedText(a._german + b._german, a._english + b._english);
        }

        public static LocalizedText operator +(LocalizedText? a, string? b)
        {
            return a + new LocalizedText(b, b);
        }

        public static LocalizedText operator +(string? a, LocalizedText? b)
        {
            return new LocalizedText(a, a) + b;
        }

        public override string ToString()
        {
            return Lang.IsEnglish ? _english : _german;
        }

        public string German
        { get { return _german; } }

        public string English
        { get { return _english; } }
    }

    public class LocalizedException : Exception
    {
        readonly LocalizedText _text;

        public LocalizedException(LocalizedText text)
            : base(text.German)
        {
            _text = text;
        }

        public LocalizedException(LocalizedText text, Exception innerException)
            : base(text.German, innerException)
        {
            _text = text;
        }

        public static LocalizedText TextOf(Exception ex)
        {
            if (ex is LocalizedException localized)
                return localized._text;

            return new LocalizedText(ex.Message, ex.Message);
        }

        public override string Message
        { get { return _text.ToString(); } }

        public LocalizedText Text
        { get { return _text; } }
    }
}
