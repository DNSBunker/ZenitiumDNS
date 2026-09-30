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
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using ZenitiumDns.ApplicationCommon;

namespace ZenitiumDns.Core
{
    sealed partial class LanguageManager
    {
        #region variables

        public const string FOLDER_NAME = "lang";
        const string INDEX_FILE_NAME = "languages.json";
        public const int MAX_FILE_SIZE = 4 * 1024 * 1024;
        const int MAX_NAME_LENGTH = 40;
        const int MAX_VALUE_LENGTH = 8000;
        const int MAX_LANGUAGES = 32;

        readonly string _configFolder;
        readonly Func<string> _getWwwFolder;
        readonly LogManager _log;
        readonly Lock _lock = new Lock();

        Dictionary<string, string> _names = new Dictionary<string, string>(StringComparer.Ordinal);

        DateTime _englishLastModified;
        Dictionary<string, string> _english;
        byte[] _englishBytes;

        readonly Dictionary<string, byte[]> _mergedCache = new Dictionary<string, byte[]>(StringComparer.Ordinal);

        #endregion

        #region constructor

        public LanguageManager(string configFolder, Func<string> getWwwFolder, LogManager log)
        {
            _configFolder = configFolder;
            _getWwwFolder = getWwwFolder;
            _log = log;
        }

        #endregion

        #region private

        [GeneratedRegex("^[a-z]{2,3}(-[A-Za-z0-9]{2,8})?$")]
        private static partial Regex LanguageCodeRegex();

        [GeneratedRegex("<[^<>]*>")]
        private static partial Regex TagRegex();

        [GeneratedRegex("\\{[0-9]+\\}")]
        private static partial Regex PlaceholderRegex();

        private string FolderPath
        { get { return Path.Combine(_configFolder, FOLDER_NAME); } }

        private string GetLanguageFile(string code)
        {
            return Path.Combine(FolderPath, code + ".json");
        }

        private static List<string> GetSortedMatches(Regex regex, string text)
        {
            List<string> matches = new List<string>();

            foreach (Match match in regex.Matches(text))
                matches.Add(match.Value);

            matches.Sort(StringComparer.Ordinal);
            return matches;
        }

        private static int CountChar(string text, char c)
        {
            int count = 0;

            foreach (char ch in text)
            {
                if (ch == c)
                    count++;
            }

            return count;
        }

        private static bool HasSameMarkup(string key, string value)
        {
            if (value.Length > MAX_VALUE_LENGTH)
                return false;

            List<string> keyTags = GetSortedMatches(TagRegex(), key);
            List<string> valueTags = GetSortedMatches(TagRegex(), value);

            if (keyTags.Count != valueTags.Count)
                return false;

            for (int i = 0; i < keyTags.Count; i++)
            {
                if (!keyTags[i].Equals(valueTags[i], StringComparison.Ordinal))
                    return false;
            }

            string keyWithoutTags = TagRegex().Replace(key, "");
            string valueWithoutTags = TagRegex().Replace(value, "");

            if ((CountChar(valueWithoutTags, '<') > CountChar(keyWithoutTags, '<')) || (CountChar(valueWithoutTags, '>') > CountChar(keyWithoutTags, '>')))
                return false;

            List<string> keyPlaceholders = GetSortedMatches(PlaceholderRegex(), key);
            List<string> valuePlaceholders = GetSortedMatches(PlaceholderRegex(), value);

            if (keyPlaceholders.Count != valuePlaceholders.Count)
                return false;

            for (int i = 0; i < keyPlaceholders.Count; i++)
            {
                if (!keyPlaceholders[i].Equals(valuePlaceholders[i], StringComparison.Ordinal))
                    return false;
            }

            return true;
        }

        private Dictionary<string, string> GetEnglishDictionary()
        {
            string file = Path.Combine(_getWwwFolder(), "lang", "en.json");
            DateTime lastModified = File.GetLastWriteTimeUtc(file);

            if ((_english is null) || (lastModified != _englishLastModified))
            {
                byte[] bytes = File.ReadAllBytes(file);
                Dictionary<string, string> english = JsonSerializer.Deserialize<Dictionary<string, string>>(bytes) ?? new Dictionary<string, string>();

                _english = english;
                _englishBytes = bytes;
                _englishLastModified = lastModified;
                _mergedCache.Clear();
            }

            return _english;
        }

        private void SaveIndex()
        {
            Directory.CreateDirectory(FolderPath);

            string file = Path.Combine(FolderPath, INDEX_FILE_NAME);
            string tmpFile = file + ".tmp";

            File.WriteAllBytes(tmpFile, JsonSerializer.SerializeToUtf8Bytes(_names));
            File.Move(tmpFile, file, true);
        }

        #endregion

        #region public

        public static bool IsBuiltIn(string code)
        {
            return (code == Lang.German) || (code == Lang.English);
        }

        public void Load()
        {
            lock (_lock)
            {
                Dictionary<string, string> names = new Dictionary<string, string>(StringComparer.Ordinal);
                string indexFile = Path.Combine(FolderPath, INDEX_FILE_NAME);

                if (File.Exists(indexFile))
                {
                    try
                    {
                        Dictionary<string, string> stored = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllBytes(indexFile));

                        if (stored is not null)
                        {
                            foreach (KeyValuePair<string, string> entry in stored)
                            {
                                if (LanguageCodeRegex().IsMatch(entry.Key) && !IsBuiltIn(entry.Key) && File.Exists(GetLanguageFile(entry.Key)))
                                    names[entry.Key] = entry.Value ?? entry.Key;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _log.Write("Web Service failed to load the imported languages: " + indexFile, ex);
                    }
                }

                _names = names;
                _mergedCache.Clear();
            }
        }

        public bool IsAvailable(string code)
        {
            if (code is null)
                return false;

            if (IsBuiltIn(code))
                return true;

            lock (_lock)
            {
                return _names.ContainsKey(code);
            }
        }

        public IReadOnlyList<KeyValuePair<string, string>> GetImportedLanguages()
        {
            lock (_lock)
            {
                List<KeyValuePair<string, string>> languages = new List<KeyValuePair<string, string>>(_names);
                languages.Sort(delegate (KeyValuePair<string, string> x, KeyValuePair<string, string> y) { return string.Compare(x.Value, y.Value, StringComparison.OrdinalIgnoreCase); });
                return languages;
            }
        }

        public byte[] GetDictionary(string code)
        {
            lock (_lock)
            {
                try
                {
                    GetEnglishDictionary();

                    if (code == Lang.English)
                        return _englishBytes;

                    if (!_names.ContainsKey(code))
                        return "{}"u8.ToArray();

                    if (_mergedCache.TryGetValue(code, out byte[] cached))
                        return cached;

                    Dictionary<string, string> merged = new Dictionary<string, string>(_english, StringComparer.Ordinal);
                    Dictionary<string, string> imported = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllBytes(GetLanguageFile(code))) ?? new Dictionary<string, string>();

                    foreach (KeyValuePair<string, string> entry in imported)
                    {
                        if (merged.ContainsKey(entry.Key) && (entry.Value is not null) && HasSameMarkup(entry.Key, entry.Value))
                            merged[entry.Key] = entry.Value;
                    }

                    byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(merged);
                    _mergedCache[code] = bytes;
                    return bytes;
                }
                catch (Exception ex)
                {
                    _log.Write("Web Service failed to load the dictionary for language: " + code, ex);
                    return "{}"u8.ToArray();
                }
            }
        }

        public ImportResult Import(string code, string name, Stream stream)
        {
            code = (code ?? "").Trim();
            name = (name ?? "").Trim();

            if (!LanguageCodeRegex().IsMatch(code))
                throw new DnsWebServiceException(Lang.T("Der Sprachcode muss aus 2 oder 3 Kleinbuchstaben bestehen, optional mit Region, z. B. fr oder pt-BR.", "The language code must consist of 2 or 3 lowercase letters, optionally with a region, for example fr or pt-BR."));

            if (IsBuiltIn(code))
                throw new DnsWebServiceException(Lang.T("Deutsch und Englisch sind fest eingebaut und können nicht ersetzt werden.", "German and English are built in and cannot be replaced."));

            if ((name.Length == 0) || (name.Length > MAX_NAME_LENGTH) || (name.IndexOfAny(['<', '>', '"', '&']) >= 0))
                throw new DnsWebServiceException(Lang.T("Der Name der Sprache muss 1 bis 40 Zeichen lang sein und darf keine der Zeichen < > \" & enthalten.", "The language name must be 1 to 40 characters long and cannot contain any of the characters < > \" &."));

            byte[] data;

            using (MemoryStream mS = new MemoryStream())
            {
                byte[] buffer = new byte[65536];
                int read;

                while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    if (mS.Length + read > MAX_FILE_SIZE)
                        throw new DnsWebServiceException(Lang.T("Die Sprachdatei darf höchstens 4 MB groß sein.", "The language file cannot exceed 4 MB."));

                    mS.Write(buffer, 0, read);
                }

                data = mS.ToArray();
            }

            Dictionary<string, JsonElement> parsed;

            try
            {
                parsed = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(data);
            }
            catch (JsonException ex)
            {
                throw new DnsWebServiceException(Lang.T("Die Sprachdatei ist kein gültiges JSON-Objekt.", "The language file is not a valid JSON object."), ex);
            }

            if (parsed is null)
                throw new DnsWebServiceException(Lang.T("Die Sprachdatei ist kein gültiges JSON-Objekt.", "The language file is not a valid JSON object."));

            lock (_lock)
            {
                Dictionary<string, string> english = GetEnglishDictionary();
                Dictionary<string, string> accepted = new Dictionary<string, string>(StringComparer.Ordinal);
                int unknown = 0;
                int rejected = 0;

                foreach (KeyValuePair<string, JsonElement> entry in parsed)
                {
                    if (!english.ContainsKey(entry.Key))
                    {
                        unknown++;
                        continue;
                    }

                    if (entry.Value.ValueKind != JsonValueKind.String)
                    {
                        rejected++;
                        continue;
                    }

                    string value = entry.Value.GetString();

                    if (string.IsNullOrWhiteSpace(value) || !HasSameMarkup(entry.Key, value))
                    {
                        rejected++;
                        continue;
                    }

                    accepted[entry.Key] = value;
                }

                if (accepted.Count == 0)
                    throw new DnsWebServiceException(Lang.T("Die Sprachdatei enthält keine verwendbare Übersetzung. Als Schlüssel dienen die deutschen Originaltexte wie in lang/en.json.", "The language file contains no usable translation. The keys are the original German texts as in lang/en.json."));

                if (!_names.ContainsKey(code) && (_names.Count >= MAX_LANGUAGES))
                    throw new DnsWebServiceException(Lang.T("Es können höchstens 32 Sprachen importiert werden.", "At most 32 languages can be imported."));

                Directory.CreateDirectory(FolderPath);

                string file = GetLanguageFile(code);
                string tmpFile = file + ".tmp";

                File.WriteAllBytes(tmpFile, JsonSerializer.SerializeToUtf8Bytes(accepted, new JsonSerializerOptions() { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }));
                File.Move(tmpFile, file, true);

                _names[code] = name;
                _mergedCache.Remove(code);
                SaveIndex();

                return new ImportResult(code, name, accepted.Count, english.Count, rejected, unknown);
            }
        }

        public bool Delete(string code)
        {
            lock (_lock)
            {
                if (!_names.Remove(code))
                    return false;

                _mergedCache.Remove(code);

                try
                {
                    File.Delete(GetLanguageFile(code));
                }
                catch (Exception ex)
                {
                    _log.Write(ex);
                }

                SaveIndex();
                return true;
            }
        }

        #endregion

        public sealed record ImportResult(string Code, string Name, int Translated, int Total, int Rejected, int Unknown);
    }
}
