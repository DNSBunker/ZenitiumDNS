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
using System.Threading;
using ZenitiumDns.ApplicationCommon;

namespace ZenitiumDns.Core.Auth
{
    sealed class UserPreferencesManager
    {
        #region variables

        public const string FILE_NAME = "userprefs.json";
        public const int MAX_SIZE = 65536;

        readonly string _configFolder;
        readonly LogManager _log;
        readonly Lock _lock = new Lock();

        Dictionary<string, string> _preferences = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        #endregion

        #region constructor

        public UserPreferencesManager(string configFolder, LogManager log)
        {
            _configFolder = configFolder;
            _log = log;
        }

        #endregion

        #region private

        private string FilePath
        { get { return Path.Combine(_configFolder, FILE_NAME); } }

        private void SaveInternal()
        {
            string tmpFile = FilePath + ".tmp";

            using (FileStream fS = new FileStream(tmpFile, FileMode.Create, FileAccess.Write))
            {
                using (Utf8JsonWriter jsonWriter = new Utf8JsonWriter(fS))
                {
                    jsonWriter.WriteStartObject();

                    foreach (KeyValuePair<string, string> entry in _preferences)
                    {
                        jsonWriter.WritePropertyName(entry.Key);
                        jsonWriter.WriteRawValue(entry.Value, true);
                    }

                    jsonWriter.WriteEndObject();
                }
            }

            File.Move(tmpFile, FilePath, true);
        }

        #endregion

        #region public

        public static string Validate(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
                return "{}";

            if (Encoding.UTF8.GetByteCount(json) > MAX_SIZE)
                throw new DnsWebServiceException(Lang.T("Die persönlichen Einstellungen dürfen höchstens 64 KB groß sein.", "Personal preferences cannot exceed 64 KB."));

            try
            {
                using (JsonDocument document = JsonDocument.Parse(json, new JsonDocumentOptions() { MaxDepth = 16 }))
                {
                    if (document.RootElement.ValueKind != JsonValueKind.Object)
                        throw new DnsWebServiceException(Lang.T("Die persönlichen Einstellungen müssen ein JSON-Objekt sein.", "Personal preferences must be a JSON object."));

                    return document.RootElement.GetRawText();
                }
            }
            catch (JsonException ex)
            {
                throw new DnsWebServiceException(Lang.T("Die persönlichen Einstellungen sind kein gültiges JSON.", "Personal preferences are not valid JSON."), ex);
            }
        }

        public void Load()
        {
            string file = FilePath;

            lock (_lock)
            {
                Dictionary<string, string> preferences = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

                if (File.Exists(file))
                {
                    try
                    {
                        using (FileStream fS = new FileStream(file, FileMode.Open, FileAccess.Read))
                        {
                            using (JsonDocument document = JsonDocument.Parse(fS))
                            {
                                if (document.RootElement.ValueKind == JsonValueKind.Object)
                                {
                                    foreach (JsonProperty property in document.RootElement.EnumerateObject())
                                    {
                                        if (property.Value.ValueKind == JsonValueKind.Object)
                                            preferences[property.Name] = property.Value.GetRawText();
                                    }
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _log.Write("DNS Server failed to load personal preferences file: " + file, ex);
                    }
                }

                _preferences = preferences;
            }
        }

        public string Get(string username)
        {
            lock (_lock)
            {
                if (_preferences.TryGetValue(username, out string json))
                    return json;

                return "{}";
            }
        }

        public void Set(string username, string json)
        {
            string validated = Validate(json);

            lock (_lock)
            {
                if (validated == "{}")
                    _preferences.Remove(username);
                else
                    _preferences[username] = validated;

                SaveInternal();
            }
        }

        public void Remove(string username)
        {
            lock (_lock)
            {
                if (_preferences.Remove(username))
                    SaveInternal();
            }
        }

        public void Rename(string oldUsername, string newUsername)
        {
            lock (_lock)
            {
                if (!_preferences.Remove(oldUsername, out string json))
                    return;

                _preferences[newUsername] = json;
                SaveInternal();
            }
        }

        #endregion
    }
}
