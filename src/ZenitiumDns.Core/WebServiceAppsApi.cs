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

using ZenitiumDns.ApplicationCommon;
using ZenitiumDns.Core.Auth;
using ZenitiumDns.Core.Dns.Applications;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;

namespace ZenitiumDns.Core
{
    public partial class DnsWebService
    {
        sealed class WebServiceAppsApi
        {
            #region variables

            readonly DnsWebService _dnsWebService;

            #endregion

            #region constructor

            public WebServiceAppsApi(DnsWebService dnsWebService)
            {
                _dnsWebService = dnsWebService;
            }

            #endregion

            #region private

            private static void WriteAppAsJson(Utf8JsonWriter jsonWriter, DnsApplication application)
            {
                jsonWriter.WriteStartObject();

                jsonWriter.WriteString("name", application.Name);
                jsonWriter.WriteString("description", application.Description);
                jsonWriter.WriteString("version", DnsWebService.GetCleanVersion(application.Version));
                jsonWriter.WriteBoolean("enabled", application.Enabled);

                jsonWriter.WritePropertyName("dnsApps");
                {
                    jsonWriter.WriteStartArray();

                    foreach (KeyValuePair<string, IDnsApplication> dnsApp in application.DnsApplications)
                    {
                        jsonWriter.WriteStartObject();

                        jsonWriter.WriteString("classPath", dnsApp.Key);
                        jsonWriter.WriteString("description", dnsApp.Value.Description);

                        if (dnsApp.Value is IDnsAppRecordRequestHandler appRecordHandler)
                        {
                            jsonWriter.WriteBoolean("isAppRecordRequestHandler", true);
                            jsonWriter.WriteString("recordDataTemplate", appRecordHandler.ApplicationRecordDataTemplate);
                        }
                        else
                        {
                            jsonWriter.WriteBoolean("isAppRecordRequestHandler", false);
                        }

                        jsonWriter.WriteBoolean("isRequestController", dnsApp.Value is IDnsRequestController);
                        jsonWriter.WriteBoolean("isAuthoritativeRequestHandler", dnsApp.Value is IDnsAuthoritativeRequestHandler);
                        jsonWriter.WriteBoolean("isRequestBlockingHandler", dnsApp.Value is IDnsRequestBlockingHandler);
                        jsonWriter.WriteBoolean("isQueryLogger", dnsApp.Value is IDnsQueryLogger);
                        jsonWriter.WriteBoolean("isQueryLogs", dnsApp.Value is IDnsQueryLogs);
                        jsonWriter.WriteBoolean("isPostProcessor", dnsApp.Value is IDnsPostProcessor);

                        jsonWriter.WriteEndObject();
                    }

                    jsonWriter.WriteEndArray();
                }

                jsonWriter.WriteEndObject();
            }

            #endregion

            #region public

            public void ListInstalledApps(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (
                    !_dnsWebService._authManager.IsPermitted(PermissionSection.Apps, sessionUser, PermissionFlag.View) &&
                    !_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.View) &&
                    !_dnsWebService._authManager.IsPermitted(PermissionSection.Logs, sessionUser, PermissionFlag.View)
                   )
                {
                    throw new DnsWebServiceException("Access was denied.");
                }

                List<string> apps = new List<string>(_dnsWebService._dnsServer.DnsApplicationManager.Applications.Keys);
                apps.Sort();

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                jsonWriter.WritePropertyName("apps");
                jsonWriter.WriteStartArray();

                foreach (string app in apps)
                {
                    if (_dnsWebService._dnsServer.DnsApplicationManager.Applications.TryGetValue(app, out DnsApplication application))
                        WriteAppAsJson(jsonWriter, application);
                }

                jsonWriter.WriteEndArray();
            }

            public async Task SetAppEnabledAsync(HttpContext context, bool enabled)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Apps, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                string name = context.Request.GetQueryOrForm("name").Trim();

                DnsApplication application = await _dnsWebService._dnsServer.DnsApplicationManager.SetApplicationEnabledAsync(name, enabled);

                _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + sessionUser.Username + "] DNS application '" + name + "' was " + (enabled ? "enabled" : "disabled") + " successfully.");

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                jsonWriter.WritePropertyName("updatedApp");
                WriteAppAsJson(jsonWriter, application);
            }

            public async Task GetAppConfigAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Apps, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string name = request.GetQueryOrForm("name").Trim();

                if (!_dnsWebService._dnsServer.DnsApplicationManager.Applications.TryGetValue(name, out DnsApplication application))
                    throw new DnsWebServiceException("DNS application was not found: " + name);

                string config = await application.GetConfigAsync();

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                jsonWriter.WriteString("config", config);
            }

            public async Task SetAppConfigAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Apps, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string name = request.GetQueryOrForm("name").Trim();

                if (!_dnsWebService._dnsServer.DnsApplicationManager.Applications.TryGetValue(name, out DnsApplication application))
                    throw new DnsWebServiceException("DNS application was not found: " + name);

                string config = request.QueryOrForm("config");
                if (config is null)
                    throw new DnsWebServiceException("Parameter 'config' missing.");

                if (config.Length == 0)
                {
                    config = null;
                }
                else
                {
                    try
                    {
                        using JsonDocument jsonDocument = JsonDocument.Parse(config, new JsonDocumentOptions() { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
                    }
                    catch (JsonException ex)
                    {
                        throw new DnsWebServiceException("The app config is not valid JSON: " + ex.Message);
                    }
                }

                await application.SetConfigAsync(config);

                _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + sessionUser.Username + "] DNS application '" + name + "' app config was saved successfully.");

            }

            #endregion
        }
    }
}
