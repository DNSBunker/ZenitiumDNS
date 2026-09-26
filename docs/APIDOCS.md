# ZenitiumDNS API Documentation

ZenitiumDNS provides a HTTP API which is used by the web console to perform all actions. Thus any action that the web console does can be performed using this API from your own applications.

The URL in the documentation uses `localhost` and port `5380`. You should use the hostname/IP address and port that is specific to your DNS server instance.

## API Request

Unless it is explicitly specified, all HTTP API requests can use both `GET` or `POST` methods. When using `POST` method to pass the API parameters as form data, the `Content-Type` header must be set to `application/x-www-form-urlencoded`. When the HTTP API call is used to upload files, the call must use `POST` method and the `Content-Type` header must be set to `multipart/form-data`.

Note! The "set" type of API requests will overwrite any existing value managed by that call. The "add" type of API requests will append to existing value managed by the call.

## API Authentication

Starting from version 15.0, the HTTP API requires passing bearer session token using the `Authorization` header for all requests that require a user to login. The same header is required when using an API token.

The request header must be as shown below:

`Authorization: Bearer <token>`

The session token can also be passed as a query string or form data `token` parameter which is supported for backward compatibility reasons.

## API Response Format

The HTTP API returns a JSON formatted response for all requests. The JSON object returned contains `status` property which indicate if the request was successful. 

The `status` property can have following values:
- `ok`: This indicates that the call was successful.
- `error`: This response tells the call failed and provides additional properties that provide details about the error.
- `invalid-token`: When a session has expired or an invalid token was provided this response is received.
- `2fa-required`: When a user has two-factor authentication enabled and the OTP was not provided during login, change password, etc. API calls.

A successful response will look as shown below. Note that there will be other properties in the response which are specific to the request that was made.

```
{
	"status": "ok"
}
```

In case of errors, the response will look as shown below. The `errorMessage` property can be shown in the UI to the user while the other two properties are useful for debugging.

```
{
	"status": "error",
	"errorMessage": "error message",
	"stackTrace": "application stack trace",
	"innerErrorMessage": "inner exception message"
}
```

## Name Server Address Format

The DNS server uses a specific text format to define the name server address to allow specifying multiple parameters like the domain name, IP address, port or URL. This format is used in the web console as well as in this API. It is used to specify forwarder address in DNS settings, conditional forwarder zone's FWD record, or the server address in DNS Client resolve query API calls.

- A name server address with just an IP address is specified just as its string literal with optional port number is as shown: `1.1.1.1` or `8.8.8.8:53`. When port is not specified, the default port number for the selected DNS transport protocol is used.
- A name server address with just a domain name is specified similarly as its string literal with optional port number is as shown: `dns.quad9.net:853` or `cloudflare-dns.com`. When port is not specified, the default port number for the selected DNS transport protocol is used.
- A combination of domain name and IP address together with optional port number is as shown: `cloudflare-dns.com (1.1.1.1)`, `dns.quad9.net (9.9.9.9:853)` or `dns.quad9.net:853 (9.9.9.9)`. Here, the domain name (with optional port number) is specified and the IP address (with optional port number) is specified in a round bracket. When port is not specified, the default port number for the selected DNS transport protocol is used. This allows the DNS server to use the specified IP address instead of trying to resolve it separately.
- A name server address that specifies a DNS-over-HTTPS URL is specified just as its string literal is as shown: `https://cloudflare-dns.com/dns-query`
- A combination of DNS-over-HTTPS URL and IP address together is as shown: `https://cloudflare-dns.com/dns-query (1.1.1.1)`. Here, the IP address of the domain name in the URL is specified in the round brackets. This allows the DNS server to use the specified IP address instead of trying to resolve it separately.
- IPv6 addresses must always be enclosed in square brackets when port is specified as shown: `cloudflare-dns.com ([2606:4700:4700::1111]:853)` or `[2606:4700:4700::1111]:853`

## User API Calls

These API calls allow to a user to login, logout, perform account management, etc. Once logged in, a session token is returned which MUST be used with all other API calls.

### Status

This call returns generic API status information.

URL:\
`http://localhost:5380/api/status`

PERMISSIONS:\
None

Response:
```
{
	"hasDefaultCredentials": false,
	"ssoEnabled": false,
	"server": "server1",
	"status": "ok"
}
```

### Login

This call authenticates with the server and generates a session token to be used for subsequent API calls. The session token expires as per the user's session expiry timeout value (default 30 minutes) from the last API call.

URL:\
`http://localhost:5380/api/user/login?user=admin&pass=admin&includeInfo=true`

PERMISSIONS:\
None

WHERE:
- `user`: The username for the user account. The built-in administrator username on the DNS server is `admin`.
- `pass`: The password for the user account. The default password for `admin` user is `admin`. 
- `totp` (optional): The time-based one-time password for the user account if it has Two Factor Authentication (2FA) enabled.
- `includeInfo` (optional): Includes basic info relevant for the user in response.

WARNING: It is highly recommended to change the password on first use to avoid security related issues.

RESPONSE:
```
{
	"displayName": "Administrator",
	"username": "admin",
	"isSsoUser": false,
	"totpEnabled": false,
	"token": "932b2a3495852c15af01598f62563ae534460388b6a370bfbbb8bb6094b698e9",
	"info": {
		"version": "15.0",
		"dnsServerDomain": "server1",
		"defaultRecordTtl": 3600,
		"defaultNsRecordTtl": 14400,
		"defaultSoaRecordTtl": 900,
		"permissions": {
			"Dashboard": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Zones": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Cache": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Allowed": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Blocked": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Apps": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"DnsClient": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Settings": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Administration": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Logs": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			}
		}
	},
	"status": "ok"
}
```

WHERE:
- `token`: Is the session token generated that MUST be used with all subsequent API calls.

### Create API Token

Allows creating a non-expiring API token that can be used with automation scripts to make API calls. The token allows access to API calls with the same privileges as that of the user account. Thus its recommended to create a separate user account with limited permissions as required by the specific task that the token will be used for. The token cannot be used to change the user's password, or update the user profile details.

URL:\
`http://localhost:5380/api/user/createToken?user=admin&pass=admin&tokenName=MyToken1`

PERMISSIONS:\
None

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token` (optional): The session token generated only by the `login` call.
- `user` (optional): The username for the user account for which to generate the API token.
- `pass` (optional): The password for the user account.
- `totp` (optional): The time-based one-time password for the user account if it has Two Factor Authentication (2FA) enabled.
- `tokenName`: The name of the created token to identify its session.

NOTE! You can either use a valid session token with `Authorization` header or use the `user`, `pass`, and `totp` (if required) parameters instead to authenticate.

RESPONSE:
```
{
	"username": "admin",
	"tokenName": "MyToken1",
	"token": "932b2a3495852c15af01598f62563ae534460388b6a370bfbbb8bb6094b698e9",
	"status": "ok"
}
```

WHERE:
- `token`: Is the session token generated that MUST be used with all subsequent API calls.

### Create Single Use API Token

Allows creating a single use API token such that it can be used only once with any API call and expires immediately on use. It shares the same properties as that of the API token.

URL:\
`http://localhost:5380/api/user/createSingleUseToken`

PERMISSIONS:\
none

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated only by the `login` call.

RESPONSE:
```
{
	"username": "admin",
	"token": "932b2a3495852c15af01598f62563ae534460388b6a370bfbbb8bb6094b698e9",
	"status": "ok"
}
```

### Logout

This call ends the session generated by the `login` or the `createToken` call. The `token` would no longer be valid after calling the `logout` API.

URL:\
`http://localhost:5380/api/user/logout`

PERMISSIONS:\
None

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"status": "ok"
}
```

### Get Session Info

Returns the same info as that of the `login` or the `createToken` calls for the session specified by the token.

URL:\
`http://localhost:5380/api/user/session/get`

PERMISSIONS:\
None

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"displayName": "Administrator",
	"username": "admin",
	"type": "Local",
	"isSsoUser": false,
	"totpEnabled": false,
	"token": "e9460eb997299f2fbbb7a09a57319cf22b295af8af60d89cff556b81e5ce9903",
	"info": {
		"version": "15.5",
		"uptimestamp": "2026-09-26T01:44:40.0001384Z",
		"dnsServerDomain": "server1.example.com",
		"defaultRecordTtl": 3600,
		"defaultNsRecordTtl": 14400,
		"defaultSoaRecordTtl": 900,
		"dnssecValidation": false,
		"permissions": {
			"Dashboard": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Zones": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Cache": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Allowed": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Blocked": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Apps": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"DnsClient": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Settings": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Administration": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Logs": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			}
		}
	},
	"status": "ok"
}
```

### Delete User Session

Allows deleting a session for the current user.

URL:\
`http://localhost:5380/api/user/session/delete?partialToken=620c3bfcd09d0a07`

PERMISSIONS:\
None

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `partialToken`: The partial token as returned by the user profile details API call.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

### Change Password

Allows changing the password for the current logged in user account.

NOTE: It is highly recommended to change the `admin` user password on first use to avoid security related issues.

URL:\
`http://localhost:5380/api/user/changePassword?pass=password&newPass=newpassword`

PERMISSIONS:\
None

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated only by the `login` call.
- `pass`: The current password for the currently logged in user.
- `newPass`: The new password to be set for the currently logged in user.
- `totp` (optional): The 6-digit code from the authenticator app if the user has 2FA enabled.
- `iterations` (optional): The number of iterations for PBKDF2 SHA256 password hashing.

RESPONSE:
```
{
	"status": "ok"
}
```

### Initialize 2FA

Initializes two-factor authentication for the current logged in user account. The secret returned by this API call needs to be used with authenticator apps like microsoft Authenticator or Google Authenticator. This call is the first step to enable 2FA followed by calling the Enable 2FA API call.

URL:\
`http://localhost:5380/api/user/2fa/init`

PERMISSIONS:\
None

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated only by the `login` call.

RESPONSE:
```
{
	"response": {
		"totpEnabled": false,
		"qrCodePngImage": "iVBORw0KGgoAAAANSUhEU...",
		"secret": "RZ56CYOXKAXI5D23"
	},
	"status": "ok"
}
```

### Enable 2FA

Enables two-factor authentication for the current logged in user account. This API call can be called only after the Initialize 2FA API call.

URL:\
`http://localhost:5380/api/user/2fa/enable`

PERMISSIONS:\
None

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated only by the `login` call.
- `totp`: The 6-digit code from the authenticator app.

RESPONSE:
```
{
	"status": "ok"
}
```

### Disable 2FA

Disables two-factor authentication for the current logged in user account.

URL:\
`http://localhost:5380/api/user/2fa/disable`

PERMISSIONS:\
None

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated only by the `login` call.

RESPONSE:
```
{
	"status": "ok"
}
```

### Get User Profile Details

Gets the user account profile details.

URL:\
`http://localhost:5380/api/user/profile/get`

PERMISSIONS:\
None

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"response": {
		"displayName": "Administrator",
		"username": "admin",
	    "isSsoUser": false,
		"totpEnabled": false,
		"disabled": false,
		"previousSessionLoggedOn": "2022-09-15T12:59:05.944Z",
		"previousSessionRemoteAddress": "127.0.0.1",
		"recentSessionLoggedOn": "2022-09-15T13:57:50.1843973Z",
		"recentSessionRemoteAddress": "127.0.0.1",
		"sessionTimeoutSeconds": 1800,
		"memberOfGroups": [
			"Administrators"
		],
		"sessions": [
			{
				"username": "admin",
				"isCurrentSession": true,
				"partialToken": "620c3bfcd09d0a07",
				"type": "Standard",
				"tokenName": null,
				"lastSeen": "2022-09-15T13:58:02.4728Z",
				"lastSeenRemoteAddress": "127.0.0.1",
				"lastSeenUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0"
			}
		]
	},
	"status": "ok"
}
```

### Set User Profile Details

Allows changing user account profile values.

URL:\
`http://localhost:5380/api/user/profile/set?displayName=Administrator&sessionTimeoutSeconds=1800`

PERMISSIONS:\
None

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated only by the `login` call.
- `displayName` (optional): The display name to set for the user account. For SSO users, the display name is managed by SSO provider and cannot be changed with this API call.
- `sessionTimeoutSeconds` (optional): The session timeout value to set in seconds for the user account.

RESPONSE:
```
{
	"response": {
		"displayName": "Administrator",
		"username": "admin",
		"isSsoUser": false,
		"totpEnabled": false,
		"disabled": false,
		"previousSessionLoggedOn": "2022-09-15T12:59:05.944Z",
		"previousSessionRemoteAddress": "127.0.0.1",
		"recentSessionLoggedOn": "2022-09-15T13:57:50.1843973Z",
		"recentSessionRemoteAddress": "127.0.0.1",
		"sessionTimeoutSeconds": 1800,
		"memberOfGroups": [
			"Administrators"
		],
		"sessions": [
			{
				"username": "admin",
				"isCurrentSession": true,
				"partialToken": "620c3bfcd09d0a07",
				"type": "Standard",
				"tokenName": null,
				"lastSeen": "2022-09-15T14:00:50.288738Z",
				"lastSeenRemoteAddress": "127.0.0.1",
				"lastSeenUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0"
			}
		]
	},
	"status": "ok"
}
```

### Check For Update

This call requests the server to check for software update.

URL:\
`http://localhost:5380/api/user/checkForUpdate`

PERMISSIONS:\
None

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"response": {
		"updateAvailable": true,
		"updateVersion": "9.0",
		"currentVersion": "8.1.4",
		"updateTitle": "New Update Available!",
		"updateMessage": "Follow the instructions from the link below to update the DNS server to the latest version. Read the change logs before installing the update to know if there are any breaking changes.",
		"downloadLink": "https://example.com/zenitiumdns/ZenitiumDnsSetup.zip",
		"instructionsLink": "https://example.com/zenitiumdns/install.html",
		"changeLogLink": "https://example.com/zenitiumdns/CHANGELOG.md"
	},
	"status": "ok"
}
```

## Dashboard API Calls

These API calls provide access to dashboard stats and allow deleting stat files.

### Get Metrics (JSON)

Returns lifetime counters, live response time summaries and the current server status in JSON format.

URL\:
`http://localhost:5380/api/dashboard/metrics/json`

PERMISSIONS:\
Dashboard: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"response": {
		"uptimestamp": "2026-09-26T01:42:05.3304591Z",
		"uptimeSeconds": 66,
		"lifetimeCounters": {
			"totalQueries": 66,
			"totalNoError": 35,
			"totalServerFailure": 0,
			"totalNxDomain": 31,
			"totalRefused": 0,
			"totalAuthoritative": 0,
			"totalRecursive": 3,
			"totalCached": 33,
			"totalBlocked": 30,
			"totalDropped": 0,
			"totalClients": 1
		},
		"responseTime5Minutes": {
			"minutes": 5,
			"count": 66,
			"queriesPerSecond": 0.26,
			"average": 1.49,
			"median": 0.14,
			"p95": 3.27,
			"p99": 67,
			"max": 79.79,
			"cachedAverage": 0.19,
			"recursiveAverage": 28.75
		},
		"responseTime60Minutes": {
			"minutes": 60,
			"count": 66,
			"queriesPerSecond": 0.02,
			"average": 1.49,
			"median": 0.14,
			"p95": 3.27,
			"p99": 67,
			"max": 79.79,
			"cachedAverage": 0.19,
			"recursiveAverage": 28.75
		},
		"cachedEntries": 6,
		"serverStatus": {
			"uptimeSeconds": 66,
			"ipv6Mode": "Disabled",
			"ipv6UpstreamAvailable": false,
			"enableBlocking": true,
			"dnssecValidation": false,
			"forwarding": false
		}
	},
	"status": "ok"
}
```

WHERE:
- `lifetimeCounters`: Counters since the DNS server was started.
- `responseTime5Minutes`, `responseTime60Minutes`: Response time summaries over the last 5 and 60 minutes, measured from receiving a request until its response is sent. `queriesPerSecond` is the answered query rate over the window, `average`, `median`, `p95`, `p99` and `max` are in milliseconds. Percentiles are interpolated from a histogram and never exceed `max`. `cachedAverage` and `recursiveAverage` are the averages for answers served from the cache and answers that needed recursive resolution or forwarding.
- `cachedEntries`: Number of records in the DNS cache.
- `serverStatus`: The current status of the DNS server (see `Get Stats`).

### Get Metrics (Prometheus Text Format)

Returns lifetime counters, cache size, IPv6 upstream state and live query rate and response time gauges of the DNS Server in Prometheus text format.

URL\:
`http://localhost:5380/api/dashboard/metrics/text`

PERMISSIONS:\
Dashboard: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
Response data is in Prometheus text format with `Content-Type: text/plain; version=0.0.4`.

```
# HELP uptime_seconds Uptime of the DNS Server in seconds
# TYPE uptime_seconds gauge
uptime_seconds 66
# HELP start_time Start time of the DNS Server since epoch (milliseconds)
# TYPE start_time gauge
start_time 1790386925330
# TYPE queries_total counter
queries_total 66
# TYPE no_error_total counter
no_error_total 35
# TYPE server_failure_total counter
server_failure_total 0
# TYPE nx_domain_total counter
nx_domain_total 31
# TYPE refused_total counter
refused_total 0
# TYPE authoritative_total counter
authoritative_total 0
# TYPE recursive_total counter
recursive_total 3
# TYPE cached_total counter
cached_total 33
# TYPE blocked_total counter
blocked_total 30
# TYPE dropped_total counter
dropped_total 0
# TYPE clients_total counter
clients_total 1
# HELP cache_entries Number of records in the DNS cache
# TYPE cache_entries gauge
cache_entries 6
# HELP ipv6_upstream_available Whether outbound IPv6 queries to name servers are currently used (1) or suspended (0)
# TYPE ipv6_upstream_available gauge
ipv6_upstream_available 0
# HELP queries_per_second Answered queries per second over the window
# TYPE queries_per_second gauge
# HELP response_time_milliseconds Response time of answered queries over the window
# TYPE response_time_milliseconds gauge
queries_per_second{window="1m"} 0.458
response_time_milliseconds{window="1m",stat="avg"} 0.683
response_time_milliseconds{window="1m",stat="p50"} 0.156
response_time_milliseconds{window="1m",stat="p95"} 3.062
response_time_milliseconds{window="1m",stat="p99"} 3.062
response_time_milliseconds{window="1m",stat="cached_avg"} 0.088
response_time_milliseconds{window="1m",stat="recursive_avg"} 3.062
queries_per_second{window="5m"} 0.263
response_time_milliseconds{window="5m",stat="avg"} 1.494
response_time_milliseconds{window="5m",stat="p50"} 0.14
response_time_milliseconds{window="5m",stat="p95"} 3.275
response_time_milliseconds{window="5m",stat="p99"} 67
response_time_milliseconds{window="5m",stat="cached_avg"} 0.194
response_time_milliseconds{window="5m",stat="recursive_avg"} 28.751
queries_per_second{window="60m"} 0.019
response_time_milliseconds{window="60m",stat="avg"} 1.494
response_time_milliseconds{window="60m",stat="p50"} 0.14
response_time_milliseconds{window="60m",stat="p95"} 3.275
response_time_milliseconds{window="60m",stat="p99"} 67
response_time_milliseconds{window="60m",stat="cached_avg"} 0.194
response_time_milliseconds{window="60m",stat="recursive_avg"} 28.751
```

The metrics `queries_per_second` and `response_time_milliseconds` are provided with a `window` label for the last 1, 5 and 60 minutes. `response_time_milliseconds` additionally has a `stat` label with the values `avg`, `p50`, `p95`, `p99`, `cached_avg` and `recursive_avg`.

### Get Stats

Returns the DNS stats that are displayed on the web console dashboard.

URL:\
`http://localhost:5380/api/dashboard/stats/get?type=LastHour&utc=true`

PERMISSIONS:\
Dashboard: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `type` (optional): The duration type for which valid values are: [`LastHour`, `LastDay`, `LastWeek`, `LastMonth`, `LastYear`, `Custom`]. Default value is `LastHour`.
- `utc` (optional): Set to `true` to return the main chart data with labels in UTC date time format using which the labels can be converted into local time for display using the received `labelFormat`.
- `dontTrimQueryTypeData` (optional): Set to `true` to get full data for query type chart instead of top 10 entries. Default value is `false` when unspecified.
- `start` (optional): The start date in ISO 8601 format. Applies only to `custom` type.
- `end` (optional): The end date in ISO 8601 format. Applies only to `custom` type.

RESPONSE:
```
{
	"response": {
		"stats": {
			"totalQueries": 61,
			"totalNoError": 30,
			"totalServerFailure": 0,
			"totalNxDomain": 31,
			"totalRefused": 0,
			"totalAuthoritative": 0,
			"totalRecursive": 2,
			"totalCached": 29,
			"totalBlocked": 30,
			"totalDropped": 0,
			"totalClients": 1,
			"zones": 1,
			"cachedEntries": 6,
			"allowedZones": 0,
			"blockedZones": 1,
			"allowListZones": 0,
			"blockListZones": 0
		},
		"live": {
			"minutes": 5,
			"count": 66,
			"queriesPerSecond": 0.26,
			"average": 1.49,
			"median": 0.14,
			"p95": 3.27,
			"p99": 67,
			"max": 79.79,
			"cachedAverage": 0.19,
			"recursiveAverage": 28.75
		},
		"lastHourResponseTime": {
			"minutes": 60,
			"count": 66,
			"queriesPerSecond": 0.02,
			"average": 1.49,
			"median": 0.14,
			"p95": 3.27,
			"p99": 67,
			"max": 79.79,
			"cachedAverage": 0.19,
			"recursiveAverage": 28.75
		},
		"responseTimeChartData": {
			"average": [
				0,
				0,
				1.56
			],
			"p95": [
				0,
				0,
				2.95
			]
		},
		"serverStatus": {
			"uptimeSeconds": 66,
			"ipv6Mode": "Disabled",
			"ipv6UpstreamAvailable": false,
			"enableBlocking": true,
			"dnssecValidation": false,
			"forwarding": false
		},
		"mainChartData": {
			"labelFormat": "HH:mm",
			"labels": [
				"2026-09-26T01:41:00.0000000Z",
				"2026-09-26T01:42:00.0000000Z",
				"2026-09-26T01:43:00.0000000Z"
			],
			"datasets": [
				{
					"label": "Total",
					"data": [
						0,
						0,
						61
					]
				},
				{
					"label": "No Error",
					"data": [
						0,
						0,
						30
					]
				},
				{
					"label": "Server Failure",
					"data": [
						0,
						0,
						0
					]
				},
				{
					"label": "NX Domain",
					"data": [
						0,
						0,
						31
					]
				}
			]
		},
		"queryResponseChartData": {
			"labels": [
				"Authoritative",
				"Recursive",
				"Cached",
				"Blocked",
				"Dropped"
			],
			"datasets": [
				{
					"data": [
						0,
						2,
						29,
						30,
						0
					]
				}
			]
		},
		"queryTypeChartData": {
			"labels": [
				"A"
			],
			"datasets": [
				{
					"data": [
						61
					]
				}
			]
		},
		"protocolTypeChartData": {
			"labels": [
				"Udp"
			],
			"datasets": [
				{
					"data": [
						61
					]
				}
			]
		},
		"topClients": [
			{
				"name": "127.0.0.1",
				"domain": "localhost",
				"hits": 61,
				"rateLimited": false
			}
		],
		"topDomains": [
			{
				"name": "www.example.zt",
				"hits": 30
			}
		],
		"topBlockedDomains": [
			{
				"name": "ads.example.zt",
				"hits": 30
			}
		]
	},
	"status": "ok"
}
```

The example above is shortened: the arrays in `mainChartData` and `responseTimeChartData` contain one entry per minute, hour, day or month of the selected period, and `mainChartData.datasets` contains one dataset per series (`Total`, `No Error`, `Server Failure`, `NX Domain`, `Refused`, `Authoritative`, `Recursive`, `Cached`, `Blocked`, `Dropped`, `Clients`). The datasets contain no color information; the client chooses the colors.

WHERE:
- `stats`: The totals for the selected period together with the current number of zones, cache entries, allowed and blocked domains and block list entries.
- `live`: Response time summary over the last 5 minutes, independent of the selected period. The fields are described in `Get Metrics (JSON)`.
- `lastHourResponseTime`: Response time summary over the last 60 minutes. Returned only for `LastHour`.
- `responseTimeChartData`: Average and 95th percentile response time in milliseconds per minute of the last hour, aligned with `mainChartData.labels`. A value of `0` means no query was answered in that minute. Returned only for `LastHour`.
- `serverStatus`: The current status of the DNS server:
  - `uptimeSeconds`: Seconds since the DNS server was started.
  - `ipv6Mode`: The configured IPv6 mode for outbound queries (`Disabled`, `Enabled` or `Preferred`).
  - `ipv6UpstreamAvailable`: `true` while outbound IPv6 queries are used, `false` while IPv6 is disabled or suspended by the automatic fallback.
  - `ipv6UpstreamUnavailableUntil` (optional): Time in UTC until which IPv6 is suspended.
  - `enableBlocking`: `true` when blocking is enabled.
  - `temporaryDisableBlockingTill` (optional): Time in UTC until which blocking is temporarily disabled.
  - `dnssecValidation`: `true` when DNSSEC validation is enabled.
  - `forwarding`: `true` when forwarders are configured, `false` when the server resolves recursively from the root servers.

The totals and charts include only completed minutes. The current minute is added when the minute ends, while `live`, `lastHourResponseTime` and `serverStatus` are live values.

### Get Top Stats

Returns the top stats data for specified stats type.

URL:\
`http://localhost:5380/api/dashboard/stats/getTop?type=LastHour&statsType=TopClients&limit=1000`

PERMISSIONS:\
Dashboard: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `type` (optional): The duration type for which valid values are: [`LastHour`, `LastDay`, `LastWeek`, `LastMonth`, `LastYear`, `custom`]. Default value is `LastHour`.
- `start` (optional): The start date in ISO 8601 format. Applies only to `custom` type.
- `end` (optional): The end date in ISO 8601 format. Applies only to `custom` type.
- `statsType`: The stats type for which valid values are : [`TopClients`, `TopDomains`, `TopBlockedDomains`]
- `limit` (optional): The limit of records to return. Default value is `1000`.
- `noReverseLookup` (optional): Set to `true` to disable reverse lookup for Top Clients list. This option is only applicable with `TopClients` stats type.
- `onlyRateLimitedClients` (optional): Set to `true` to list only clients which are being rate limited in the Top Clients list. This option is only applicable with `TopClients` stats type.

RESPONSE:
The response json will include the object with definition same in the `getStats` response depending on the `statsType`. For example below is the response for `TopClients`:
```
{
	"response": {
		"topClients": [
			{
				"name": "192.168.10.5",
				"domain": "server1.local",
				"hits": 236,
				"rateLimited": false
			},
			{
				"name": "192.168.10.4",
				"domain": "nas1.local",
				"hits": 16,
				"rateLimited": false
			},
			{
				"name": "192.168.10.6",
				"domain": "server2.local",
				"hits": 14,
				"rateLimited": false
			},
			{
				"name": "192.168.10.3",
				"domain": "nas2.local",
				"hits": 12,
				"rateLimited": false
			},
			{
				"name": "217.31.193.175",
				"domain": "condor175.knot-resolver.cz",
				"hits": 10,
				"rateLimited": false
			},
			{
				"name": "162.158.180.45",
				"hits": 9,
				"rateLimited": false
			},
			{
				"name": "217.31.193.163",
				"domain": "gondor-resolver.labs.nic.cz",
				"hits": 9,
				"rateLimited": false
			},
			{
				"name": "210.245.24.68",
				"hits": 8,
				"rateLimited": false
			},
			{
				"name": "101.91.16.140",
				"hits": 8,
				"rateLimited": false
			}
		],
	},
	"status": "ok"
}
```

### Delete All Stats

Permanently delete all hourly and daily stats files from the disk and clears all stats stored in memory. This call will clear all stats from the Dashboard.

URL:\
`http://localhost:5380/api/dashboard/stats/deleteAll`

PERMISSIONS:\
Dashboard: Delete

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

### Probe IPv6 Upstream

Checks right away whether name servers are reachable over IPv6 by querying a few IPv6 root servers, and updates the automatic IPv6 fallback state. The DNS server also runs this check every two minutes in the background. A failed check suspends outbound IPv6 queries for 10 minutes, a successful one resumes them.

URL:\
`http://localhost:5380/api/dashboard/ipv6/probe?reset=true`

PERMISSIONS:\
Settings: Modify

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `reset` (optional): Set to `true` to clear the current suspension and failure counters before probing. Default value is `false`.

RESPONSE:
```
{
	"response": {
		"serverStatus": {
			"uptimeSeconds": 66,
			"ipv6Mode": "Enabled",
			"ipv6UpstreamAvailable": true,
			"enableBlocking": true,
			"dnssecValidation": false,
			"forwarding": false
		}
	},
	"status": "ok"
}
```

WHERE:
- `serverStatus`: The server status after the check, as described in `Get Stats`.

An error is returned when `ipv6Mode` is `Disabled`.

## Zone API Calls

These API calls manage the Conditional Forwarder zones on the DNS server. ZenitiumDNS is built as a public recursive resolver and does not host authoritative zones: a Conditional Forwarder zone forwards all queries for the zone name and its subdomains to the configured forwarders (FWD records), and can additionally hold local records that override the forwarded answers. Zone files of other zone types (Primary, Secondary, Stub, Catalog) found in the config folder are skipped when the server starts.

### List Zones

List all Conditional Forwarder zones on this DNS server. The list contains only the zones that the user has View permissions for. These API calls requires permission for both the Zones section as well as the individual permission for each zone.

URL:\
`http://localhost:5380/api/zones/list?pageNumber=1&zonesPerPage=10`

PERMISSIONS:\
Zones: View\
Zone: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `filterName` (optional): The string to use to filter zones by name. The filter string can use `*` as wildcard option to select zero or more characters, and `?` option to select exactly one wildcard character. The filter name can be a string in unicode format to filter for IDN names.
- `filterType` (optional): The zone type to filter. The only valid option is `Forwarder`.
- `pageNumber` (optional): When this parameter is specified, the API will return paginated results based on the page number and zones per pages options. When not specified, the API will return a list of all zones.
- `zonesPerPage` (optional): The number of zones per page to be returned. This option is only used when `pageNumber` options is specified. The default value is `10` when not specified.

RESPONSE:
```
{
	"response": {
		"pageNumber": 1,
		"totalPages": 1,
		"totalZones": 2,
		"zones": [
			{
				"name": "corp.example",
				"type": "Forwarder",
				"lastModified": "2026-09-26T01:44:41.9595921Z",
				"disabled": false
			},
			{
				"name": "home.arpa",
				"type": "Forwarder",
				"lastModified": "2026-09-26T01:44:41.9373336Z",
				"disabled": false
			}
		]
	},
	"status": "ok"
}
```

### Create Zone

Creates a new Conditional Forwarder zone.

URL:\
`http://localhost:5380/api/zones/create?zone=corp.example&type=Forwarder&protocol=Tls&forwarder=dns.corp.example:853&dnssecValidation=true`

PERMISSIONS:\
Zones: Modify

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `zone`: The domain name for creating the new zone. The value can be valid domain name, an IP address, or an network address in CIDR format. When value is IP address or network address, a reverse zone is created.
- `type` (optional): The type of zone to be created. The only valid value is `Forwarder`, which is also the default. Any other zone type is rejected with an error.
- `initializeForwarder` (optional): Set value as `true` to initialize the zone with an FWD record or set it to `false` to create an empty zone. Default value is `true`.
- `protocol` (optional): The DNS transport protocol used to reach the forwarder. Valid values are [`Udp`, `Tcp`, `Tls`, `Https`, `Quic`]. Default value is `Udp`.
- `forwarder` (optional): The address of the DNS server to be used as a forwarder. This parameter is required when `initializeForwarder` is `true`. The special value `this-server` resolves the zone recursively on this DNS server, which allows overriding only some records of a zone.
- `dnssecValidation` (optional): Set this boolean value to indicate if DNSSEC validation must be done for answers from this forwarder. Setting it to `false` creates a Negative Trust Anchor for the zone.
- `proxyType` (optional): The type of proxy that must be used for conditional forwarding. Valid values are [`NoProxy`, `DefaultProxy`, `Http`, `Socks5`]. Default value is `DefaultProxy`.
- `proxyAddress` (optional): The proxy server address to use when `proxyType` is `Http` or `Socks5`.
- `proxyPort` (optional): The proxy server port to use when `proxyType` is `Http` or `Socks5`.
- `proxyUsername` (optional): The proxy server username to use when `proxyType` is `Http` or `Socks5`.
- `proxyPassword` (optional): The proxy server password to use when `proxyType` is `Http` or `Socks5`.

REQUEST: To import a zone file while creating the zone, use POST request with multi-part form data containing the zone file data.

RESPONSE:
```
{
	"response": {
		"domain": "corp.example"
	},
	"status": "ok"
}
```

WHERE:
- `domain`: Will contain the zone that was created. This is specifically useful to know the reverse zone that was created.

### Import Zone

Imports a set of DNS resource records in standard RFC 1035 zone file format into an existing Conditional Forwarder zone. SOA records and DNSSEC records in the imported data are ignored.

URL:\
`http://localhost:5380/api/zones/import?zone=corp.example&overwrite=true`

PERMISSIONS:\
Zones: Modify\
Zone: Modify

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `zone`: The domain name of the zone to import into.
- `overwrite` (optional): Set to `true` to allow overwriting existing resource record set for the records being imported. Default value when unspecified is `true`.
- `overwriteZone` (optional): Set to `true` to delete all existing records from the zone before importing new records. Default value when unspecified is `false`.
- `records` (optional): The zone file data as a form field, as an alternative to the request body.

REQUEST: This is a POST request call where the request must use `text/plain` content type with request body containing the zone file data OR the request must be multi-part form data with the zone file data.

RESPONSE:
```
{
	"status": "ok"
}
```

### Export Zone

Exports the complete zone in standard RFC 1035 zone file format.

URL:\
`http://localhost:5380/api/zones/export?zone=example.com`

PERMISSIONS:\
Zones: View
Zone: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `zone`: The domain name of the zone to export.

RESPONSE: Response is a downloadable text file with `Content-Type: text/plain` and `Content-Disposition: attachment`.

### Clone Zone

Clones an existing zone with all the records to create a new zone.

URL:\
`http://localhost:5380/api/zones/clone?zone=example.com&sourceZone=template.com`

PERMISSIONS:\
Zones: Modify
Zone: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `zone`: The domain name of the zone to be created.
- `sourceZone`: The domain name of the zone to be cloned.

RESPONSE:
```
{
	"status": "ok"
}
```

### Enable Zone

Enables a zone.

URL:\
`http://localhost:5380/api/zones/enable?zone=example.com`

PERMISSIONS:\
Zones: Modify\
Zone: Modify

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `zone`: The domain name of the zone to be enabled.

RESPONSE:
```
{
	"status": "ok"
}
```

### Disable Zone

Disables a zone. This will prevent the DNS server from responding for queries to this zone.

URL:\
`http://localhost:5380/api/zones/disable?zone=example.com`

PERMISSIONS:\
Zones: Modify\
Zone: Modify

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `zone`: The domain name of the zone to be disabled.

RESPONSE:
```
{
	"status": "ok"
}
```

### Delete Zone

Deletes a zone.

URL:\
`http://localhost:5380/api/zones/delete?zone=example.com`

PERMISSIONS:\
Zones: Delete\
Zone: Delete

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `zone`: The domain name of the zone to be deleted.
- `zones` (optional): A comma separated list of domain names of zones to be deleted. The `zone` parameter will be ignored when this parameter is used.

RESPONSE (single zone delete):
```
{
	"status": "ok"
}
```

RESPONSE (multi zone delete):
```
{
	"response": {
		"deleted": [
			"example1.com"
		],
		"failed": {
			"example2.com": "No such zone was found: example2.com"
		}
	},
	"server": "server1",
	"status": "ok"
}
```

### Get Zone Options

Gets the zone specific options.

URL:\
`http://localhost:5380/api/zones/options/get?zone=corp.example`

PERMISSIONS:\
Zones: Modify\
Zone: Modify

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `zone`: The domain name of the zone to get options.

RESPONSE:
```
{
	"response": {
		"name": "corp.example",
		"type": "Forwarder",
		"disabled": false,
		"queryAccess": "UseSpecifiedNetworkACL",
		"queryAccessNetworkACL": [
			"192.168.0.0/16",
			"!0.0.0.0/0"
		]
	},
	"status": "ok"
}
```

### Set Zone Options

Sets the zone specific options.

URL:\
`http://localhost:5380/api/zones/options/set?zone=corp.example&queryAccess=UseSpecifiedNetworkACL&queryAccessNetworkACL=192.168.0.0/16,!0.0.0.0/0`

PERMISSIONS:\
Zones: Modify\
Zone: Delete

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `zone`: The domain name of the zone to set options.
- `disabled` (optional): Sets if the zone is enabled or disabled.
- `queryAccess` (optional): Sets who may query the zone. Valid options are [`Deny`, `Allow`, `AllowOnlyPrivateNetworks`, `UseSpecifiedNetworkACL`]. Clients that are not allowed receive `REFUSED`. Queries from loopback addresses and internal queries of the DNS server are always allowed.
- `queryAccessNetworkACL` (optional): A comma separated Access Control List (ACL) of Network Access Control (NAC) entries. A NAC entry is an IP address or network address to allow; prefix it with `!` to deny. The entries are evaluated in the given order and a client that matches no entry is denied. Set to `false` to clear the list. This option is used when `queryAccess` is `UseSpecifiedNetworkACL`.

RESPONSE:
```
{
	"status": "ok"
}
```

### Get Zone Permissions

Gets the zone specific permissions.

URL:\
`http://localhost:5380/api/zones/permissions/get?zone=example.com&includeUsersAndGroups=true`

PERMISSIONS:\
Zones: Modify\
Zone: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `zone`: The domain name of the zone to get the permissions for.
- `includeUsersAndGroups`: Set to true to get a list of users and groups in the response.

RESPONSE:
```
{
	"response": {
		"section": "Zones",
		"subItem": "example.com",
		"userPermissions": [
			{
				"username": "admin",
				"canView": true,
				"canModify": true,
				"canDelete": true
			}
		],
		"groupPermissions": [
			{
				"name": "Administrators",
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			{
				"name": "DNS Administrators",
				"canView": true,
				"canModify": true,
				"canDelete": true
			}
		],
		"users": [
			"admin",
			"shreyas"
		],
		"groups": [
			"Administrators",
			"DNS Administrators",
			"Everyone"
		]
	},
	"status": "ok"
}
```

### Set Zone Permissions

Sets the zone specific permissions.

URL:\
`http://localhost:5380/api/zones/permissions/set?zone=example.com&userPermissions=admin|true|true|true&groupPermissions=Administrators|true|true|true|DNS%20Administrators|true|true|true`

PERMISSIONS:\
Zones: Modify\
Zone: Delete

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `zone`: The domain name of the zone to get the permissions for.
- `userPermissions` (optional): A pipe `|` separated table data with each row containing username and boolean values for the view, modify and delete permissions. For example: user1|true|true|true|user2|true|false|false
- `groupPermissions` (optional): A pipe `|` separated table data with each row containing the group name and boolean values for the view, modify and delete permissions. For example: group1|true|true|true|group2|true|true|false

RESPONSE:
```
{
	"response": {
		"section": "Zones",
		"subItem": "example.com",
		"userPermissions": [
			{
				"username": "admin",
				"canView": true,
				"canModify": true,
				"canDelete": true
			}
		],
		"groupPermissions": [
			{
				"name": "Administrators",
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			{
				"name": "DNS Administrators",
				"canView": true,
				"canModify": true,
				"canDelete": true
			}
		]
	},
	"status": "ok"
}
```

### Add Record

Adds a resource record to a Conditional Forwarder zone. Records added to the zone override the answers of the forwarder for the same name and type.

URL:\
`http://localhost:5380/api/zones/records/add?domain=example.com&zone=example.com`

PERMISSIONS:\
Zones: None\
Zone: Modify

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `domain`: The domain name of the zone to add record.
- `zone` (optional): The name of the zone into which the `domain` exists. When unspecified, the closest zone will be used.
- `type`: The DNS resource record type. Supported record types are [`A`, `AAAA`, `NS`, `CNAME`, `PTR`, `MX`, `TXT`, `RP`, `SRV`, `NAPTR`, `DNAME`, `SSHFP`, `TLSA`, `SVCB`, `HTTPS`, `URI`, `CAA`] and proprietary types [`ANAME`, `FWD`, `APP`]. Unknown record types are also supported. `SOA` and DNSSEC record types (`DS`, `DNSKEY`, `RRSIG`, `NSEC`, `NSEC3`, `NSEC3PARAM`) cannot be added.
- `ttl` (optional): The DNS resource record TTL value. This is the value in seconds that the DNS resolvers can cache the record for. When not specified the default TTL value from settings will be used.
- `overwrite` (optional): This option when set to `true` will overwrite existing resource record set for the selected `type` with the new record. Default value of `false` will add the new record into existing resource record set.
- `comments` (optional): Sets comments for the added resource record.
- `expiryTtl` (optional): Set to automatically delete the record when the value in seconds elapses since the record’s last modified time.
- `ipAddress` (optional): The IP address for adding `A` or `AAAA` record. A special value of `request-ip-address` can be used to set the record with the IP address of the API HTTP request to help with dynamic DNS update applications. This option is required and used only for `A` and `AAAA` records.
- `ptr` (optional): Set this option to `true` to add a reverse PTR record for the IP address in the `A` or `AAAA` record. This option is used only for `A` and `AAAA` records.
- `updateSvcbHints` (optional): Set this option to `true` to update any SVCB/HTTPS records in the zone that has Automatic Hints option enabled and matches its target name with the current record's domain name. This option is used for `A` and `AAAA` records.
- `nameServer` (optional): The name server domain name. This option is required for adding `NS` record.
- `glue` (optional): This is the glue address for the name server in the `NS` record. This optional parameter is used for adding `NS` record.
- `cname` (optional): The CNAME domain name. This option is required for adding `CNAME` record.
- `ptrName` (optional): The PTR domain name. This option is required for adding `PTR` record.
- `exchange` (optional): The exchange domain name. This option is required for adding `MX` record.
- `preference` (optional): This is the preference value for `MX` record type. This option is required for adding `MX` record.
- `characterStringsBase64` (optional): A comma separated list of character-strings in base64 encoding for adding `TXT` record.
- `text` (optional): The text data for `TXT` record. This option is required for adding `TXT` record when `characterStringsBase64` is not used.
- `splitText` (optional): Set to `true` for using new line char to split text into multiple character-strings for adding `TXT` record when `characterStringsBase64` is not used.
- `mailbox` (optional): Set an email address for adding `RP` record.
- `txtDomain` (optional): Set a `TXT` record's domain name for adding `RP` record.
- `priority` (optional): This parameter is required for adding the `SRV` record.
- `weight` (optional): This parameter is required for adding the `SRV` record.
- `port` (optional): This parameter is required for adding the `SRV` record.
- `target` (optional): This parameter is required for adding the `SRV` record.
- `naptrOrder` (optional): This parameter is required for adding the `NAPTR` record.
- `naptrPreference` (optional): This parameter is required for adding the `NAPTR` record.
- `naptrFlags` (optional): This parameter is required for adding the `NAPTR` record.
- `naptrServices` (optional): This parameter is required for adding the `NAPTR` record.
- `naptrRegexp` (optional): This parameter is required for adding the `NAPTR` record.
- `naptrReplacement` (optional): This parameter is required for adding the `NAPTR` record.
- `dname` (optional): The DNAME domain name. This option is required for adding `DNAME` record.
- `sshfpAlgorithm` (optional): Valid values are [`RSA`, `DSA`, `ECDSA`, `Ed25519`, `Ed448`]. This parameter is required for adding `SSHFP` record.
- `sshfpFingerprintType` (optional): Valid values are [`SHA1`, `SHA256`]. This parameter is required for adding `SSHFP` record.
- `sshfpFingerprint` (optional): A hex string value. This parameter is required for adding `SSHFP` record.
- `tlsaCertificateUsage` (optional): Valid values are [`PKIX-TA`, `PKIX-EE`, `DANE-TA`, `DANE-EE`]. This parameter is required for adding `TLSA` record.
- `tlsaSelector` (optional): Valid values are [`Cert`, `SPKI`]. This parameter is required for adding `TLSA` record.
- `tlsaMatchingType` (optional): Valid value are [`Full`, `SHA2-256`, `SHA2-512`]. This parameter is required for adding `TLSA` record.
- `tlsaCertificateAssociationData` (optional): A X509 certificate in PEM format or a hex string value. This parameter is required for adding `TLSA` record.
- `svcPriority` (optional): The priority value for `SVCB` or `HTTPS` record. This parameter is required for adding `SCVB` or `HTTPS` record.
- `svcTargetName` (optional): The target domain name for `SVCB` or `HTTPS` record. This parameter is required for adding `SCVB` or `HTTPS` record.
- `svcParams` (optional): The service parameters for `SVCB` or `HTTPS` record which is a pipe separated list of key and value. For example, `alpn|h2,h3|port|53443`. To clear existing values, set it to `false`. This parameter is required for adding `SCVB` or `HTTPS` record.
- `autoIpv4Hint` (optional): Set this option to `true` to enable Automatic Hints for the `ipv4hint` parameter in the `svcParams`. This option is valid only for `SVCB` and `HTTPS` records.
- `autoIpv6Hint` (optional): Set this option to `true` to enable Automatic Hints for the `ipv6hint` parameter in the `svcParams`. This option is valid only for `SVCB` and `HTTPS` records.
- `uriPriority` (optional): The priority value for adding the `URI` record.
- `uriWeight` (optional): The weight value for adding the `URI` record.
- `uri` (optional): The URI value for adding the `URI` record.
- `flags` (optional): This parameter is required for adding the `CAA` record.
- `tag` (optional): This parameter is required for adding the `CAA` record.
- `value` (optional): This parameter is required for adding the `CAA` record.
- `aname` (optional): The ANAME domain name. This option is required for adding `ANAME` record.
- `protocol` (optional): This parameter is required for adding the `FWD` record. Valid values are [`Udp`, `Tcp`, `Tls`, `Https`, `Quic`].
- `forwarder` (optional): The forwarder address. A special value of `this-server` can be used to directly forward requests internally to the DNS server. This parameter is required for adding the `FWD` record.
- `forwarderPriority` (optional): Set an integer priority value for adding the `FWD` record. Forwarders with high priority (lower value) will be queried before trying for low priority forwarders. Forwarders with the same priority will be concurrently queried.
- `dnssecValidation` (optional): Set this boolean value to indicate if DNSSEC validation must be done. This optional parameter is to be used with FWD records. Default value is `false`.
- `proxyType` (optional): The type of proxy that must be used for conditional forwarding. This optional parameter is to be used with FWD records. Valid values are [`NoProxy`, `DefaultProxy`, `Http`, `Socks5`]. Default value `DefaultProxy` is used when this parameter is missing.
- `proxyAddress` (optional): The proxy server address to use when `proxyType` is configured. This optional parameter is to be used with FWD records.
- `proxyPort` (optional): The proxy server port to use when `proxyType` is configured. This optional parameter is to be used with FWD records.
- `proxyUsername` (optional): The proxy server username to use when `proxyType` is configured. This optional parameter is to be used with FWD records.
- `proxyPassword` (optional): The proxy server password to use when `proxyType` is configured. This optional parameter is to be used with FWD records.
- `appName` (optional): The name of the DNS app. This parameter is required for adding the `APP` record.
- `classPath` (optional): This parameter is required for adding the `APP` record.
- `recordData` (optional): This parameter is used for adding the `APP` record as per the DNS app requirements.
- `rdata` (optional): This parameter is used for adding unknown i.e. unsupported record types. The value must be formatted as a hex string or a colon separated hex string.

RESPONSE:
```
{
	"response": {
		"zone": {
			"name": "example.com",
			"type": "Forwarder",
			"lastModified": "2026-09-26T01:44:41.9595921Z",
			"disabled": false
		},
		"addedRecord": {
			"disabled": false,
			"name": "example.com",
			"type": "A",
			"ttl": 3600,
			"rData": {
				"ipAddress": "3.3.3.3"
			},
			"dnssecStatus": "Unknown",
			"lastUsedOn": "0001-01-01T00:00:00"
		}
	},
	"status": "ok"
}
```

### Get Records

Gets all records for a given zone. The response also lists the internal SOA record of the zone, which exists only for technical reasons and cannot be changed.

URL:\
`http://localhost:5380/api/zones/records/get?domain=example.com&zone=example.com&listZone=true`

PERMISSIONS:\
Zones: None\
Zone: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `domain`: The domain name of the zone to get records.
- `zone` (optional): The name of the zone into which the `domain` exists. When unspecified, the closest zone will be used.
- `listZone` (optional): When set to `true` will list all records in the zone else will list records only for the given domain name. Default value is `false` when not specified.

RESPONSE:
```
{
	"response": {
		"zone": {
			"name": "corp.example",
			"type": "Forwarder",
			"lastModified": "2026-09-26T01:44:41.9595921Z",
			"disabled": false
		},
		"records": [
			{
				"name": "corp.example",
				"type": "SOA",
				"ttl": 0,
				"ttlString": "0s",
				"disabled": false,
				"rData": {
					"primaryNameServer": "katana",
					"responsiblePerson": "invalid",
					"serial": 1,
					"refresh": 900,
					"retry": 300,
					"expire": 604800,
					"minimum": 900,
					"refreshString": "15m",
					"retryString": "5m",
					"expireString": "1w",
					"minimumString": "15m"
				},
				"dnssecStatus": "Unknown",
				"lastUsedOn": "0001-01-01T00:00:00",
				"lastModified": "2026-09-26T01:44:41.9206365Z",
				"expiryTtl": 0,
				"expiryTtlString": "0s"
			},
			{
				"name": "corp.example",
				"type": "TXT",
				"ttl": 3600,
				"ttlString": "1h",
				"disabled": false,
				"rData": {
					"text": "v=spf1 -all",
					"splitText": false,
					"characterStrings": [
						"v=spf1 -all"
					],
					"characterStringsBase64": [
						"dj1zcGYxIC1hbGw="
					]
				},
				"dnssecStatus": "Unknown",
				"lastUsedOn": "0001-01-01T00:00:00",
				"lastModified": "2026-09-26T01:44:41.9595125Z",
				"expiryTtl": 0,
				"expiryTtlString": "0s"
			},
			{
				"name": "corp.example",
				"type": "FWD",
				"ttl": 0,
				"ttlString": "0s",
				"disabled": false,
				"rData": {
					"protocol": "Tls",
					"forwarder": "dns.corp.example:853",
					"priority": 0,
					"dnssecValidation": true,
					"proxyType": "NoProxy"
				},
				"dnssecStatus": "Unknown",
				"lastUsedOn": "0001-01-01T00:00:00",
				"lastModified": "2026-09-26T01:44:41.9206239Z",
				"expiryTtl": 0,
				"expiryTtlString": "0s"
			},
			{
				"name": "intranet.corp.example",
				"type": "A",
				"ttl": 300,
				"ttlString": "5m",
				"disabled": false,
				"rData": {
					"ipAddress": "192.168.10.5"
				},
				"dnssecStatus": "Unknown",
				"lastUsedOn": "0001-01-01T00:00:00",
				"lastModified": "2026-09-26T01:44:41.9487518Z",
				"expiryTtl": 0,
				"expiryTtlString": "0s"
			}
		]
	},
	"status": "ok"
}
```

### Update Record

Updates an existing record in a zone.

URL:\
`http://localhost:5380/api/zones/records/update?domain=mail.example.com&zone=example.com&type=A&value=127.0.0.1&newValue=127.0.0.2&ptr=false`

PERMISSIONS:\
Zones: None\
Zone: Modify

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `domain`: The domain name of the zone to update the record.
- `zone` (optional): The name of the zone into which the `domain` exists. When unspecified, the closest zone will be used.
- `type`: The type of the resource record to update.
- `newDomain` (optional): The new domain name to be set for the record. To be used to rename sub domain name of the record.
- `ttl` (optional): The TTL value of the resource record. Default value of `3600` is used when parameter is missing.
- `disable` (optional): Specifies if the record should be disabled. The default value is `false` when this parameter is missing.
- `comments` (optional): Sets comments for the updated resource record.
- `expiryTtl` (optional): Set to automatically delete the record when the value in seconds elapses since the record’s last modified time.
- `ipAddress` (optional): The current IP address in the `A` or `AAAA` record. This parameter is required when updating `A` or `AAAA` record.
- `newIpAddress` (optional): The new IP address in the `A` or `AAAA` record. This parameter when missing will use the current value in the record.
- `ptr` (optional): Set this option to `true` to specify if the PTR record associated with the `A` or `AAAA` record must also be updated. This option is used only for `A` and `AAAA` records.
- `updateSvcbHints` (optional): Set this option to `true` to update any SVCB/HTTPS records in the zone that has Automatic Hints option enabled and matches its target name with the current record's domain name. This option is used for `A` and `AAAA` records.
- `nameServer` (optional): The current name server domain name. This option is required for updating `NS` record.
- `newNameServer` (optional): The new server domain name. This option is used for updating `NS` record.
- `glue` (optional): The comma separated list of IP addresses set as glue for the NS record. This parameter is used only when updating `NS` record.
- `cname` (optional): The CNAME domain name to update in the existing `CNAME` record.
- `primaryNameServer` (optional): This is the primary name server parameter in the SOA record. This parameter is required when updating the SOA record.
- `responsiblePerson` (optional): This is the responsible person parameter in the SOA record. This parameter is required when updating the SOA record.
- `serial` (optional): This is the serial parameter in the SOA record. This parameter is required when updating the SOA record.
- `refresh` (optional): This is the refresh parameter in the SOA record. This parameter is required when updating the SOA record.
- `retry` (optional): This is the retry parameter in the SOA record. This parameter is required when updating the SOA record.
- `expire` (optional): This is the expire parameter in the SOA record. This parameter is required when updating the SOA record.
- `minimum` (optional): This is the minimum parameter in the SOA record. This parameter is required when updating the SOA record.
- `ptrName`(optional): The current PTR domain name. This option is required for updating `PTR` record.
- `newPtrName`(optional): The new PTR domain name. This option is required for updating `PTR` record.
- `preference` (optional): The current preference value in an MX record. This parameter when missing will default to `1` value. This parameter is used only when updating `MX` record.
- `newPreference` (optional): The new preference value in an MX record. This parameter when missing will use the old value. This parameter is used only when updating `MX` record.
- `exchange` (optional): The current exchange domain name. This option is required for updating `MX` record.
- `newExchange` (optional): The new exchange domain name. This option is required for updating `MX` record.
- `characterStringsBase64` (optional): A comma separated list of character-strings in base64 encoding for current TXT record.
- `newCharacterStringsBase64` (optional): A comma separated list of character-strings in base64 encoding for new TXT record.
- `text` (optional): The current text value. This option is required for updating `TXT` record when `characterStringsBase64` is not used.
- `newText` (optional): The new text value. This option is required for updating `TXT` record when `newCharacterStringsBase64` is not used.
- `splitText` (optional): The current split text value. This option is used for updating `TXT` record when `characterStringsBase64` is not used and is set to `false` when unspecified.
- `newSplitText` (optional): The new split text value. This option is used for updating `TXT` record when `newCharacterStringsBase64` is not used and is set to current split text value when unspecified.
- `mailbox` (optional): The current email address value. This option is required for updating `RP` record.
- `newMailbox` (optional): The new email address value. This option is used for updating `RP` record and is set to the current value when unspecified.
- `txtDomain` (optional): The current TXT record's domain name value. This option is required for updating `RP` record.
- `newTxtDomain` (optional). The new TXT record's domain name value. This option is used for updating `RP` record and is set to the current value when unspecified.
- `priority` (optional): This is the current priority in the SRV record. This parameter is required when updating the `SRV` record.
- `newPriority` (optional): This is the new priority in the SRV record. This parameter when missing will use the old value. This parameter is used when updating the `SRV` record.
- `weight` (optional): This is the current weight in the SRV record. This parameter is required when updating the `SRV` record.
- `newWeight` (optional): This is the new weight in the SRV record. This parameter when missing will use the old value. This parameter is used when updating the `SRV` record.
- `port` (optional): This is the port parameter in the SRV record. This parameter is required when updating the `SRV` record.
- `newPort` (optional): This is the new value of the port parameter in the SRV record. This parameter when missing will use the old value. This parameter is used to update the port parameter in the `SRV` record.
- `target` (optional): The current target value. This parameter is required when updating the `SRV` record.
- `newTarget` (optional): The new target value. This parameter when missing will use the old value. This parameter is required when updating the `SRV` record.
- `naptrOrder` (optional): The current value in the NAPTR record. This parameter is required when updating the `NAPTR` record.
- `naptrNewOrder` (optional): The new value in the NAPTR record. This parameter when missing will use the old value. This parameter is used when updating the `NAPTR` record.
- `naptrPreference` (optional): The current value in the NAPTR record. This parameter is required when updating the `NAPTR` record.
- `naptrNewPreference` (optional): The new value in the NAPTR record. This parameter when missing will use the old value. This parameter is used when updating the `NAPTR` record.
- `naptrFlags` (optional): The current value in the NAPTR record. This parameter is required when updating the `NAPTR` record.
- `naptrNewFlags` (optional): The new value in the NAPTR record. This parameter when missing will use the old value. This parameter is used when updating the `NAPTR` record.
- `naptrServices` (optional): The current value in the NAPTR record. This parameter is required when updating the `NAPTR` record.
- `naptrNewServices` (optional): The new value in the NAPTR record. This parameter when missing will use the old value. This parameter is used when updating the `NAPTR` record.
- `naptrRegexp` (optional): The current value in the NAPTR record. This parameter is required when updating the `NAPTR` record.
- `naptrNewRegexp` (optional): The new value in the NAPTR record. This parameter when missing will use the old value. This parameter is used when updating the `NAPTR` record.
- `naptrReplacement` (optional): The current value in the NAPTR record. This parameter is required when updating the `NAPTR` record.
- `naptrNewReplacement` (optional): The new value in the NAPTR record. This parameter when missing will use the old value. This parameter is used when updating the `NAPTR` record.
- `dname` (optional): The DNAME domain name. This parameter is required when updating the `DNAME` record.
- `sshfpAlgorithm` (optional): This parameter is required when updating `SSHFP` record.
- `newSshfpAlgorithm` (optional): This parameter is required when updating `SSHFP` record.
- `sshfpFingerprintType` (optional): This parameter is required when updating `SSHFP` record.
- `newSshfpFingerprintType` (optional): This parameter is required when updating `SSHFP` record.
- `sshfpFingerprint` (optional): This parameter is required when updating `SSHFP` record.
- `newSshfpFingerprint` (optional): This parameter is required when updating `SSHFP` record.
- `tlsaCertificateUsage` (optional): This parameter is required when updating `TLSA` record.
- `newTlsaCertificateUsage` (optional): This parameter is required when updating `TLSA` record.
- `tlsaSelector` (optional): This parameter is required when updating `TLSA` record.
- `newTlsaSelector` (optional): This parameter is required when updating `TLSA` record.
- `tlsaMatchingType` (optional): This parameter is required when updating `TLSA` record.
- `newTlsaMatchingType` (optional): This parameter is required when updating `TLSA` record.
- `tlsaCertificateAssociationData` (optional): This parameter is required when updating `TLSA` record.
- `newTlsaCertificateAssociationData` (optional): This parameter is required when updating `TLSA` record.
- `svcPriority` (optional): The priority value for `SVCB` or `HTTPS` record. This parameter is required for updating `SCVB` or `HTTPS` record.
- `newSvcPriority` (optional): The new priority value for `SVCB` or `HTTPS` record. This parameter when missing will use the old value. 
- `svcTargetName` (optional): The target domain name for `SVCB` or `HTTPS` record. This parameter is required for updating `SCVB` or `HTTPS` record.
- `newSvcTargetName` (optional): The new target domain name for `SVCB` or `HTTPS` record. This parameter when missing will use the old value. 
- `svcParams` (optional): The service parameters for `SVCB` or `HTTPS` record which is a pipe separated list of key and value. For example, `alpn|h2,h3|port|53443`. To clear existing values, set it to `false`. This parameter is required for updating `SCVB` or `HTTPS` record.
- `newSvcParams` (optional): The new service parameters for `SVCB` or `HTTPS` record which is a pipe separated list of key and value. To clear existing values, set it to `false`. This parameter when missing will use the old value. 
- `autoIpv4Hint` (optional): Set this option to `true` to enable Automatic Hints for the `ipv4hint` parameter in the `newSvcParams`. This option is valid only for `SVCB` and `HTTPS` records.
- `autoIpv6Hint` (optional): Set this option to `true` to enable Automatic Hints for the `ipv6hint` parameter in the `newSvcParams`. This option is valid only for `SVCB` and `HTTPS` records.
- `uriPriority` (optional): The priority value for the `URI` record. This parameter is required for updating the `URI` record.
- `newUriPriority` (optional): The new priority value for the `URI` record. This parameter when missing will use the old value.
- `uriWeight` (optional): The weight value for the `URI` record. This parameter is required for updating the `URI` record.
- `newUriWeight` (optional): The new weight value for the `URI` record. This parameter when missing will use the old value.
- `uri` (optional): The URI value for the `URI` record. This parameter is required for updating the `URI` record.
- `newUri` (optional): The new URI value for the `URI` record. This parameter when missing will use the old value.
- `flags` (optional): This is the flags parameter in the `CAA` record. This parameter is required when updating the `CAA` record.
- `newFlags` (optional): This is the new value of the flags parameter in the `CAA` record. This parameter is used to update the flags parameter in the `CAA` record.
- `tag` (optional): This is the tag parameter in the `CAA` record. This parameter is required when updating the `CAA` record.
- `newTag` (optional): This is the new value of the tag parameter in the `CAA` record. This parameter is used to update the tag parameter in the `CAA` record.
- `value` (optional): The current value in `CAA` record. This parameter is required when updating the `CAA` record.
- `newValue` (optional): The new value in `CAA` record. This parameter is required when updating the `CAA` record.
- `aname` (optional): The current `ANAME` domain name. This parameter is required when updating the `ANAME` record.
- `newAName` (optional): The new `ANAME` domain name. This parameter is required when updating the `ANAME` record.
- `protocol` (optional): This is the current protocol value in the `FWD` record. Valid values are [`Udp`, `Tcp`, `Tls`, `Https`, `Quic`]. This parameter is optional and default value `Udp` will be used when updating the `FWD` record.
- `newProtocol` (optional): This is the new protocol value in the `FWD` record. Valid values are [`Udp`, `Tcp`, `Tls`, `Https`, `Quic`]. This parameter is optional and default value `Udp` will be used when updating the `FWD` record.
- `forwarder` (optional): The current forwarder address. This parameter is required when updating the `FWD` record.
- `newForwarder` (optional): The new forwarder address. This parameter is required when updating the `FWD` record.
- `forwarderPriority` (optional): The current forwarder priority value. This optional parameter is to be used with `FWD` record. When unspecified, the default value of `0` will be used.
- `dnssecValidation` (optional): Set this boolean value to indicate if DNSSEC validation must be done. This optional parameter is to be used with FWD records. Default value is `false`.
- `proxyType` (optional): The type of proxy that must be used for conditional forwarding. This optional parameter is to be used with FWD records. Valid values are [`NoProxy`, `DefaultProxy`, `Http`, `Socks5`]. Default value `DefaultProxy` is used when this parameter is missing.
- `proxyAddress` (optional): The proxy server address to use when `proxyType` is configured. This optional parameter is to be used with FWD records.
- `proxyPort` (optional): The proxy server port to use when `proxyType` is configured. This optional parameter is to be used with FWD records.
- `proxyUsername` (optional): The proxy server username to use when `proxyType` is configured. This optional parameter is to be used with FWD records.
- `proxyPassword` (optional): The proxy server password to use when `proxyType` is configured. This optional parameter is to be used with FWD records.
- `appName` (optional): This parameter is required for updating the `APP` record.
- `classPath` (optional): This parameter is required for updating the `APP` record.
- `recordData` (optional): This parameter is used for updating the `APP` record as per the DNS app requirements.
- `rdata` (optional): This parameter is used for updating unknown i.e. unsupported record types. The value must be formatted as a hex string or a colon separated hex string.
- `newRData` (optional): This parameter is used for updating unknown i.e. unsupported record types. The new value that must be formatted as a hex string or a colon separated hex string.

RESPONSE:
```
{
	"response": {
		"zone": {
			"name": "example.com",
			"type": "Forwarder",
			"lastModified": "2026-09-26T01:44:41.9595921Z",
			"disabled": false
		},
		"updatedRecord": {
			"disabled": false,
			"name": "example.com",
			"type": "SOA",
			"ttl": 900,
			"rData": {
				"primaryNameServer": "server1.home",
				"responsiblePerson": "hostadmin.example.com",
				"serial": 75,
				"refresh": 900,
				"retry": 300,
				"expire": 604800,
				"minimum": 900
			},
			"dnssecStatus": "Unknown",
			"lastUsedOn": "0001-01-01T00:00:00"
		}
	},
	"status": "ok"
}
```

### Delete Record

Deletes a record from a zone.

URL:\
`http://localhost:5380/api/zones/records/delete?domain=example.com&zone=example.com&type=A&value=127.0.0.1`

PERMISSIONS:\
Zones: None\
Zone: Delete

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `domain`: The domain name of the zone to delete the record.
- `zone` (optional): The name of the zone into which the `domain` exists. When unspecified, the closest zone will be used.
- `type`: The type of the resource record to delete.
- `ipAddress` (optional): This parameter is required when deleting `A` or `AAAA` record.
- `updateSvcbHints` (optional): Set this option to `true` to update any SVCB/HTTPS records in the zone that has Automatic Hints option enabled and matches its target name with the current record's domain name. This option is used for `A` and `AAAA` records.
- `nameServer` (optional): This parameter is required when deleting `NS` record.
- `ptrName` (optional): This parameter is required when deleting `PTR` record.
- `preference` (optional): This parameter is required when deleting `MX` record.
- `exchange` (optional): This parameter is required when deleting `MX` record.
- `characterStringsBase64` (optional): A comma separated list of character-strings in base64 encoding for deleting `TXT` record.
- `text` (optional): This parameter is required for deleting `TXT` record when `characterStringsBase64` is not used.
- `splitText` (optional): This parameter is used when deleting `TXT` record when `characterStringsBase64` is not used. Default value is set to `false` when unspecified.
- `mailbox` (optional): Set an email address for deleting `RP` record.
- `txtDomain` (optional): Set a `TXT` record's domain name for deleting `RP` record.
- `priority` (optional): This parameter is required when deleting the `SRV` record.
- `weight` (optional): This parameter is required when deleting the `SRV` record.
- `port` (optional): This parameter is required when deleting the `SRV` record.
- `target` (optional): This parameter is required when deleting the `SRV` record.
- `naptrOrder` (optional): This parameter is required when deleting the `NAPTR` record.
- `naptrPreference` (optional): This parameter is required when deleting the `NAPTR` record.
- `naptrFlags` (optional): This parameter is required when deleting the `NAPTR` record.
- `naptrServices` (optional): This parameter is required when deleting the `NAPTR` record.
- `naptrRegexp` (optional): This parameter is required when deleting the `NAPTR` record.
- `naptrReplacement` (optional): This parameter is required when deleting the `NAPTR` record.
- `sshfpAlgorithm` (optional): This parameter is required when deleting `SSHFP` record.
- `sshfpFingerprintType` (optional): This parameter is required when deleting `SSHFP` record.
- `sshfpFingerprint` (optional): This parameter is required when deleting `SSHFP` record.
- `tlsaCertificateUsage` (optional): This parameter is required when deleting `TLSA` record.
- `tlsaSelector` (optional): This parameter is required when deleting `TLSA` record.
- `tlsaMatchingType` (optional): This parameter is required when deleting `TLSA` record.
- `tlsaCertificateAssociationData` (optional): This parameter is required when deleting `TLSA` record.
- `svcPriority` (optional): The priority value for `SVCB` or `HTTPS` record. This parameter is required for deleting `SCVB` or `HTTPS` record.
- `svcTargetName` (optional): The target domain name for `SVCB` or `HTTPS` record. This parameter is required for deleting `SCVB` or `HTTPS` record.
- `svcParams` (optional): The service parameters for `SVCB` or `HTTPS` record which is a pipe separated list of key and value. For example, `alpn|h2,h3|port|53443`. To clear existing values, set it to `false`. This parameter is required for deleting `SCVB` or `HTTPS` record.
- `uriPriority` (optional): The priority value in the `URI` record. This parameter is required when deleting the `URI` record.
- `uriWeight` (optional): The weight value in the `URI` record. This parameter is required when deleting the `URI` record.
- `uri` (optional): The URI value in the `URI` record. This parameter is required when deleting the `URI` record.
- `flags` (optional): This is the flags parameter in the `CAA` record. This parameter is required when deleting the `CAA` record.
- `tag` (optional): This is the tag parameter in the `CAA` record. This parameter is required when deleting the `CAA` record.
- `value` (optional): This parameter is required when deleting the `CAA` record.
- `aname` (optional): This parameter is required when deleting the `ANAME` record.
- `protocol` (optional): This is the protocol parameter in the FWD record. Valid values are [`Udp`, `Tcp`, `Tls`, `Https`, `Quic`]. This parameter is optional and default value `Udp` will be used when deleting the `FWD` record.
- `forwarder` (optional): This parameter is required when deleting the `FWD` record.
- `rdata` (optional): This parameter is used for deleting unknown i.e. unsupported record types. The value must be formatted as a hex string or a colon separated hex string.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

## DNS Cache API Calls

These API calls allow managing the DNS server cache.

### List Cached Zones

List all cached zones.

URL:\
`http://localhost:5380/api/cache/list?domain=google.com`

PERMISSIONS:\
Cache: View 

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `domain` (Optional): The domain name to list records. If not passed, the domain is set to empty string which corresponds to the zone root.
- `direction` (Optional): Allows specifying the direction of browsing the zone. Valid values are [`up`, `down`] and the default value is `down` when parameter is missing. This option allows the server to skip empty labels in the domain name when browsing up or down.

RESPONSE:
```
{
	"response": {
		"domain": "google.com",
		"zones": [],
		"records": [
			{
				"name": "google.com",
				"type": "A",
				"ttl": "283 (4 mins 43 sec)",
				"rData": {
					"value": "216.58.199.174"
				}
			}
		]
	},
	"status": "ok"
}
```

### Delete Cached Zone

Deletes a specific zone from the DNS cache.

URL:\
`http://localhost:5380/api/cache/delete?domain=google.com`

PERMISSIONS:\
Cache: Delete

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `domain`: The domain name to delete cached records from.

RESPONSE:
```
{
	"status": "ok"
}
```

### Flush DNS Cache

This call clears all the DNS cache from the server forcing the DNS server to make recursive queries again to populate the cache.

URL:\
`http://localhost:5380/api/cache/flush`

PERMISSIONS:\
Cache: Delete

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"status": "ok"
}
```

## Allowed Zones API Calls

These API calls allow managing the Allowed zones.

### List Allowed Zones

List all allowed zones.

URL:\
`http://localhost:5380/api/allowed/list?domain=google.com`

PERMISSIONS:\
Allowed: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `domain` (Optional): The domain name to list records. If not passed, the domain is set to empty string which corresponds to the zone root.
- `direction` (Optional): Allows specifying the direction of browsing the zone. Valid values are [`up`, `down`] and the default value is `down` when parameter is missing. This option allows the server to skip empty labels in the domain name when browsing up or down.

RESPONSE:
```
{
	"response": {
		"domain": "google.com",
		"zones": [],
		"records": [
			{
				"name": "google.com",
				"type": "NS",
				"ttl": "14400 (4 hours)",
				"rData": {
					"value": "server1"
				}
			},
			{
				"name": "google.com",
				"type": "SOA",
				"ttl": "14400 (4 hours)",
				"rData": {
					"primaryNameServer": "server1",
					"responsiblePerson": "hostadmin.server1",
					"serial": 1,
					"refresh": 14400,
					"retry": 3600,
					"expire": 604800,
					"minimum": 900
				}
			}
		]
	},
	"status": "ok"
}
```

### Allow Zone

Adds a domain name into the Allowed Zones.

URL:\
`http://localhost:5380/api/allowed/add?domain=google.com`

PERMISSIONS:\
Allowed: Modify

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `domain`: The domain name for the zone to be added.

RESPONSE:
```
{
	"status": "ok"
}
```

### Delete Allowed Zone

Allows deleting a zone from the Allowed Zones.

URL:\
`http://localhost:5380/api/allowed/delete?domain=google.com`

PERMISSIONS:\
Allowed: Delete

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `domain`: The domain name for the zone to be deleted.

RESPONSE:
```
{
	"status": "ok"
}
```

### Flush Allowed Zone

Flushes the Allowed zone to clear all records.

URL:\
`http://localhost:5380/api/allowed/flush`

PERMISSIONS:\
Allowed: Delete

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"status": "ok"
}
```

### Import Allowed Zones

Imports domain names into the Allowed Zones.

URL:\
`http://localhost:5380/api/allowed/import`

PERMISSIONS:\
Allowed: Modify

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

REQUEST:
This is a `POST` request call where the content type of the request must be `application/x-www-form-urlencoded` and the content must be as shown below:

```
allowedZones=google.com,twitter.com
```

WHERE:
- `allowedZones`: A list of comma separated domain names that are to be imported.

RESPONSE:
```
{
	"status": "ok"
}
```

### Export Allowed Zones

Allows exporting all the zones from the Allowed Zones as a text file.

URL:\
`http://localhost:5380/api/allowed/export`

PERMISSIONS:\
Allowed: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
Response is a downloadable text file with `Content-Type: text/plain` and `Content-Disposition: attachment`.

## Blocked Zones API Calls

These API calls allow managing the Blocked zones.

### List Blocked Zones

List all blocked zones.

URL:\
`http://localhost:5380/api/blocked/list?domain=google.com`

PERMISSIONS:\
Blocked: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `domain` (Optional): The domain name to list records. If not passed, the domain is set to empty string which corresponds to the zone root.
- `direction` (Optional): Allows specifying the direction of browsing the zone. Valid values are [`up`, `down`] and the default value is `down` when parameter is missing. This option allows the server to skip empty labels in the domain name when browsing up or down.

RESPONSE:
```
{
	"response": {
		"domain": "google.com",
		"zones": [],
		"records": [
			{
				"name": "google.com",
				"type": "NS",
				"ttl": "14400 (4 hours)",
				"rData": {
					"value": "server1"
				}
			},
			{
				"name": "google.com",
				"type": "SOA",
				"ttl": "14400 (4 hours)",
				"rData": {
					"primaryNameServer": "server1",
					"responsiblePerson": "hostadmin.server1",
					"serial": 1,
					"refresh": 14400,
					"retry": 3600,
					"expire": 604800,
					"minimum": 900
				}
			}
		]
	},
	"status": "ok"
}
```

### Block Zone

Adds a domain name into the Blocked Zones.

URL:\
`http://localhost:5380/api/blocked/add?domain=google.com`

PERMISSIONS:\
Blocked: Modify

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `domain`: The domain name for the zone to be added.

RESPONSE:
```
{
	"status": "ok"
}
```

### Delete Blocked Zone

Allows deleting a zone from the Blocked Zones.

URL:\
`http://localhost:5380/api/blocked/delete?domain=google.com`

PERMISSIONS:\
Blocked: Delete

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `domain`: The domain name for the zone to be deleted.

RESPONSE:
```
{
	"status": "ok"
}
```

### Flush Blocked Zone

Flushes the Blocked zone to clear all records.

URL:\
`http://localhost:5380/api/blocked/flush`

PERMISSIONS:\
Blocked: Delete

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"status": "ok"
}
```

### Import Blocked Zones

Imports domain names into Blocked Zones.

URL:\
`http://localhost:5380/api/blocked/import`

PERMISSIONS:\
Blocked: Modify

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

REQUEST:
This is a `POST` request call where the content type of the request must be `application/x-www-form-urlencoded` and the content must be as shown below:

```
blockedZones=google.com,twitter.com
```

WHERE:
- `blockedZones`: A list of comma separated domain names that are to be imported.

RESPONSE:
```
{
	"status": "ok"
}
```

### Export Blocked Zones

Allows exporting all the zones from the Blocked Zones as a text file.

URL:\
`http://localhost:5380/api/blocked/export`

PERMISSIONS:\
Blocked: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
Response is a downloadable text file with `Content-Type: text/plain` and `Content-Disposition: attachment`.

## DNS Apps API Calls

These API calls allows managing DNS Apps.

### List Apps

Lists all installed apps on the DNS server. If the DNS server has Internet access and is able to retrieve data from DNS App Store, the API call will also return if a store App has updates available.

URL:\
`http://localhost:5380/api/apps/list`

PERMISSIONS:\
Apps/Zones/Logs: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"response": {
		"apps": [
			{
				"name": "Block Page",
				"version": "1.0",
				"enabled": true,
				"dnsApps": [
					{
						"classPath": "BlockPageWebServer.App",
						"description": "Serves a block page from a built-in web server that can be displayed to the end user when a website is blocked by the DNS server.\n\nNote: You need to manually configure the custom IP addresses of this built-in web server in the blocking settings for the block page to be served.",
						"isAppRecordRequestHandler": false,
						"isRequestController": false,
						"isAuthoritativeRequestHandler": false,
						"isRequestBlockingHandler": false,
						"isQueryLogger": false,
						"isPostProcessor": false
					}
				]
			},
			{
				"name": "What Is My DNS",
				"version": "2.0",
				"dnsApps": [
					{
						"classPath": "WhatIsMyDns.App",
						"description": "Returns the IP address of the user's DNS Server for A, AAAA, and TXT queries.",
						"isAppRecordRequestHandler": true,
						"recordDataTemplate": null,
						"isRequestController": false,
						"isAuthoritativeRequestHandler": false,
						"isRequestBlockingHandler": false,
						"isQueryLogger": false,
						"isPostProcessor": false
					}
				]
			}
		]
	},
	"status": "ok"
}
```

### List Store Apps

Lists all available apps on the DNS App Store.

URL:\
`http://localhost:5380/api/apps/listStoreApps`

PERMISSIONS:\
Apps: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"response": {
		"storeApps": [
			{
				"name": "Geo Continent",
				"version": "1.1",
				"description": "Returns A or AAAA records, or CNAME record based on the continent the client queries from using MaxMind GeoIP2 Country database. This app requires MaxMind GeoIP2 database and includes the GeoLite2 version for trial. To update the MaxMind GeoIP2 database for your app, download the GeoIP2-Country.mmdb file from MaxMind and zip it. Use the zip file with the manual Update option.",
				"url": "https://example.com/zenitiumdns/apps/GeoContinentApp.zip",
				"size": "2.01 MB",
				"installed": false
			},
			{
				"name": "Geo Country",
				"version": "1.1",
				"description": "Returns A or AAAA records, or CNAME record based on the country the client queries from using MaxMind GeoIP2 Country database. This app requires MaxMind GeoIP2 database and includes the GeoLite2 version for trial. To update the MaxMind GeoIP2 database for your app, download the GeoIP2-Country.mmdb file from MaxMind and zip it. Use the zip file with the manual Update option.",
				"url": "https://example.com/zenitiumdns/apps/GeoCountryApp.zip",
				"size": "2.01 MB",
				"installed": false
			},
			{
				"name": "Geo Distance",
				"version": "1.1",
				"description": "Returns A or AAAA records, or CNAME record of the server located geographically closest to the client using MaxMind GeoIP2 City database. This app requires MaxMind GeoIP2 database and includes the GeoLite2 version for trial. To update the MaxMind GeoIP2 database for your app, download the GeoIP2-City.mmdb file from MaxMind and zip it. Use the zip file with the manual Update option.",
				"url": "https://example.com/zenitiumdns/apps/GeoDistanceApp.zip",
				"size": "28.6 MB",
				"installed": false
			},
			{
				"name": "Split Horizon",
				"version": "1.1",
				"description": "Returns different set of A or AAAA records, or CNAME record for clients querying over public and private networks.",
				"url": "https://example.com/zenitiumdns/apps/SplitHorizonApp.zip",
				"size": "11.1 KB",
				"installed": true,
				"installedVersion": "1.1",
				"updateAvailable": false
			},
			{
				"name": "What Is My Dns",
				"version": "1.1",
				"description": "Returns the IP address of the user's DNS Server for A, AAAA, and TXT queries.",
				"url": "https://example.com/zenitiumdns/apps/WhatIsMyDnsApp.zip",
				"size": "8.79 KB",
				"installed": true,
				"installedVersion": "1.1",
				"updateAvailable": false
			}
		]
	},
	"status": "ok"
}
```

### Download And Install App

Download an app zip file from given URL and installs it on the DNS Server.

URL:\
`http://localhost:5380/api/apps/downloadAndInstall?name=app-name&url=https://example.com/app.zip`

PERMISSIONS:\
Apps: Delete

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the app to install.
- `url`: The URL of the app zip file. URL must start with `https://`.

RESPONSE:
```
{
	"response": {
		"installedApp": {
			"name": "Wild IP",
			"version": "1.0",
			"dnsApps": [
				{
					"classPath": "WildIp.App",
					"description": "Returns the IP address that was embedded in the subdomain name for A and AAAA queries. It works similar to sslip.io.",
					"isAppRecordRequestHandler": true,
					"recordDataTemplate": null,
					"isRequestController": false,
					"isAuthoritativeRequestHandler": false,
					"isRequestBlockingHandler": false,
					"isQueryLogger": false,
					"isPostProcessor": false
				}
			]
		}
	},
	"status": "ok"
}
```

### Download And Update App

Download an app zip file from given URL and updates an existing app installed on the DNS Server.

URL:\
`http://localhost:5380/api/apps/downloadAndUpdate?name=app-name&url=https://example.com/app.zip`

PERMISSIONS:\
Apps: Delete

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the app to install.
- `url`: The URL of the app zip file. URL must start with `https://`.

RESPONSE:
```
{
	"response": {
		"updatedApp": {
			"name": "Wild IP",
			"version": "1.0",
			"dnsApps": [
				{
					"classPath": "WildIp.App",
					"description": "Returns the IP address that was embedded in the subdomain name for A and AAAA queries. It works similar to sslip.io.",
					"isAppRecordRequestHandler": true,
					"recordDataTemplate": null,
					"isRequestController": false,
					"isAuthoritativeRequestHandler": false,
					"isRequestBlockingHandler": false,
					"isQueryLogger": false,
					"isPostProcessor": false
				}
			]
		}
	},
	"status": "ok"
}
```

### Install App

Installs a DNS application on the DNS server.

URL:\
`http://localhost:5380/api/apps/install?name=app-name`

PERMISSIONS:\
Apps: Delete

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the app to install.

REQUEST: This is a POST request call where the request must be multi-part form data with the DNS application zip file data in binary format.

RESPONSE:
```
{
	"response": {
		"installedApp": {
			"name": "Wild IP",
			"version": "1.0",
			"dnsApps": [
				{
					"classPath": "WildIp.App",
					"description": "Returns the IP address that was embedded in the subdomain name for A and AAAA queries. It works similar to sslip.io.",
					"isAppRecordRequestHandler": true,
					"recordDataTemplate": null,
					"isRequestController": false,
					"isAuthoritativeRequestHandler": false,
					"isRequestBlockingHandler": false,
					"isQueryLogger": false,
					"isPostProcessor": false
				}
			]
		}
	},
	"status": "ok"
}
```

### Update App

Allows to manually update an installed app using a provided app zip file.

URL:\
`http://localhost:5380/api/apps/update?name=app-name`

PERMISSIONS:\
Apps: Delete

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the app to update.

REQUEST: This is a POST request call where the request must be multi-part form data with the DNS application zip file data in binary format.

RESPONSE:
```
{
	"response": {
		"updatedApp": {
			"name": "Wild IP",
			"version": "1.0",
			"dnsApps": [
				{
					"classPath": "WildIp.App",
					"description": "Returns the IP address that was embedded in the subdomain name for A and AAAA queries. It works similar to sslip.io.",
					"isAppRecordRequestHandler": true,
					"recordDataTemplate": null,
					"isRequestController": false,
					"isAuthoritativeRequestHandler": false,
					"isRequestBlockingHandler": false,
					"isQueryLogger": false,
					"isPostProcessor": false
				}
			]
		}
	},
	"status": "ok"
}
```

### Uninstall App

Uninstall an app from the DNS server. This does not remove any APP records that were using this DNS application.

URL:\
`http://localhost:5380/api/apps/uninstall?name=app-name`

PERMISSIONS:\
Apps: Delete

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the app to uninstall.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

### Enable App

Enables an installed DNS app so that it is initialized and takes part in request processing. Bundled apps are installed in disabled state.

URL:\
`http://localhost:5380/api/apps/enable?token=x&name=app-name`

PERMISSIONS:\
Apps: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the installed app.

RESPONSE:\
Returns the app in the same format as the `list` call in the `updatedApp` property. The `enabled` property shows the new state.

### Disable App

Disables an installed DNS app. The app stays installed and its config can still be edited, but it is not initialized and does not take part in request processing.

URL:\
`http://localhost:5380/api/apps/disable?token=x&name=app-name`

PERMISSIONS:\
Apps: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the installed app.

RESPONSE:\
Returns the app in the same format as the `list` call in the `updatedApp` property.

### Get App Config

Retrieve the DNS application config from the `dnsApp.config` file in the application folder.

URL:\
`http://localhost:5380/api/apps/config/get?name=app-name`

PERMISSIONS:\
Apps: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the app to retrieve the config.

RESPONSE:
```
{
	"response": {
		"config": "config data or `null`"
	},
	"status": "ok"
}
```

### Set App Config

Saves the provided DNS application config into the `dnsApp.config` file in the application folder.

URL:\
`http://localhost:5380/api/apps/config/set?name=app-name`

PERMISSIONS:\
Apps: Modify

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the app to retrieve the config.

REQUEST: This is a POST request call where the content type of the request must be `application/x-www-form-urlencoded` and the content must be as shown below:
```
config=query-string-encoded-config-data
```

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

## DNS Client API Calls

These API calls allow interacting with the DNS Client section.

### Resolve Query

URL:\
`http://localhost:5380/api/dnsClient/resolve?server=this-server&domain=example.com&type=A&protocol=UDP`

PERMISSIONS:\
DnsClient: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `server`: The name server to query using the DNS client. Use `recursive-resolver` to perform recursive resolution. Use `system-dns` to query the DNS servers configured on the system.
- `domain`: The domain name to query.
- `type`: The type of the query.
- `protocol` (optional): The DNS transport protocol to be used to query. Valid values are [`Udp`, `Tcp`, `Tls`, `Https`, `Quic`]. The default value of `Udp` is used when the parameter is missing.
- `dnssec` (optional): Set to `true` to enable DNSSEC validation.
- `eDnsClientSubnet` (optional): The network address to be used with EDNS Client Subnet option in the request.

RESPONSE:
```
{
	"response": {
		"result": {
			"Metadata": {
				"NameServer": "server1:53 (127.0.0.1:53)",
				"Protocol": "Udp",
				"DatagramSize": "45 bytes",
				"RoundTripTime": "1.42 ms"
			},
			"Identifier": 60127,
			"IsResponse": true,
			"OPCODE": "StandardQuery",
			"AuthoritativeAnswer": true,
			"Truncation": false,
			"RecursionDesired": true,
			"RecursionAvailable": true,
			"Z": 0,
			"AuthenticData": false,
			"CheckingDisabled": false,
			"RCODE": "NoError",
			"QDCOUNT": 1,
			"ANCOUNT": 1,
			"NSCOUNT": 0,
			"ARCOUNT": 0,
			"Question": [
				{
					"Name": "example.com",
					"Type": "A",
					"Class": "IN"
				}
			],
			"Answer": [
				{
					"Name": "example.com",
					"Type": "A",
					"Class": "IN",
					"TTL": "86400 (1 day)",
					"RDLENGTH": "4 bytes",
					"RDATA": {
						"IPAddress": "127.0.0.1"
					}
				}
			],
			"Authority": [],
			"Additional": []
		},
		"rawResponses": []
	},
	"status": "ok"
}
```

### Health Check

This API call is intended to be used for automated health checks. This call when succeeded tells if the DNS server process is running and if the DNS server is able to resolve domain names. These calls do not cause entries in query logs.

URL:\
`http://localhost:5380/api/dnsClient/healthCheck`

PERMISSIONS:\
DnsClient: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `domain` (optional): The domain name to query. When unspecified, `localhost` is used as the domain name.
- `type`: The type of the query. When unspecified, record type `A` is used.

RESPONSE:
```
{
	"server": "server1",
	"status": "ok"
}
```

## Self Test API Calls

### Run Self Test

Runs the self test that checks listeners, recursive resolution and DNSSEC validation of the root zone, TLS certificates, security settings, block lists, client block lists, apps and system resources. Results are cached for 60 seconds.

URL:\
`http://localhost:5380/api/selftest/run?token=x&refresh=false`

PERMISSIONS:\
Settings: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `refresh` (optional): Set `true` to run the checks again instead of returning cached results.

RESPONSE:
```
{
	"response": {
		"runOn": "2026-09-26T16:29:16.0000000Z",
		"results": [
			{
				"group": "Auflösung",
				"title": "DNSSEC-Validierung",
				"status": "ok",
				"message": "Die signierte Root-Zone wurde erfolgreich validiert."
			}
		],
		"errors": 0,
		"warnings": 0
	},
	"status": "ok"
}
```

The `status` of each result is one of `ok`, `info`, `warning` or `error`. The messages are in German.

## Settings API Calls

These API calls allow managing the DNS server settings.

### Get DNS Settings

This call returns all the DNS server settings.

URL:\
`http://localhost:5380/api/settings/get`

PERMISSIONS:\
Settings: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"response": {
		"version": "15.5",
		"uptimestamp": "2026-09-26T01:42:05.3304591Z",
		"dnsServerDomain": "server1",
		"dnsServerLocalEndPoints": [
			"127.0.0.1:53"
		],
		"dnsServerIPv4SourceAddresses": [
			"0.0.0.0"
		],
		"dnsServerIPv6SourceAddresses": [
			"::"
		],
		"defaultRecordTtl": 3600,
		"defaultNsRecordTtl": 14400,
		"defaultSoaRecordTtl": 900,
		"defaultResponsiblePerson": null,
		"dnsServerEnableCheckForUpdate": true,
		"dnsAppsEnableAutomaticUpdate": true,
		"ipv6Mode": "Disabled",
		"preferIPv6": false,
		"ipv6AutoFallback": true,
		"enableUdpSocketPool": false,
		"udpListenerThreads": 0,
		"maxPendingStreamRequests": 100,
		"socketPoolExcludedPorts": [
			53443
		],
		"udpPayloadSize": 1232,
		"dnssecValidation": false,
		"eDnsClientSubnet": false,
		"eDnsClientSubnetIPv4PrefixLength": 24,
		"eDnsClientSubnetIPv6PrefixLength": 56,
		"eDnsClientSubnetIpv4Override": null,
		"eDnsClientSubnetIpv6Override": null,
		"requestFilterMalformed": true,
		"requestFilterMaxSize": 1232,
		"requestFilterOpcode": true,
		"requestFilterClass": true,
		"requestFilterAny": true,
		"requestFilterZoneTransfer": true,
		"requestFilterNoRecursion": true,
		"requestFilterEdnsVersion": true,
		"requestFilterRefuseOnly": false,
		"requestFilterMatches": {
			"malformed": 0,
			"size": 0,
			"opcode": 0,
			"class": 0,
			"any": 0,
			"zoneTransfer": 0,
			"noRecursion": 0,
			"ednsVersion": 0
		},
		"clientBlockListUrls": [
			"https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"
		],
		"clientBlockListUpdateIntervalHours": 24,
		"clientBlockListAddressRanges": 18503,
		"clientBlockListDrops": 0,
		"clientBlockListLastUpdatedOn": "2026-09-26T17:02:57.8052024Z",
		"qpsPrefixLimitsIPv4": [
			{
				"prefix": 32,
				"udpLimit": 100,
				"tcpLimit": 400
			},
			{
				"prefix": 24,
				"udpLimit": 1000,
				"tcpLimit": 4000
			}
		],
		"qpsPrefixLimitsIPv6": [
			{
				"prefix": 64,
				"udpLimit": 100,
				"tcpLimit": 400
			},
			{
				"prefix": 56,
				"udpLimit": 1000,
				"tcpLimit": 4000
			}
		],
		"rateLimitBurstSeconds": 5,
		"rateLimitUdpTruncationPercentage": 50,
		"rateLimitBypassList": [],
		"clientTimeout": 2000,
		"tcpSendTimeout": 10000,
		"tcpReceiveTimeout": 10000,
		"quicIdleTimeout": 60000,
		"quicMaxInboundStreams": 100,
		"listenBacklog": 100,
		"udpSendBufferSizeKB": 2048,
		"udpReceiveBufferSizeKB": 2048,
		"maxConcurrentResolutionsPerCore": 100,
		"webServiceLocalAddresses": [
			"[::]"
		],
		"webServiceHttpPort": 5380,
		"webServiceEnableHttpUnixSocket": false,
		"webServiceHttpUnixSocket": null,
		"webServiceEnableTlsUnixSocket": false,
		"webServiceTlsUnixSocket": null,
		"webServiceEnableTls": false,
		"webServiceEnableHttp3": false,
		"webServiceHttpToTlsRedirect": false,
		"webServiceUseSelfSignedTlsCertificate": false,
		"webServiceTlsPort": 53443,
		"webServiceReverseProxyAddresses": [
			"127.0.0.0/8",
			"10.0.0.0/8",
			"100.64.0.0/10",
			"169.254.0.0/16",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"!2000::/3",
			"::/0"
		],
		"webServiceRealIpHeader": "X-Real-IP",
		"webServiceCspFrameAncestorsHeader": "'none'",
		"webServiceTlsCertificatePath": null,
		"webServiceTlsCertificatePassword": null,
		"webServiceTlsCertificateKeyPath": null,
		"enableEDnsClientSubnetSourceAddress": false,
		"enableDnsOverUdpProxy": false,
		"enableDnsOverTcpProxy": false,
		"enableDnsOverHttp": false,
		"enableDnsOverHttpUnixSocket": false,
		"enableDnsOverHttpsUnixSocket": false,
		"enableDnsOverTls": false,
		"enableDnsOverHttps": false,
		"enableDnsOverHttp3": false,
		"enableDnsOverQuic": false,
		"enableDnsOverHttpHelpRedirect": true,
		"dnsOverUdpProxyPort": 538,
		"dnsOverTcpProxyPort": 538,
		"dnsOverHttpPort": 80,
		"dnsOverHttpUnixSocket": null,
		"dnsOverHttpsUnixSocket": null,
		"dnsOverTlsPort": 853,
		"dnsOverHttpsPort": 443,
		"dnsOverQuicPort": 853,
		"dnsReverseProxyNetworkACL": [],
		"dnsOverHttpRealIpHeader": "X-Real-IP",
		"dnsTlsCertificatePath": null,
		"dnsTlsCertificatePassword": null,
		"dnsTlsCertificateKeyPath": null,
		"enableDdr": true,
		"ddrOnlyUnencrypted": true,
		"ddrRecords": [],
		"recursion": "Allow",
		"recursionNetworkACL": [],
		"randomizeName": true,
		"qnameMinimization": true,
		"locallyServedDnsZones": true,
		"resolverRetries": 2,
		"resolverTimeout": 1500,
		"resolverConcurrency": 2,
		"resolverMaxStackCount": 16,
		"saveCache": true,
		"serveStale": true,
		"serveStaleTtl": 259200,
		"serveStaleAnswerTtl": 30,
		"serveStaleResetTtl": 30,
		"serveStaleMaxWaitTime": 1800,
		"cacheMaximumEntries": 10000,
		"cacheMinimumRecordTtl": 10,
		"cacheMaximumRecordTtl": 604800,
		"cacheNegativeRecordTtl": 300,
		"cacheFailureRecordTtl": 10,
		"cachePrefetchEligibility": 2,
		"cachePrefetchTrigger": 9,
		"enableBlocking": true,
		"allowTxtBlockingReport": true,
		"blockingBypassList": [],
		"blockingType": "NxDomain",
		"blockingAnswerTtl": 300,
		"blockingNegativeTtl": 300,
		"blockingReportText": null,
		"customBlockingAddresses": [],
		"blockListUrls": null,
		"blockListUpdateIntervalHours": 24,
		"proxy": null,
		"forwarders": null,
		"forwarderProtocol": "Udp",
		"concurrentForwarding": true,
		"forwarderRetries": 3,
		"forwarderTimeout": 2000,
		"forwarderConcurrency": 2,
		"enableLogging": true,
		"loggingType": "File",
		"ignoreResolverLogs": false,
		"logQueries": false,
		"noStackTrace": false,
		"useLocalTime": false,
		"logFolder": "logs",
		"maxLogFileDays": 365,
		"enableInMemoryStats": false,
		"maxStatFileDays": 365
	},
	"status": "ok"
}
```

### Set DNS Settings

This call allows to change the DNS server settings. 

Note! Any parameter passed with this API call will overwrite existing value for that parameter. If you wish to append new values instead then you should first call the Get DNS Settings API to get the existing value, append your new value to it, and then pass the updated value with this API call.

URL:\
`http://localhost:5380/api/settings/set?dnsServerDomain=server1&dnsServerLocalEndPoints=0.0.0.0:53,[::]:53&webServiceLocalAddresses=0.0.0.0,[::]&webServiceHttpPort=5380&webServiceEnableTls=false&webServiceTlsPort=53443&webServiceTlsCertificatePath=&webServiceTlsCertificatePassword=&enableDnsOverHttp=false&enableDnsOverTls=false&enableDnsOverHttps=false&dnsTlsCertificatePath=&dnsTlsCertificatePassword=&preferIPv6=false&logQueries=true&allowRecursion=true&allowRecursionOnlyForPrivateNetworks=true&randomizeName=true&cachePrefetchEligibility=2&cachePrefetchTrigger=9&proxyType=socks5&proxyAddress=192.168.10.2&proxyPort=9050&proxyUsername=username&proxyPassword=password&proxyBypass=127.0.0.0/8,169.254.0.0/16,fe80::/10,::1,localhost&forwarders=192.168.10.2&forwarderProtocol=Udp&useNxDomainForBlocking=false&blockListUrls=https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts,https://mirror1.malwaredomains.com/files/justdomains,https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt,https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt`

PERMISSIONS:\
Settings: Modify

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `dnsServerDomain` (optional): The primary domain name used by this DNS Server to identify itself.
- `dnsServerLocalEndPoints` (optional): Local end points are the network interface IP addresses and ports you want the DNS Server to listen for requests. 
- `dnsServerIPv4SourceAddresses` (optional): A comma separated list of IPv4 source addresses that the DNS server must use for making all outbound DNS requests when the server is connected to two or more networks. Network addresses are also accepted. By default, the IPv4 address of the network with a default route will be used as the source address.
- `dnsServerIPv6SourceAddresses` (optional): A comma separated list of IPv6 source addresses that the DNS server must use for making all outbound DNS requests when the server is connected to two or more networks. Network addresses are also accepted. By default, the IPv6 address of the network with a default route will be used as the source address. Note that this option will be used only when `Prefer IPv6` option is enabled.
- `defaultRecordTtl` (optional): The default TTL value to use if not specified when adding or updating records in a Zone.
- `defaultNsRecordTtl` (optional): The default TTL value to use if not specified when adding or updating NS records in a zone.
- `defaultSoaRecordTtl` (optional): The default TTL value for SOA records. This value is kept for compatibility and is not used by Conditional Forwarder zones.
- `defaultResponsiblePerson` (optional): The default SOA Responsible Person email address. This value is kept for compatibility and is not used by Conditional Forwarder zones.
- `dnsServerEnableCheckForUpdate` (optional): Set to `true` to enable the DNS Server to check if an update is available when the Check For Update API is called which usually occurs after a user logs into the Web Console.
- `dnsAppsEnableAutomaticUpdate` (optional): Set to `true` to allow DNS server to automatically update the DNS Apps from the DNS App Store. The DNS Server will check for updates every 24 hrs when this option is enabled.
- `ipv6Mode` (optional): Valid options are `Disabled`, `Enabled`, and `Preferred`. Initial value is `Disabled`.
- `ipv6AutoFallback` (optional): Set to `true` to automatically suspend outbound IPv6 queries to name servers when IPv6 connectivity is broken. After 8 consecutive IPv6 timeouts, IPv6 is suspended for one minute, doubling with each further suspension up to 30 minutes. A background probe against the IPv6 root servers every two minutes resumes IPv6 as soon as it works again. This option has no effect when `ipv6Mode` is `Disabled`. Initial value is `true`.
- `enableUdpSocketPool` (optional): Set this to `true` to enable UDP socket pool. The DNS Server will use UDP socket pool for all outbound DNS-over-UDP requests when enabled.
- `socketPoolExcludedPorts` (optional): A comma separated list of port numbers that must be excluded from being used by the UDP socket pool.
- `udpPayloadSize` (optional): The maximum EDNS UDP payload size that can be used to avoid IP fragmentation. Valid range is 512-4096 bytes. Initial value is `1232`.
- `dnssecValidation` (optional): Set this to `true` to enable DNSSEC validation. DNS Server will validate all responses from name servers or forwarders when this option is enabled.
- `eDnsClientSubnet` (optional): Set this to `true` to enable EDNS Client Subnet. DNS Server will use the public IP address of the request with a prefix length, or the existing Client Subnet option from the request while resolving requests.
- `eDnsClientSubnetIPv4PrefixLength` (optional): The EDNS Client Subnet IPv4 prefix length to define the client subnet. Initial value is `24`.
- `eDnsClientSubnetIPv6PrefixLength` (optional): The EDNS Client Subnet IPv6 prefix length to define the client subnet. Initial value is `56`.
- `eDnsClientSubnetIpv4Override` (optional): The IPv4 network address that must be used as ECS for all outbound requests overriding client's actual subnet.
- `eDnsClientSubnetIpv6Override` (optional): The IPv6 network address that must be used as ECS for all outbound requests overriding client's actual subnet.
- `requestFilterMalformed`, `requestFilterOpcode`, `requestFilterClass`, `requestFilterAny`, `requestFilterZoneTransfer`, `requestFilterNoRecursion`, `requestFilterEdnsVersion` (optional): Enable or disable the request filter rules for unreadable requests, opcodes other than QUERY, classes other than IN, type ANY, AXFR/IXFR, requests without the RD flag and EDNS versions other than 0. Matching UDP requests are dropped, stream requests are answered with `REFUSED` and Extended DNS Error 18. Requests from loopback addresses are never filtered. All rules are enabled initially.
- `requestFilterMaxSize` (optional): Requests larger than this size in bytes are dropped. Set `0` to disable. Initial value is `1232`.
- `requestFilterRefuseOnly` (optional): Set `true` to answer filtered UDP requests with `REFUSED` instead of dropping them.
- `clientBlockListUrls` (optional): A comma separated list of client IP block list URLs (`https://`, `http://` or `file://`). Supported formats are one IP address or CIDR network per line, optionally followed by other columns as in IPsum or Spamhaus DROP. Requests from listed addresses are dropped, stream connections are closed. Loopback addresses and the `rateLimitBypassList` networks are never blocked. Set this parameter to `false` to remove all lists.
- `clientBlockListUpdateIntervalHours` (optional): The interval in hours to download the client block lists again. Set `0` to disable automatic updates. Initial value is `24`.
- `qpsPrefixLimitsIPv4` (optional): A pipe `|` separated multi row list of prefix, udpLimit and tcpLimit. Set this parameter to `false` to remove all entries. The maximum queries per second that an IPv4 client subnet can make to UDP and TCP (including DoT, DoH and DoQ) services, enforced with a token bucket per subnet. Set limit value to 0 to allow unlimited queries. The obsolete parameter `qpmPrefixLimitsIPv4` is still accepted and converted from queries per minute.
- `qpsPrefixLimitsIPv6` (optional): Same as `qpsPrefixLimitsIPv4` for IPv6 client subnets. The obsolete parameter `qpmPrefixLimitsIPv6` is still accepted.
- `rateLimitBurstSeconds` (optional): A client may briefly send as many queries as its limit allows in this number of seconds before the per second limit applies. Valid range is `1`-`60`. Initial value is `5`.
- `rateLimitUdpTruncationPercentage` (optional): The percentage of rate limited UDP requests that are answered with a truncation (TC) response while the rest are dropped. A TC response causes a real client to retry over TCP. Valid range is `0`-`100`. Initial value is `50`.
- `rateLimitBypassList` (optional): A comma separated list of IP addresses or network addresses that are never rate limited or blocked by client block lists.
- `clientTimeout` (optional): The amount of time the DNS server must wait in milliseconds before responding with a ServerFailure response to a client request when no answer is available. Valid range is `1000`-`10000`. Initial value is `4000`.
- `tcpSendTimeout` (optional): The maximum amount of time in milliseconds a TCP socket will wait for the response to be sent. This option will apply for DNS requests being received by the DNS Server over TCP, TLS, TcpProxy, or HTTPS transports. Valid range is `1000`-`90000`. Initial value is `10000`.
- `tcpReceiveTimeout` (optional): The maximum amount of time in milliseconds a TCP socket will wait for receiving data. This option will apply for DNS requests being received by the DNS Server over TCP, TLS, TcpProxy, or HTTPS transports. Valid range is `1000`-`90000`. Initial value is `10000`.
- `maxPendingStreamRequests` (optional): The maximum number of requests being processed concurrently for a single TCP, TLS or TcpProxy connection (RFC 7766 pipelining). Further requests on the same connection are read only after responses were sent. Valid range is 1-10000. Initial value is `100`.
- `quicIdleTimeout` (optional): The time interval in milliseconds after which an idle QUIC connection will be closed. This option applies only to QUIC transport protocol. Valid range is `1000`-`90000`. Initial value is `60000`.
- `quicMaxInboundStreams` (optional): The max number of inbound bidirectional streams that can be accepted per QUIC connection. This option applies only to QUIC transport protocol. Valid range is `1`-`1000`. Initial value is `100`.
- `listenBacklog` (optional): The maximum number of pending inbound connections. This option applies to TCP, TLS, TcpProxy, and QUIC transport protocols. Initial value is `100`.
- `udpSendBufferSizeKB` (optional): The UDP listener socket send buffer size. This option applies to UDP and UdpProxy transport protocols. Valid range is 8-65536. Initial value is 2048.
- `udpReceiveBufferSizeKB` (optional): The UDP listener socket receive buffer size. This option applies to UDP and UdpProxy transport protocols. Valid range is 8-65536. Initial value is 2048.
- `udpListenerThreads` (optional): The number of threads receiving UDP requests per local end point. Set to `0` to use the number of CPU cores, at most 8. Valid range is 0-64. Changing this value restarts the DNS service. Initial value is `0`.
- `maxConcurrentResolutionsPerCore` (optional): The maximum number of concurrent async outbound resolutions that should be done per CPU core.  Initial value is `100`.
- `webServiceLocalAddresses` (optional): Local addresses are the network interface IP addresses you want the web service to listen for requests. 
- `webServiceHttpPort` (optional): Specify the TCP port number for the web console and this API web service. Initial value is `5380`.
- `webServiceEnableHttpUnixSocket` (optional): Set this to `true` to enable Web Service HTTP over Unix Domain Socket (UDS).
- `webServiceHttpUnixSocket` (optional): Specify the Unix Domain Sockets (UDS) file path for HTTP Web Service. Ensure that the DNS Server has read+write permissions to the parent directory to be able to create the UDS file.
- `webServiceEnableTlsUnixSocket` (optional): Set this to `true` to enable Web Service HTTPS over Unix Domain Socket (UDS).
- `webServiceTlsUnixSocket` (optional): Specify the Unix Domain Sockets (UDS) file path for HTTPS Web Service. Ensure that the DNS Server has read+write permissions to the parent directory to be able to create the UDS file.
- `webServiceEnableTls` (optional): Set this to `true` to start the HTTPS service to access web service.
- `webServiceEnableHttp3` (optional): Set this to `true` to enable HTTP/3 protocol for the web service.
- `webServiceHttpToTlsRedirect` (optional): Set this option to `true` to enable HTTP to HTTPS Redirection.
- `webServiceTlsPort` (optional): Specified the TCP port number for the web console for HTTPS access.
- `webServiceReverseProxyAddresses` (optional):  A comma separated list of ACL entries which can be an IP address or a network address. Configure the ACL to define allowed reverse proxy servers such that client IP address from requests coming from these servers is read using the `webServiceRealIpHeader` option. Add ! character at the start to deny, e.g. !192.168.10.0/24 will deny entire subnet. The ACL is processed in the same order its listed. If no networks match, the default policy is to deny all.
- `webServiceUseSelfSignedTlsCertificate` (optional): Set `true` for the web service to use an automatically generated self signed certificate when TLS certificate path is not specified.
- `webServiceTlsCertificatePath` (optional): Specify a PEM certificate chain (for example `fullchain.pem`) or a PKCS #12 certificate (.pfx/.p12) file path on the server. This certificate is used by the web console for HTTPS access.
- `webServiceTlsCertificateKeyPath` (optional): The PEM private key file path (for example `privkey.pem`). Leave empty when the key is contained in the certificate file or when using PKCS #12.
- `webServiceTlsCertificatePassword` (optional): The PKCS #12 password or the password of an encrypted PKCS #8 PEM private key, if any.
- `webServiceRealIpHeader` (optional): The HTTP header that must be used to read client's actual IP address when the request comes from a reverse proxy with a private IP address.
- `webServiceCspFrameAncestorsHeader` (optional): The Content Security Policy (CSP) Frame Ancestors header value that must be used when serving the Web Console.
- `enableEDnsClientSubnetSourceAddress` (optional): Enable this option to read the client's source IP address from the EDNS Client Subnet (ECS) option in the DNS requests coming via DNS-over-UDP or DNS-over-TCP protocols. This option allows a DNS proxy to pass the client's source IP address via ECS option to the DNS Server. It is mandatory to configure `dnsReverseProxyNetworkACL` to allow requests coming from your DNS proxy server to work with this option.
- `enableDnsOverUdpProxy` (optional): Enable this option to accept DNS-over-UDP-PROXY requests. It implements the [PROXY Protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) for both version 1 & 2 over UDP datagram. Configure the `dnsReverseProxyNetworkACL` option to allow only requests coming from your reverse proxy server.
- `enableDnsOverTcpProxy` (optional): Enable this option to accept DNS-over-TCP-PROXY requests. It implements the [PROXY Protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) for both version 1 & 2 over TCP connection. Configure the `dnsReverseProxyNetworkACL` option to allow only requests coming from your reverse proxy server.
- `enableDnsOverHttp` (optional): Enable this option to accept DNS-over-HTTP requests. It must be used with a TLS terminating reverse proxy like nginx. Configure the `dnsReverseProxyNetworkACL` option to allow only requests coming from your reverse proxy server. Enabling this option also allows automatic TLS certificate renewal with HTTP challenge (webroot) for DNS-over-HTTPS service.
- `enableDnsOverHttpUnixSocket` (optional): Enable this option to accept DNS-over-HTTP requests over Unix Domain Sockets (UDS).
- `enableDnsOverHttpsUnixSocket` (optional): Enable this option to accept DNS-over-HTTPS requests over Unix Domain Sockets (UDS).
- `enableDnsOverTls` (optional): Enable this option to accept DNS-over-TLS requests.
- `enableDnsOverHttps` (optional): Enable this option to accept DNS-over-HTTPS requests.
- `enableDnsOverQuic` (optional): Enable this option to accept DNS-over-QUIC requests.
- `enableDnsOverHttpHelpRedirect` (optional): When this option is enabled, if a user visits the `/dns-query` DNS-over-HTTP(s) URL path using a web browser, the web browser will be redirected to `/` URL path to display the help page for the DNS-over-HTTP(s) service.
- `dnsOverUdpProxyPort` (optional): The UDP port number for DNS-over-UDP-PROXY protocol. Initial value is `538`.
- `dnsOverTcpProxyPort` (optional): The TCP port number for DNS-over-TCP-PROXY protocol. Initial value is `538`.
- `dnsOverHttpPort` (optional): The TCP port number for DNS-over-HTTP protocol. Initial value is `80`.
- `dnsOverHttpUnixSocket` (optional): Specify the Unix Domain Sockets (UDS) file path for DNS-over-HTTP protocol service. Ensure that the DNS Server has read+write permissions to the parent directory to be able to create the UDS file.
- `dnsOverHttpsUnixSocket` (optional): Specify the Unix Domain Sockets (UDS) file path for DNS-over-HTTPS protocol service. Ensure that the DNS Server has read+write permissions to the parent directory to be able to create the UDS file.
- `dnsOverTlsPort` (optional): The TCP port number for DNS-over-TLS protocol. Initial value is `853`.
- `dnsOverHttpsPort` (optional): The TCP port number for DNS-over-HTTPS protocol. Initial value is `443`.
- `dnsOverQuicPort` (optional): The UDP port number for DNS-over-QUIC protocol. Initial value is `853`.
- `dnsReverseProxyNetworkACL` (optional): A comma separated list of ACL entries which can be an IP address or a network address. Configure the ACL to allow only requests coming from your reverse proxy server for DNS-over-UDP-PROXY, DNS-over-TCP-PROXY, and DNS-over-HTTP protocols. Add ! character at the start to deny access, e.g. !192.168.10.0/24 will deny entire subnet. The ACL is processed in the same order its listed. If no networks match, the default policy is to deny all.
- `dnsTlsCertificatePath` (optional): Specify a PEM certificate chain (for example `fullchain.pem`) or a PKCS #12 certificate (.pfx/.p12) file path on the server. This certificate is used by the DNS-over-TLS, DNS-over-HTTPS and DNS-over-QUIC protocols. Certificate and key files are reloaded automatically when they change, including renewals that replace symbolic links.
- `dnsTlsCertificateKeyPath` (optional): The PEM private key file path (for example `privkey.pem`). Leave empty when the key is contained in the certificate file or when using PKCS #12.
- `dnsTlsCertificatePassword` (optional): The PKCS #12 password or the password of an encrypted PKCS #8 PEM private key, if any.
- `enableDdr` (optional): Set `true` to answer SVCB queries for `_dns.resolver.arpa` with the enabled encrypted protocols (Discovery of Designated Resolvers, RFC 9462). The records are generated from the enabled services, their ports and the name in the TLS certificate and are returned as `ddrRecords` in the settings. Initial value is `true`.
- `ddrOnlyUnencrypted` (optional): Set `true` to answer DDR queries only when they arrive over unencrypted DNS (UDP or TCP port 53, including PROXY protocol). Initial value is `true`.
- `dnsOverHttpRealIpHeader` (optional): The HTTP header that must be used to read client's actual IP address when the request comes from a reverse proxy with a private IP address.
- `recursion` (optional): Sets the recursion policy for the DNS server. Valid values are [`Deny`, `Allow`, `AllowOnlyForPrivateNetworks`, `UseSpecifiedNetworkACL`].
- `recursionNetworkACL` (optional): A comma separated Access Control List (ACL) of Network Access Control (NAC) entry. NAC is an IP address or network address to allow. Add `!` at the start of the NAC to deny access. The ACL is processed in the same order its listed. If no networks match, the default policy is to deny all except loopback. Set this parameter to `false` to remove existing values. These values are only used when `recursion` is set to `UseSpecifiedNetworkACL`.
- `randomizeName` (optional): Enables QNAME randomization [draft-vixie-dnsext-dns0x20-00](https://tools.ietf.org/html/draft-vixie-dnsext-dns0x20-00) when using UDP as the transport protocol. Initial value is `true`.
- `qnameMinimization` (optional): Enables QNAME minimization [draft-ietf-dnsop-rfc7816bis-04](https://tools.ietf.org/html/draft-ietf-dnsop-rfc7816bis-04) when doing recursive resolution. Initial value is `true`.
- `locallyServedDnsZones` (optional): Enables [Locally Served DNS Zones](https://datatracker.ietf.org/doc/rfc6303/) and [Special-Use Domain Names](https://datatracker.ietf.org/doc/rfc6761/) for recursive resolution to avoid leakage of queries and reduce load on the root servers.
- `resolverRetries` (optional): The number of retries that the recursive resolver must do.
- `resolverTimeout` (optional): The timeout value in milliseconds for the recursive resolver.
- `resolverConcurrency` (optional): The number of concurrent requests that should be sent by the recursive resolver to the name servers.
- `resolverMaxStackCount` (optional): The max stack count that the recursive resolver must use.
- `saveCache` (optional): Enable this option to save DNS cache on disk when the DNS server stops. The saved cache will be loaded next time the DNS server starts.
- `serveStale` (optional): Enable the serve stale feature to improve resiliency by using expired or stale records in cache when the DNS server is unable to reach the upstream or authoritative name servers. Initial value is `true`.
- `serveStaleTtl` (optional): The TTL value in seconds which should be used for cached records that are expired. When the serve stale TTL too expires for a stale record, it gets removed from the cache. Recommended value is between 1-3 days and maximum supported value is 7 days. Initial value is `259200`.
- `serveStaleAnswerTtl` (optional): The TTL value in seconds which should be used for the records in a stale response. This is the TTL value that the client will be using to cache the stale records. The valid range is 0-300 seconds and recommended value is 30 seconds.
- `serveStaleResetTtl` (optional): The TTL value in seconds which should be used to reset the stale record's TTL value in the cache when the resolver fails to refresh the data. The TTL reset causes the stale records to become valid again so that they can be used to serve requests normally. This reset effectively prevents the resolver from attempting to frequently update the stale records. The valid range is 10-900 seconds and recommended value is 30 seconds.
- `serveStaleMaxWaitTime` (optional): The time in milliseconds that the DNS server must wait for the resolver before serving stale records from the cache. Lower value will ensure faster response at the expense of not getting updated data from the upstream. Setting value to 0 will instantly return stale answer without waiting for the resolver to fetch updates from the upstream. The valid range is 0-1800 milliseconds and default value is 1800 milliseconds.
- `cacheMinimumRecordTtl` (optional): The minimum TTL value that a record can have in cache. Set a value to make sure that the records with TTL value than it stays in cache for a minimum duration. Initial value is `10`.
- `cacheMaximumRecordTtl` (optional): The maximum TTL value that a record can have in cache. Set a lower value to allow the records to expire early. Initial value is `86400`.
- `cacheNegativeRecordTtl` (optional): The negative TTL value to use when there is no SOA MINIMUM value available. Initial value is `300`.
- `cacheFailureRecordTtl` (optional): The failure TTL value to used for caching failure responses. This allows storing failure record in cache and prevent frequent recursive resolution to name servers that are responding with `ServerFailure`. Initial value is `60`.
- `cachePrefetchEligibility` (optional): The minimum initial TTL value of a record needed to be eligible for prefetching.
- `cachePrefetchTrigger` (optional): A record with TTL value less than trigger value will initiate prefetch operation immediately for itself. Set `0` to disable prefetching & auto prefetching.
- `enableBlocking` (optional): Sets the DNS server to block domain names using Blocked Zone and Block List Zone.
- `allowTxtBlockingReport` (optional): Specifies if the DNS Server should respond with TXT records containing a blocked domain report for TXT type requests.
- `blockingBypassList` (optional): A comma separated list of IP addresses or network addresses that are allowed to bypass blocking.
- `blockingType` (optional): Sets how the DNS server should respond to a blocked domain request. Valid values are [`AnyAddress`, `NxDomain`, `CustomAddress`] where `AnyAddress` is default which response with `0.0.0.0` and `::` IP addresses for blocked domains. Using `NxDomain` will respond with `NX Domain` response. `CustomAddress` will return the specified custom blocking addresses.
- `blockingAnswerTtl` (optional): The TTL value in seconds that must be used for the address records and TXT reports in a blocking response.
- `blockingNegativeTtl` (optional): The TTL and SOA MINIMUM value in seconds of the SOA record in NXDOMAIN and NODATA blocking responses, which controls negative caching as per RFC 2308. Initial value is `300`.
- `blockingReportText` (optional): A custom text for the Extended DNS Error and the TXT blocking report. The placeholders `{domain}`, `{list}` and `{source}` are replaced with the blocked domain, the block list URL and the blocking source. Set an empty value to use the default text.
- `customBlockingAddresses` (optional): A comma separated list of IP addresses. Set the custom blocking addresses to be used for blocked domain response. These addresses are returned only when `blockingType` is set to `CustomAddress`.
- `blockListUrls` (optional): A comma separated list of block list URLs that this server must automatically download and use with the block lists zone. DNS Server will use the data returned by the block list URLs to update the block list zone automatically every 24 hours. The expected file format is standard hosts file format or plain text file containing list of domains to block. Set this parameter to `false` to remove existing values.
- `blockListUpdateIntervalHours` (optional): The interval in hours to automatically download and update the block lists. Initial value is `24`.
- `proxyType` (optional): The type of proxy protocol to be used. Valid values are [`None`, `Http`, `Socks5`].
- `proxyAddress` (optional): The proxy server hostname or IP address.
- `proxyPort` (optional): The proxy server port.
- `proxyUsername` (optional): The proxy server username.
- `proxyPassword` (optional): The proxy server password.
- `proxyBypass` (optional): A comma separated bypass list consisting of IP addresses, network addresses in CIDR format, or host/domain names to never use proxy for.
- `forwarders` (optional): A comma separated list of forwarders to be used by this DNS server. Set this parameter to `false` string to remove existing forwarders so that the DNS server does recursive resolution by itself.
- `forwarderProtocol` (optional): The forwarder DNS transport protocol to be used. Valid values are [`Udp`, `Tcp`, `Tls`, `Https`, `Quic`].
- `concurrentForwarding` (optional): Set this option to `true` to allow querying two or more forwarders concurrently instead of sequentially querying them in their given order. The DNS server will automatically select forwarders (based on their average latency) to query and use the fastest response it receives from any of them. If none of the selected forwarders respond in time, the DNS server will similarly select forwarders from the remaining ones and queries them till all are tried before giving up.
- `forwarderRetries` (optional): The number of retries that the forwarder DNS client must do.
- `forwarderTimeout` (optional): The timeout value in milliseconds for the forwarder DNS client.
- `forwarderConcurrency` (optional): The number of concurrent requests that the forwarder DNS client should do.
- `loggingType` (optional): Specifies how the error logs and audit logs are written. The valid values are [`None`, `File`, `Console`, `FileAndConsole`]. Initial value is `File`.
- `enableLogging` (optional)(obsolete, use `loggingType` instead): Enable this option to log error and audit logs into the log file. Initial value is `true`.
- `ignoreResolverLogs` (optional): Enable this option to stop logging domain name resolution errors into the log file.
- `logQueries` (optional): Enable this option to log every query received by this DNS Server and the corresponding response answers into the log file.  Initial value is `false`.
- `noStackTrace` (optional): Enable to log only short error messages instead of full exception stack trace.
- `useLocalTime` (optional): Enable this option to use local time instead of UTC for logging.  Initial value is `false`.
- `logFolder` (optional): The folder path on the server where the log files should be saved. The path can be relative to the DNS server config folder. Initial value is `logs`.
- `maxLogFileDays` (optional): Max number of days to keep the log files. Log files older than the specified number of days will be deleted automatically. Recommended value is `365`. Set `0` to disable auto delete.
- `enableInMemoryStats` (optional): Set this option to `true` to enable in-memory stats. When enabled, only Last Hour data will be available on Dashboard and no stats data will be stored on disk.
- `maxStatFileDays` (optional): Max number of days to keep the dashboard stats. Stat files older than the specified number of days will be deleted automatically. Recommended value is `365`. Set `0` to disable auto delete.


REQUEST: Instead of query string or form data parameters described above, the request optionally can also POST settings as JSON data in the same format as returned by `getDnsSettings` API call.

RESPONSE:
This call returns the newly updated settings in the same format as that of the `getDnsSettings` call.

### Force Update Client Block Lists

This call downloads the client block lists again and reloads them in the background.

URL:\
`http://localhost:5380/api/settings/forceUpdateClientBlockLists?token=x`

PERMISSIONS:\
Settings: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"status": "ok"
}
```

### Force Update Block Lists

This call allows to reset the next update schedule and force download and update of the block lists.

URL:\
`http://localhost:5380/api/settings/forceUpdateBlockLists`

PERMISSIONS:\
Settings: Modify

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"status": "ok"
}
```


### Temporarily Disable Block Lists

This call temporarily disables the block lists and block list zones.

URL:\
`http://localhost:5380/api/settings/temporaryDisableBlocking?minutes=5`

PERMISSIONS:\
Settings: Modify

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `minutes`: The time in minutes to disable the blocklist for.

RESPONSE:
```
{
	"status": "ok",
	"response": {
		"temporaryDisableBlockingTill": "2021-10-10T01:14:27.1106773Z"
	}
}
```


### Backup Settings

This call returns a zip file containing copies of all the items that were requested to be backed up.

URL:\
`http://localhost:5380/api/settings/backup?blockLists=true&logs=true&stats=true&zones=true&allowedZones=true&blockedZones=true&dnsSettings=true&logSettings=true&authConfig=true`

PERMISSIONS:\
Settings: Delete

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `authConfig` (optional): Set to `true` to backup the authentication config file. Default value is `false`.
- `webServiceSettings` (optional): Set to `true` to backup the web service config file. Default value is `false`.
- `dnsSettings` (optional): Set to `true` to backup DNS settings and certificate files. The Web Service or Optional Protocols TLS certificate (.pfx) files will be included in the backup only if they exist within the DNS server's config folder. Default value is `false`.
- `logSettings` (optional): Set to `true` to backup log settings file. Default value is `false`.
- `zones` (optional): Set to `true` to backup DNS zone files. Default value is `false`.
- `allowedZones` (optional): Set to `true` to backup allowed zones file. Default value is `false`.
- `blockedZones` (optional): Set to `true` to backup blocked zones file. Default value is `false`.
- `blockLists` (optional): Set to `true` to backup block lists cache files. Default value is `false`.
- `apps` (optional): Set to `true` to backup the installed DNS apps. Default value is `false`.
- `stats` (optional): Set to `true` to backup dashboard stats files. Default value is `false`.
- `logs` (optional): Set to `true` to backup log files. Default value is `false`.

RESPONSE:
A zip file with content type `application/zip` and content disposition set to `attachment`.

### Restore Settings

This call restores selected items from a given backup zip file.

URL:\
`http://localhost:5380/api/settings/restore?blockLists=true&logs=true&stats=true&zones=true&allowedZones=true&blockedZones=true&dnsSettings=true&logSettings=true&deleteExistingFiles=true&authConfig=true`

PERMISSIONS:\
Settings: Delete

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `authConfig` (optional): Set to `true` to restore the authentication config file. Default value is `false`.
- `webServiceSettings` (optional): Set to `true` to restore the web service config file. Default value is `false`.
- `dnsSettings` (optional): Set to `true` to restore DNS settings and certificate files. Default value is `false`.
- `logSettings` (optional): Set to `true` to restore log settings file. Default value is `false`.
- `zones` (optional): Set to `true` to restore DNS zone files. Default value is `false`.
- `allowedZones` (optional): Set to `true` to restore allowed zones file. Default value is `false`.
- `blockedZones` (optional): Set to `true` to restore blocked zones file. Default value is `false`.
- `blockLists` (optional): Set to `true` to restore block lists cache files. Default value is `false`.
- `apps` (optional): Set to `true` to restore the DNS apps. Default value is `false`.
- `stats` (optional): Set to `true` to restore dashboard stats files. Default value is `false`.
- `logs` (optional): Set to `true` to restore log files. Default value is `false`.
- `deleteExistingFiles` (optional). Set to `true` to delete existing files for selected items. Default value is `false`.

REQUEST:
This is a `POST` request call where the request must be multi-part form data with the backup zip file data in binary format.

RESPONSE:
This call returns the newly updated settings in the same format as that of the `getDnsSettings` call.

## Administration API Calls

Allows managing the DNS server administration which includes managing all sessions, users, groups, and permissions.

### List Sessions

Returns a list of active user sessions.

URL:\
`http://localhost:5380/api/admin/sessions/list`

PERMISSIONS:\
Administration: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"response": {
		"sessions": [
			{
				"username": "admin",
				"isCurrentSession": true,
				"partialToken": "272f4890427b9ab5",
				"type": "Standard",
				"tokenName": null,
				"lastSeen": "2022-09-17T13:23:44.9972772Z",
				"lastSeenRemoteAddress": "127.0.0.1",
				"lastSeenUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0"
			},
			{
				"username": "admin",
				"isCurrentSession": false,
				"partialToken": "ddfaecb8e9325e77",
				"type": "ApiToken",
				"tokenName": "MyToken1",
				"lastSeen": "2022-09-17T13:22:45.6710766Z",
				"lastSeenRemoteAddress": "127.0.0.1",
				"lastSeenUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0"
			}
		]
	},
	"status": "ok"
}
```

### Create API Token

Allows creating a non-expiring API token that can be used with automation scripts to make API calls. The token allows access to API calls with the same privileges as that of the user and thus its advised to create a separate user with limited permissions required for creating the API token. The token cannot be used to change the user's password, or update the user profile details.

URL:\
`http://localhost:5380/api/admin/sessions/createToken?user=admin&tokenName=MyToken1`

PERMISSIONS:\
Administration: Modify

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `user`: The username for the user account for which to generate the API token.
- `tokenName`: The name of the created token to identify its session.

RESPONSE:
```
{
	"response": {
		"username": "admin",
		"tokenName": "MyToken1",
		"token": "ddfaecb8e9325e77865ee7e100f89596a65d3eae0e6dddcb33172355b95a64af"
	},
	"status": "ok"
}
```

### Delete Session

Deletes a specified user's session.

URL:\
`http://localhost:5380/api/admin/sessions/delete?partialToken=ddfaecb8e9325e77`

PERMISSIONS:\
Administration: Delete

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `partialToken`: The partial token of the session to delete that was returned by the list of sessions.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

### List Users

Returns a list of all users.

URL:\
`http://localhost:5380/api/admin/users/list`

PERMISSIONS:\
Administration: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"response": {
		"users": [
			{
				"displayName": "Administrator",
				"username": "admin",
				"isSsoUser": false,
				"disabled": false,
				"previousSessionLoggedOn": "2022-09-17T13:20:32.7933783Z",
				"previousSessionRemoteAddress": "127.0.0.1",
				"recentSessionLoggedOn": "2022-09-17T13:22:45.671081Z",
				"recentSessionRemoteAddress": "127.0.0.1"
			},
			{
				"displayName": "Shreyas Zare",
				"username": "shreyas",
				"isSsoUser": false,
				"disabled": false,
				"previousSessionLoggedOn": "0001-01-01T00:00:00Z",
				"previousSessionRemoteAddress": "0.0.0.0",
				"recentSessionLoggedOn": "0001-01-01T00:00:00Z",
				"recentSessionRemoteAddress": "0.0.0.0"
			}
		]
	},
	"status": "ok"
}
```

### Create User

Creates a new user account.

URL:\
`http://localhost:5380/api/admin/users/create?displayName=User&user=user1&pass=password`

PERMISSIONS:\
Administration: Modify

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `user`: A unique username for the user account.
- `pass`: A password for the user account.
- `displayName` (optional): The display name for the user account.

RESPONSE:
```
{
	"response": {
		"displayName": "User",
		"username": "user1",
		"isSsoUser": false,
		"disabled": false,
		"previousSessionLoggedOn": "0001-01-01T00:00:00",
		"previousSessionRemoteAddress": "0.0.0.0",
		"recentSessionLoggedOn": "0001-01-01T00:00:00",
		"recentSessionRemoteAddress": "0.0.0.0"
	},
	"status": "ok"
}
```

### Get User Details

Returns a user account profile details.

URL:\
`http://localhost:5380/api/admin/users/get?user=admin&includeGroups=true

PERMISSIONS:\
Administration: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `user`: The username for the user account.
- `includeGroups` (optional): Set `true` to include a list of groups in response.

RESPONSE:
```
{
	"response": {
		"displayName": "Administrator",
		"username": "admin",
		"isSsoUser": false,
		"totpEnabled": false,
		"disabled": false,
		"previousSessionLoggedOn": "2022-09-16T13:22:45.671Z",
		"previousSessionRemoteAddress": "127.0.0.1",
		"recentSessionLoggedOn": "2022-09-18T09:55:26.9800695Z",
		"recentSessionRemoteAddress": "127.0.0.1",
		"sessionTimeoutSeconds": 1800,
		"memberOfGroups": [
			"Administrators"
		],
		"sessions": [
			{
				"username": "admin",
				"isCurrentSession": false,
				"partialToken": "1f8011516cea27af",
				"type": "Standard",
				"tokenName": null,
				"lastSeen": "2022-09-18T09:55:40.6519988Z",
				"lastSeenRemoteAddress": "127.0.0.1",
				"lastSeenUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0"
			},
			{
				"username": "admin",
				"isCurrentSession": false,
				"partialToken": "ddfaecb8e9325e77",
				"type": "ApiToken",
				"tokenName": "MyToken1",
				"lastSeen": "2022-09-17T13:22:45.671Z",
				"lastSeenRemoteAddress": "127.0.0.1",
				"lastSeenUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0"
			}
		],
		"groups": [
			"Administrators",
			"DNS Administrators"
		]
	},
	"status": "ok"
}
```

### Set User Details

Allows changing user account profile details.

URL:\
`http://localhost:5380/api/admin/users/set?user=admin&displayName=Administrator&disabled=false&sessionTimeoutSeconds=1800&memberOfGroups=Administrators`

PERMISSIONS:\
Administration: Modify

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `user`: The username for the user account.
- `displayName` (optional): The display name for the user account. For SSO users, the display name is managed by SSO provider and cannot be changed with this API call.
- `newUser` (optional): A new username for renaming the username for the user account. For SSO users, the username is managed by SSO provider and cannot be changed with this API call.
- `totpEnabled` (optional): Set to `false` to disable 2FA for the user account. The parameter cannot have a `true` value. For SSO users, 2FA is managed by SSO provider and cannot be enabled with this API call.
- `disabled` (optional): Set `true` to disable the user account and delete all its active sessions.
- `sessionTimeoutSeconds` (optional): A session time out value in seconds for the user account.
- `newPass` (optional): A new password to reset the user account password. For SSO users, the password is managed by SSO provider and cannot be changed with this API call.
- `iterations` (optional): The number of iterations for PBKDF2 SHA256 password hashing. This is only used with the `newPass` option.
- `memberOfGroups` (optional): A list of comma separated group names that the user must be set as a member. For SSO users, the group membership is managed by SSO provider if SSO Group Map was configured and cannot be changed with this API call in that case.

RESPONSE:
```
{
	"response": {
		"displayName": "Administrator",
		"username": "admin",
		"isSsoUser": false,
		"totpEnabled": false,
		"disabled": false,
		"previousSessionLoggedOn": "2022-09-17T13:22:45.671Z",
		"previousSessionRemoteAddress": "127.0.0.1",
		"recentSessionLoggedOn": "2022-09-18T09:55:26.9800695Z",
		"recentSessionRemoteAddress": "127.0.0.1",
		"sessionTimeoutSeconds": 1800,
		"memberOfGroups": [
			"Administrators"
		],
		"sessions": [
			{
				"username": "admin",
				"isCurrentSession": false,
				"partialToken": "1f8011516cea27af",
				"type": "Standard",
				"tokenName": null,
				"lastSeen": "2022-09-18T09:59:19.9034491Z",
				"lastSeenRemoteAddress": "127.0.0.1",
				"lastSeenUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0"
			},
			{
				"username": "admin",
				"isCurrentSession": false,
				"partialToken": "ddfaecb8e9325e77",
				"type": "ApiToken",
				"tokenName": "MyToken1",
				"lastSeen": "2022-09-17T13:22:45.671Z",
				"lastSeenRemoteAddress": "127.0.0.1",
				"lastSeenUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0"
			}
		]
	},
	"status": "ok"
}
```

### Delete User

Deletes a user account.

URL:\
`http://localhost:5380/api/admin/users/delete?user=user1`

PERMISSIONS:\
Administration: Delete

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `user`: The username for the user account to delete.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

### List Groups

Returns a list of all groups.

URL:\
`http://localhost:5380/api/admin/groups/list`

PERMISSIONS:\
Administration: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"response": {
		"groups": [
			{
				"name": "Administrators",
				"description": "Super administrators"
			},
			{
				"name": "DNS Administrators",
				"description": "DNS service administrators"
			}
		]
	},
	"status": "ok"
}
```

### Create Group

Creates a new group.

URL:\
`http://localhost:5380/api/admin/groups/create?group=Group1&description=My%20description`

PERMISSIONS:\
Administration: Modify

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `group`: The name of the group to create.
- `description` (optional): The description text for the group.

RESPONSE:
```
{
	"response": {
		"name": "Group1",
		"description": "My description"
	},
	"status": "ok"
}
```

### Get Group Details

Returns the details for a group.

URL:\
`http://localhost:5380/api/admin/groups/get?group=Administrators&includeUsers=true`

PERMISSIONS:\
Administration: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `group`: The name of the group.
- `includeUsers` (optional): Set `true` to include a list of users in response.

RESPONSE:
```
{
	"response": {
		"name": "Administrators",
		"description": "Super administrators",
		"members": [
			"admin"
		],
		"users": [
			"admin",
			"shreyas"
		]
	},
	"status": "ok"
}
```

### Set Group Details

Allows changing group description or rename a group.

URL:\
`http://localhost:5380/api/admin/groups/set?group=Administrators&description=Super%20administrators&members=admin`

PERMISSIONS:\
Administration: Modify

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `group`: The name of the group to update.
- `newGroup` (optional): A new group name to rename the group.
- `description` (optional): A new group description.
- `members` (optional): A comma separated list of usernames to set as the group's members.

RESPONSE:
```
{
	"response": {
		"name": "Administrators",
		"description": "Super administrators",
		"members": [
			"admin"
		]
	},
	"status": "ok"
}
```

### Delete Group

Allows deleting a group.

URL:\
`http://localhost:5380/api/admin/groups/delete?group=Group1`

PERMISSIONS:\
Administration: Delete

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `group`: The name of the group to delete.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

### List Permissions

URL:\
`http://localhost:5380/api/admin/permissions/list`

PERMISSIONS:\
Administration: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"response": {
		"permissions": [
			{
				"section": "Dashboard",
				"userPermissions": [],
				"groupPermissions": [
					{
						"name": "Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "Everyone",
						"canView": true,
						"canModify": false,
						"canDelete": false
					}
				]
			},
			{
				"section": "Zones",
				"userPermissions": [],
				"groupPermissions": [
					{
						"name": "Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "DNS Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "Everyone",
						"canView": true,
						"canModify": false,
						"canDelete": false
					}
				]
			},
			{
				"section": "Cache",
				"userPermissions": [],
				"groupPermissions": [
					{
						"name": "Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "DNS Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "Everyone",
						"canView": true,
						"canModify": false,
						"canDelete": false
					}
				]
			},
			{
				"section": "Allowed",
				"userPermissions": [],
				"groupPermissions": [
					{
						"name": "Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "DNS Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "Everyone",
						"canView": true,
						"canModify": false,
						"canDelete": false
					}
				]
			},
			{
				"section": "Blocked",
				"userPermissions": [],
				"groupPermissions": [
					{
						"name": "Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "DNS Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "Everyone",
						"canView": true,
						"canModify": false,
						"canDelete": false
					}
				]
			},
			{
				"section": "Apps",
				"userPermissions": [],
				"groupPermissions": [
					{
						"name": "Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "DNS Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "Everyone",
						"canView": true,
						"canModify": false,
						"canDelete": false
					}
				]
			},
			{
				"section": "DnsClient",
				"userPermissions": [],
				"groupPermissions": [
					{
						"name": "Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "DNS Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "Everyone",
						"canView": true,
						"canModify": false,
						"canDelete": false
					}
				]
			},
			{
				"section": "Settings",
				"userPermissions": [],
				"groupPermissions": [
					{
						"name": "Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "DNS Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					}
				]
			},
			{
				"section": "Administration",
				"userPermissions": [],
				"groupPermissions": [
					{
						"name": "Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					}
				]
			},
			{
				"section": "Logs",
				"userPermissions": [],
				"groupPermissions": [
					{
						"name": "Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "DNS Administrators",
						"canView": true,
						"canModify": false,
						"canDelete": false
					},
					{
						"name": "Everyone",
						"canView": true,
						"canModify": false,
						"canDelete": false
					}
				]
			}
		]
	},
	"status": "ok"
}
```

### Get Permission Details

Gets details of the permissions for the specified section.

URL:\
`http://localhost:5380/api/admin/permissions/get?section=Dashboard&includeUsersAndGroups=true`

PERMISSIONS:\
Administration: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `section`: The name of the section as given in the list of permissions API call.
- `includeUsersAndGroups` (optional): Set to `true` to include a list of users and groups in the response.

RESPONSE:
```
{
	"response": {
		"section": "Dashboard",
		"userPermissions": [
			{
				"username": "shreyas",
				"canView": true,
				"canModify": false,
				"canDelete": false
			}
		],
		"groupPermissions": [
			{
				"name": "Administrators",
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			{
				"name": "Everyone",
				"canView": true,
				"canModify": false,
				"canDelete": false
			}
		],
		"users": [
			"admin",
			"shreyas"
		],
		"groups": [
			"Administrators",
			"DNS Administrators",
			"Everyone"
		]
	},
	"status": "ok"
}
```

### Set Permission Details

Allows changing permissions for the specified section.

URL:\
`http://localhost:5380/api/admin/permissions/set?section=Dashboard&userPermissions=shreyas|true|false|false&groupPermissions=Administrators|true|true|true|Everyone|true|false|false`

PERMISSIONS:\
Administration: Delete

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `section`: The name of the section as given in the list of permissions API call.
- `userPermissions` (optional): A pipe `|` separated table data with each row containing username and boolean values for the view, modify and delete permissions. For example: user1|true|true|true|user2|true|false|false
- `groupPermissions` (optional): A pipe `|` separated table data with each row containing the group name and boolean values for the view, modify and delete permissions. For example: group1|true|true|true|group2|true|true|false

RESPONSE:
```
{
	"response": {
		"section": "Dashboard",
		"userPermissions": [
			{
				"username": "shreyas",
				"canView": true,
				"canModify": false,
				"canDelete": false
			}
		],
		"groupPermissions": [
			{
				"name": "Administrators",
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			{
				"name": "Everyone",
				"canView": true,
				"canModify": false,
				"canDelete": false
			}
		]
	},
	"status": "ok"
}
```

### Get SSO Config

Returns the current Single Sign-On (SSO) configuration.

URL:\
`http://localhost:5380/api/admin/sso/get?includeGroups=true`

PERMISSIONS:\
Administration: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `includeGroups` (optional): Set to `true` to include a list of local groups.

RESPONSE:
```
{
	"response": {
		"ssoEnabled": false,
		"ssoAuthority": null,
		"ssoClientId": null,
		"ssoClientSecret": "************",
		"ssoMetadataAddress": null,
		"ssoAllowSignup": false,
		"ssoAllowSignupOnlyForMappedUsers": true,
		"ssoGroupMap": [],
		"localGroups": [
			"Administrators",
			"DNS Administrators"
		]
	},
	"server": "server1",
	"status": "ok"
}
```

### Set SSO Config

Allows to update the Single Sign-On (SSO) configuration and restarts the Web Service automatically, if required to apply changes.

URL:\
`http://localhost:5380/api/admin/sso/set`

PERMISSIONS:\
Administration: Delete

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `ssoEnabled` (optional): Set to `true` to allow Single Sign-On (SSO) with OpenID Connect (OIDC).
- `ssoAuthority` (optional): The OpenID Connect (OIDC) Authority URL.
- `ssoClientId` (optional): The OpenID Connect (OIDC) Client ID.
- `ssoClientSecret` (optional): The OpenID Connect (OIDC) Client Secret.
- `ssoMetadataAddress` (optional): The OpenID Connect (OIDC) metadata discovery URL to be used instead of the default one. Configure this option only if the Single Sign-On (SSO) provider uses a different discovery URL.
- `ssoAllowSignup` (optional): Set to `true` to allow automatically provisioning of user accounts for new users signing in via Single Sign-On (SSO). Keep this option set to `false` if you do not expect new SSO users to sign up.
- `ssoAllowSignupOnlyForMappedUsers` (optional): Set to `true` to allow a new user to sign up via Single Sign-On (SSO) only when the user is a member of at least one Remote Group that is mapped to a Local Group in the Group Map option below. This option allows SSO administrators to restrict SSO users to control who can sign up and get access based on their group memberships.
- `ssoGroupMap` (optional): A pipe `|` separated table data with each row containing Remote Group name and a corresponding Local Group name. Maps Remote Groups at Single Sign-On (SSO) provider to Local Groups for both new and existing users signed up via Single Sign-On (SSO). A SSO user's group membership will be automatically synced to the mapped Local Groups each time they log in.

RESPONSE:
```
{
	"response": {
		"ssoEnabled": false,
		"ssoAuthority": null,
		"ssoClientId": null,
		"ssoClientSecret": "************",
		"ssoMetadataAddress": null,
		"ssoAllowSignup": false,
		"ssoAllowSignupOnlyForMappedUsers": true,
		"ssoGroupMap": [],
		"localGroups": [
			"Administrators",
			"DNS Administrators"
		]
	},
	"server": "server1",
	"status": "ok"
}
```

## Log API Calls

### List Logs

Lists all logs files available on the DNS server.

URL:\
`http://localhost:5380/api/logs/list`

PERMISSIONS:\
Logs: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"response": {
		"logFiles": [
			{
				"fileName": "2020-09-19",
				"size": "8.14 KB"
			},
			{
				"fileName": "2020-09-15",
				"size": "5.6 KB"
			},
			{
				"fileName": "2020-09-12",
				"size": "18.4 KB"
			},
			{
				"fileName": "2020-09-11",
				"size": "1.78 KB"
			},
			{
				"fileName": "2020-09-10",
				"size": "2.03 KB"
			}
		]
	},
	"status": "ok"
}
```

### Download Log

Downloads the log file.

URL:\
`http://localhost:5380/api/logs/download?fileName=2020-09-10&limit=2`

PERMISSIONS:\
Logs: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `fileName`: The `fileName` returned by the List Logs API call.
- `limit` (optional): The limit of number of mega bytes to download the log file. Default value is `0` when parameter is missing which indicates there is no limit.

RESPONSE:
Response is a downloadable file with `Content-Type: text/plain` and `Content-Disposition: attachment;filename=name`

### Delete Log

Permanently deletes a log file from the disk.

URL: 
`http://localhost:5380/api/logs/delete?log=2020-09-19`

PERMISSIONS:\
Logs: Delete

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `log`: The `fileName` returned by the List Logs API call.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

### Delete All Logs

Permanently delete all log files from the disk.

URL:\
`http://localhost:5380/api/logs/deleteAll`

PERMISSIONS:\
Logs: Delete

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

### Query Logs

Queries for logs to a specified DNS app.

URL:\
`http://localhost:5380/api/logs/query?name=AppName&classPath=AppClassPath&=pageNumber=1&entriesPerPage=10&descendingOrder=true&start=yyyy-MM-dd HH:mm:ss&end=yyyy-MM-dd HH:mm:ss&clientIpAddress=&protocol=&responseType=&rcode=&qname=&qtype=&qclass=`

PERMISSIONS:\
Logs: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the installed DNS app.
- `classPath`: The class path of the DNS app.
- `pageNumber` (optional): The page number of the data set to retrieve.
- `entriesPerPage` (optional): The number of entries per page.
- `descendingOrder` (optional): Orders the selected data set in descending order.
- `start` (optional): The start date time in ISO 8601 format to filter the logs.
- `end` (optional): The end date time in ISO 8601 format to filter the logs.
- `clientIpAddress` (optional): The client IP address to filter the logs.
- `protocol` (optional): The DNS transport protocol to filter the logs. Valid values are [`Udp`, `Tcp`, `Tls`, `Https`, `Quic`].
- `responseType` (optional): The DNS server response type to filter the logs. Valid values are [`Authoritative`, `Recursive`, `Cached`, `Blocked`, `UpstreamBlocked`, `CacheBlocked`].
- `rcode` (optional): The DNS response code to filter the logs.
- `qname` (optional): The query name (QNAME) in the request question section to filter the logs.
- `qtype` (optional): The DNS resource record type (QTYPE) in the request question section to filter the logs.
- `qclass` (optional): The DNS class (QCLASS) in the request question section to filter the logs.

RESPONSE:
```
{
	"response": {
		"pageNumber": 1,
		"totalPages": 2,
		"totalEntries": 13,
		"entries": [
			{
				"rowNumber": 1,
				"timestamp": "2021-09-10T12:22:52Z",
				"clientIpAddress": "127.0.0.1",
				"protocol": "Udp",
				"responseType": "Recursive",
				"responseRtt": 33.45,
				"rcode": "NoError",
				"qname": "google.com",
				"qtype": "A",
				"qclass": "IN",
				"answer": "172.217.166.46"
			},
			{
				"rowNumber": 2,
				"timestamp": "2021-09-10T12:37:02Z",
				"clientIpAddress": "127.0.0.1",
				"protocol": "Udp",
				"responseType": "Blocked",
				"rcode": "NxDomain",
				"qname": "example.com",
				"qtype": "A",
				"qclass": "IN",
				"answer": ""
			},
			{
				"rowNumber": 3,
				"timestamp": "2021-09-11T09:13:31Z",
				"clientIpAddress": "127.0.0.1",
				"protocol": "Udp",
				"responseType": "Authoritative",
				"rcode": "ServerFailure",
				"qname": "example.com",
				"qtype": "A",
				"qclass": "IN",
				"answer": ""
			},
			{
				"rowNumber": 4,
				"timestamp": "2021-09-11T09:14:48Z",
				"clientIpAddress": "127.0.0.1",
				"protocol": "Udp",
				"responseType": "Authoritative",
				"rcode": "ServerFailure",
				"qname": "example.com",
				"qtype": "A",
				"qclass": "IN",
				"answer": ""
			},
			{
				"rowNumber": 5,
				"timestamp": "2021-09-11T09:27:25Z",
				"clientIpAddress": "127.0.0.1",
				"protocol": "Udp",
				"responseType": "Blocked",
				"rcode": "NxDomain",
				"qname": "example.com",
				"qtype": "A",
				"qclass": "IN",
				"answer": ""
			},
			{
				"rowNumber": 6,
				"timestamp": "2021-09-11T09:27:29Z",
				"clientIpAddress": "127.0.0.1",
				"protocol": "Udp",
				"responseType": "Blocked",
				"rcode": "NxDomain",
				"qname": "www.example.com",
				"qtype": "A",
				"qclass": "IN",
				"answer": ""
			},
			{
				"rowNumber": 7,
				"timestamp": "2021-09-11T09:28:36Z",
				"clientIpAddress": "127.0.0.1",
				"protocol": "Udp",
				"responseType": "Blocked",
				"rcode": "NxDomain",
				"qname": "www.example.com",
				"qtype": "A",
				"qclass": "IN",
				"answer": ""
			},
			{
				"rowNumber": 8,
				"timestamp": "2021-09-11T09:28:41Z",
				"clientIpAddress": "127.0.0.1",
				"protocol": "Udp",
				"responseType": "Blocked",
				"rcode": "NxDomain",
				"qname": "example.com",
				"qtype": "A",
				"qclass": "IN",
				"answer": ""
			},
			{
				"rowNumber": 9,
				"timestamp": "2021-09-11T09:28:44Z",
				"clientIpAddress": "127.0.0.1",
				"protocol": "Udp",
				"responseType": "Blocked",
				"rcode": "NxDomain",
				"qname": "sdfsdf.example.com",
				"qtype": "A",
				"qclass": "IN",
				"answer": ""
			},
			{
				"rowNumber": 10,
				"timestamp": "2021-09-11T09:42:02Z",
				"clientIpAddress": "127.0.0.1",
				"protocol": "Udp",
				"responseType": "Recursive",
				"responseRtt": 23.63,
				"rcode": "NoError",
				"qname": "example.com",
				"qtype": "A",
				"qclass": "IN",
				"answer": "139.59.3.235"
			}
		]
	},
	"status": "ok"
}
```

### Export Query Logs

Queries for logs to a specified DNS app and exports the data as a CSV file.

URL:\
`http://localhost:5380/api/logs/export?name=AppName&classPath=AppClassPath&start=yyyy-MM-dd HH:mm:ss&end=yyyy-MM-dd HH:mm:ss&clientIpAddress=&protocol=&responseType=&rcode=&qname=&qtype=&qclass=`

PERMISSIONS:\
Logs: View

HEADERS:
- Authorization: Bearer <token>

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the installed DNS app.
- `classPath`: The class path of the DNS app.
- `start` (optional): The start date time in ISO 8601 format to filter the logs.
- `end` (optional): The end date time in ISO 8601 format to filter the logs.
- `clientIpAddress` (optional): The client IP address to filter the logs.
- `protocol` (optional): The DNS transport protocol to filter the logs. Valid values are [`Udp`, `Tcp`, `Tls`, `Https`, `Quic`].
- `responseType` (optional): The DNS server response type to filter the logs. Valid values are [`Authoritative`, `Recursive`, `Cached`, `Blocked`, `UpstreamBlocked`, `CacheBlocked`].
- `rcode` (optional): The DNS response code to filter the logs.
- `qname` (optional): The query name (QNAME) in the request question section to filter the logs.
- `qtype` (optional): The DNS resource record type (QTYPE) in the request question section to filter the logs.
- `qclass` (optional): The DNS class (QCLASS) in the request question section to filter the logs.

RESPONSE: Response is a downloadable text file with `Content-Type: text/csv` and `Content-Disposition: attachment` headers set.
