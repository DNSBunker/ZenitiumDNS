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

using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using ZenitiumLibrary.Net.Dns;
using ZenitiumLibrary.Net.Dns.ResourceRecords;

namespace ZenitiumDns.ApplicationCommon
{
    public interface IDnsQueryLogs
    {
        Task<DnsLogPage> QueryLogsAsync(long pageNumber, int entriesPerPage, bool descendingOrder, DateTime? start, DateTime? end, IPAddress? clientIpAddress, DnsTransportProtocol? protocol, DnsServerResponseType? responseType, DnsResponseCode? rcode, string? qname, DnsResourceRecordType? qtype, DnsClass? qclass);
    }

    public class DnsLogPage
    {
        #region variables

        readonly long _pageNumber;
        readonly long _totalPages;
        readonly long _totalEntries;
        readonly IReadOnlyList<DnsLogEntry> _entries;

        #endregion

        #region constructor

        public DnsLogPage(long pageNumber, long totalPages, long totalEntries, IReadOnlyList<DnsLogEntry> entries)
        {
            _pageNumber = pageNumber;
            _totalPages = totalPages;
            _totalEntries = totalEntries;
            _entries = entries;
        }

        #endregion

        #region properties

        public long PageNumber
        { get { return _pageNumber; } }

        public long TotalPages
        { get { return _totalPages; } }

        public long TotalEntries
        { get { return _totalEntries; } }

        public IReadOnlyList<DnsLogEntry> Entries
        { get { return _entries; } }

        #endregion
    }

    public class DnsLogEntry
    {
        #region variables

        readonly long _rowNumber;
        readonly DateTime _timestamp;
        readonly IPAddress _clientIpAddress;
        readonly DnsTransportProtocol _protocol;
        readonly DnsServerResponseType _responseType;
        readonly double? _responseRtt;
        readonly DnsResponseCode _rcode;
        readonly DnsQuestionRecord? _question;
        readonly string? _answer;

        #endregion

        #region constructor

        public DnsLogEntry(long rowNumber, DateTime timestamp, IPAddress clientIpAddress, DnsTransportProtocol protocol, DnsServerResponseType responseType, double? responseRtt, DnsResponseCode rcode, DnsQuestionRecord? question, string? answer)
        {
            _rowNumber = rowNumber;
            _timestamp = timestamp;
            _clientIpAddress = clientIpAddress;
            _protocol = protocol;
            _responseType = responseType;
            _responseRtt = responseRtt;
            _rcode = rcode;
            _question = question;
            _answer = answer;

            switch (_timestamp.Kind)
            {
                case DateTimeKind.Local:
                    _timestamp = _timestamp.ToUniversalTime();
                    break;

                case DateTimeKind.Unspecified:
                    _timestamp = DateTime.SpecifyKind(_timestamp, DateTimeKind.Utc);
                    break;
            }
        }

        public DnsLogEntry(long rowNumber, DateTime timestamp, IPAddress clientIpAddress, DnsTransportProtocol protocol, DnsServerResponseType responseType, DnsResponseCode rcode, DnsQuestionRecord question, string answer)
        {
            _rowNumber = rowNumber;
            _timestamp = timestamp;
            _clientIpAddress = clientIpAddress;
            _protocol = protocol;
            _responseType = responseType;
            _rcode = rcode;
            _question = question;
            _answer = answer;

            switch (_timestamp.Kind)
            {
                case DateTimeKind.Local:
                    _timestamp = _timestamp.ToUniversalTime();
                    break;

                case DateTimeKind.Unspecified:
                    _timestamp = DateTime.SpecifyKind(_timestamp, DateTimeKind.Utc);
                    break;
            }
        }

        #endregion

        #region properties

        public long RowNumber
        { get { return _rowNumber; } }

        public DateTime Timestamp
        { get { return _timestamp; } }

        public IPAddress ClientIpAddress
        { get { return _clientIpAddress; } }

        public DnsTransportProtocol Protocol
        { get { return _protocol; } }

        public DnsServerResponseType ResponseType
        { get { return _responseType; } }

        public double? ResponseRtt
        { get { return _responseRtt; } }

        public DnsResponseCode RCODE
        { get { return _rcode; } }

        public DnsQuestionRecord? Question
        { get { return _question; } }

        public string? Answer
        { get { return _answer; } }

        #endregion
    }
}
