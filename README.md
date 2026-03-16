# Zenitium DNS

A fork of Technitium DNS

## What's different?

* Reworked and modernized Network Code, for lower latency, less CPU and RAM usage.
* Fixed various culprits with DNSSEC validations, which lead to high latency.
* Fixed QUIC Protocol, which currently let Technitium DNS built-in QUIC crash after a while.
* Added Ratio Checks to combat Water Torture Attacks, IODINE like DNS Tunneling and various other attacks.
* Added a system which requires new UDP 53 clients to "authenticate" their real IP with truncation, to combat spoofed IPs.
* Reworked WebUI Graphs for better reading.
* Enirely removed DHCP and Cluster features.
* Enhanced Caching Engine with three hour hot caching instead of one hour.
* Better iterations of cache and blocklists for lower latency and ram and CPU usage.
* Fixed hotpaths in the engines and improved usage of asyncs.
* Removed obsolete .NET codes and replaced functions and logics with .NET8/9 code.

> [!CAUTION]
> This Fork is not meant for Homeserver or Homenetwork use!