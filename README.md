# Enterprise SIEM Integration: Unified Perimeter & Endpoint Telemetry (Wazuh, pfSense/Suricata & Windows Sysmon)

## Overview
This project demonstrates the end-to-end engineering of a centralized, enterprise-grade Security Information and Event Management (SIEM) architecture built entirely with open-source tools. By correlating agentless perimeter firewall/IPS logs from **pfSense and Suricata** with deep endpoint telemetry from a **Windows Server Active Directory Domain Controller running Sysmon**, this environment replicates a real-world Tier 1/Tier 2 SOC visibility stack.

---

## Lab Architecture & Network Topology

| Hostname | Role | Operating System | IP Address | Telemetry Protocol / Port |
| :--- | :--- | :--- | :--- | :--- |
| **`sec-box`** | Wazuh Manager, Indexer & Dashboard (`v4.9.2`) | Ubuntu Linux | `10.0.0.10` | Receives Syslog (`514/UDP`) & Agent (`1514/TCP`, `1515/TCP`) |
| **`pfSense`** | Edge Firewall & Suricata IPS | FreeBSD (pfSense) | `10.0.0.6` | Agentless BSD (RFC 3164) Syslog ➔ `10.0.0.10:514/UDP` |
| **`project-x-dc`** | Active Directory Domain Controller (`CORP`) | Windows Server | `10.0.0.5` | Wazuh Agent (`v4.9.2`) + Sysmon ➔ `10.0.0.10:1514/TCP` |

```text
[ pfSense + Suricata IPS (10.0.0.6) ] ──(BSD Syslog / UDP 514)──┐
                                                                ▼
                                               [ Wazuh SIEM on sec-box (10.0.0.10) ]
                                                                ▲
[ project-x-dc + Sysmon (10.0.0.5) ] ──(Wazuh Agent / TCP 1514)─┘
