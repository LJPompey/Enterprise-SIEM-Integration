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

1. Perimeter Log Ingestion (pfSense & Suricata)
Configured pfSense remote logging using BSD (RFC 3164) format to forward firewall (filterlog), web service (nginx/php-fpm), and Suricata WAN IPS alerts directly to the Wazuh Manager.

Engineered custom Wazuh detection rules in /var/ossec/etc/rules/local_rules.xml to classify baseline perimeter syslog traffic (level 5) and escalate Suricata IPS alert/block events (level 10):

<group name="pfsense,suricata,perimeter,">
  <rule id="100100" level="5">
    <decoded_as>pf</decoded_as>
    <description>pfSense firewall event logged ($(action) $(protocol) from $(srcip) to $(dstip)).</description>
  </rule>

  <rule id="100102" level="5">
    <location>10.0.0.6</location>
    <description>pfSense perimeter syslog event received from 10.0.0.6.</description>
  </rule>

  <rule id="100101" level="10">
    <if_sid>100100,100102</if_sid>
    <match>suricata|SURICATA|alert|ALERT|drop|DROP|block|BLOCK</match>
    <description>Suricata IPS alert or block event reported by pfSense perimeter.</description>
  </rule>
</group>

