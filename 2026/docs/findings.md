# Finding Templates Reference

This page covers the 141 SysReptor finding templates in [`../templates/`](../templates/). Each template is a pre-written finding: the description, impact, recommendation and references are already filled in. During the engagement you only add what you actually observed: the affected hosts and the proof of exploitation.

All templates are written for the **CPTC12 2026-2027 - Butters Family Farms** design (`design-CPTC12-2026-2027-Butters-Family-Farms.tar.gz`). See the [main README](../README.md#importing-into-sysreptor) for how to import them.

## Contents

- [Finding fields](#finding-fields)
- [How severity is shown in the report](#how-severity-is-shown-in-the-report)
- [CVSS vectors in use](#cvss-vectors-in-use)
- [Templates at a glance](#templates-at-a-glance)
- [Templates by environment](#templates-by-environment)
  - [Active Directory](#active-directory-72)
  - [Web Application](#web-application-43)
  - [Network Service](#network-service-25)
  - [Unclassified](#unclassified-1)
- [Archive format](#archive-format)

## Finding fields

Every template fills in the finding fields that the design defines. The last column gives the heading each field appears under in the rendered PDF.

| Field ID | Label | Type | Required | Pre-filled in templates? | In the PDF as |
|---|---|---|---|---|---|
| `title` | Title | string | Yes | Yes | Finding heading |
| `severity` | Severity | enum: `low` `medium` `high` `critical` | Yes | Yes | *Not rendered* (see [below](#how-severity-is-shown-in-the-report)) |
| `cvss` | CVSS | CVSS vector | Yes | Yes | Risk Level, CVSS Score, CVSS Vector |
| `affected_components` | Affected Components | list of strings | Yes | **No, always empty** | Affected Systems |
| `summary` | Summary | markdown | Yes | Yes | Security Overview |
| `short_recommendation` | Short Recommendation | string | Yes | Yes | Quick Fix |
| `description` | Technical Description | markdown | Yes | Yes | Technical Analysis |
| `impact` | Impact | markdown | Yes | Yes | Business Impact |
| `recommendation` | Recommendation | markdown | Yes | Yes | Remediation |
| `references` | References | list of strings | No | Yes | References |
| `vulnerability` | Vulnerability Details (Optional) | markdown | No | Yes (140 of 141) | Vulnerability Details (only shown when non-empty) |
| `exploit` | Proof of Exploitation | markdown | No | **No, always empty** | Proof of Exploitation (only shown when non-empty) |
| `environment` | Environment | enum: `service` `web_application` `active_directory` | No | Yes (140 of 141) | *Not rendered*. Used to filter and group in SysReptor. |

What to fill in when you use a template:

- **`affected_components`**: one host, IP, URL, account or component per list item. Every template leaves this empty.
- **`exploit`**: the evidence from this engagement (host or endpoint, prerequisites, steps, screenshots, result). Every template leaves this empty, so you start from the design's default skeleton (`Affected Host / Endpoint`, `Prerequisites / Access`, `Validation` ...).
- **`cvss`**: adjust the vector if what you validated differs from the template's assumptions, for example if authentication was required or the impact was lower. The template vectors are sensible defaults, not measurements.
- **`summary` / `impact`**: tailor them to Butters Family Farm where it adds value.

> **Note:** Each template's JSON also has an `author` field (`"Claude"`). The Butters Family Farms design has no `author` field, so SysReptor drops that value when you create a finding from a template in a project that uses this design. That is expected.

## How severity is shown in the report

The PDF report template **does not use the `severity` field**. The finding badges, the "Risk Level" row and the Critical/High/Medium/Low sections all come from the CVSS score (`cvss.level`). Findings are sorted by CVSS score (highest first), then by title.

Right now every template's `severity` matches the level of its CVSS vector. If you change one, change the other too, or the SysReptor UI and the PDF will disagree.

CVSS level bands: **Critical** 9.0–10.0 · **High** 7.0–8.9 · **Medium** 4.0–6.9 · **Low** 0.1–3.9.

## CVSS vectors in use

The 141 templates use only 10 distinct vectors, and each score in the tables below belongs to exactly one of them. The scores were calculated with SysReptor's own CVSS implementation.

| Score | Level | Templates | Vector | What it means |
|---|---|---:|---|---|
| 9.3 | Critical | 19 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` | Network, no authentication, high confidentiality / integrity / availability impact |
| 8.7 | High | 10 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` | Network, no authentication, high confidentiality impact |
| 8.6 | High | 47 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` | Network, low-privileged user, high confidentiality + integrity impact |
| 8.3 | High | 8 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N` | Network, no authentication, attack requirements present, high confidentiality + low integrity impact |
| 7.1 | High | 1 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N` | CVSS **3.1** vector (only the unfinished SSH template) |
| 6.9 | Medium | 6 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` | Network, no authentication, low confidentiality impact |
| 6.0 | Medium | 14 | `CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` | Adjacent network, attack requirements present, high confidentiality impact |
| 5.3 | Medium | 26 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` | Network, low-privileged user, low confidentiality impact |
| 5.1 | Medium | 3 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` | Network, no authentication, active user interaction, low confidentiality impact |
| 2.3 | Low | 7 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` | Network, low-privileged user, attack requirements present, low confidentiality impact |

## Templates at a glance

| Environment | Critical | High | Medium | Low | Unrated | Total |
|---|---:|---:|---:|---:|---:|---:|
| Active Directory | 1 | 40 | 29 | 2 | – | **72** |
| Web Application | 11 | 16 | 13 | 3 | – | **43** |
| Network Service | 7 | 9 | 7 | 2 | – | **25** |
| Unclassified | – | – | – | – | 1 | **1** |
| **Total** | **19** | **65** | **49** | **7** | **1** | **141** |

The tables below leave out the environment tag (`active_directory`, `web`, `service`), since every template in a group has it. The other tags in use are `adcs`, `kerberos`, `ntlm`, `relay`, `windows`, `injection`, `xss`, `csrf`, `ssrf`, `jwt`, `api`, `ftp`, `tftp`, `snmp`, `smb`, `smtp`, `mail`, `nfs`, `iscsi`, `ipmi`, `cisco`, `telnet`, `vnc` and `ssh`.

## Templates by environment

Within each group, templates are sorted by CVSS score (highest first), then by title. Each title links to its import archive.

### Active Directory (72)

| Finding | Severity | CVSS | Tags |
|---|---|---|---|
| [Zerologon (CVE-2020-1472)](../templates/template-Zerologon-CVE-2020-1472.tar.gz) | Critical | 9.3 | `windows` |
| [ADCS ESC1: Enrollee-Supplied Subject on Authentication Template](../templates/template-ADCS-ESC1-Enrollee-Supplied-Subject-on-Authentication-Template.tar.gz) | High | 8.6 | `adcs` |
| [ADCS ESC2: Any Purpose or No EKU Template](../templates/template-ADCS-ESC2-Any-Purpose-or-No-EKU-Template.tar.gz) | High | 8.6 | `adcs` |
| [ADCS ESC3: Enrollment Agent Template](../templates/template-ADCS-ESC3-Enrollment-Agent-Template.tar.gz) | High | 8.6 | `adcs` |
| [ADCS ESC4: Vulnerable Certificate Template Access Control](../templates/template-ADCS-ESC4-Vulnerable-Certificate-Template-Access-Control.tar.gz) | High | 8.6 | `adcs` |
| [ADCS ESC5: Vulnerable PKI Object Access Control](../templates/template-ADCS-ESC5-Vulnerable-PKI-Object-Access-Control.tar.gz) | High | 8.6 | `adcs` |
| [ADCS ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 Enabled on CA](../templates/template-ADCS-ESC6-EDITF-ATTRIBUTESUBJECTALTNAME2-Enabled-on-CA.tar.gz) | High | 8.6 | `adcs` |
| [ADCS ESC7: Vulnerable Certificate Authority Access Control](../templates/template-ADCS-ESC7-Vulnerable-Certificate-Authority-Access-Control.tar.gz) | High | 8.6 | `adcs` |
| [ADCS ESC8: NTLM Relay to Web Enrollment Endpoint](../templates/template-ADCS-ESC8-NTLM-Relay-to-Web-Enrollment-Endpoint.tar.gz) | High | 8.6 | `adcs` |
| [ADCS ESC11: NTLM Relay to Certificate Enrollment RPC Endpoint](../templates/template-ADCS-ESC11-NTLM-Relay-to-Certificate-Enrollment-RPC-Endpoint.tar.gz) | High | 8.6 | `adcs` |
| [ADCS ESC12: Certificate Authority Private Key Exposure](../templates/template-ADCS-ESC12-Certificate-Authority-Private-Key-Exposure.tar.gz) | High | 8.6 | `adcs` |
| [ADCS ESC13: Certificate Template with Privileged Issuance Policy](../templates/template-ADCS-ESC13-Certificate-Template-with-Privileged-Issuance-Policy.tar.gz) | High | 8.6 | `adcs` |
| [ADCS ESC14: Weak Explicit Certificate Mapping](../templates/template-ADCS-ESC14-Weak-Explicit-Certificate-Mapping.tar.gz) | High | 8.6 | `adcs` |
| [ADCS ESC15: Arbitrary Application Policy Injection (EKUwu)](../templates/template-ADCS-ESC15-Arbitrary-Application-Policy-Injection-EKUwu.tar.gz) | High | 8.6 | `adcs` |
| [ADCS ESC17: Server Authentication Template for WSUS Client Compromise](../templates/template-ADCS-ESC17-Server-Authentication-Template-for-WSUS-Client-Compromise.tar.gz) | High | 8.6 | `adcs` |
| [BadSuccessor (CVE-2025-53779)](../templates/template-BadSuccessor-CVE-2025-53779.tar.gz) | High | 8.6 | `kerberos` |
| [Certifried (CVE-2022-26923)](../templates/template-Certifried-CVE-2022-26923.tar.gz) | High | 8.6 | `adcs` |
| [Certighost (CVE-2026-54121)](../templates/template-Certighost-CVE-2026-54121.tar.gz) | High | 8.6 | `adcs` |
| [Delegation: Constrained Delegation with Protocol Transition](../templates/template-Delegation-Constrained-Delegation-with-Protocol-Transition.tar.gz) | High | 8.6 | `kerberos` |
| [Delegation: Resource-Based Constrained Delegation (RBCD)](../templates/template-Delegation-Resource-Based-Constrained-Delegation-RBCD.tar.gz) | High | 8.6 | `kerberos` |
| [Delegation: Unconstrained Delegation](../templates/template-Delegation-Unconstrained-Delegation.tar.gz) | High | 8.6 | `kerberos` |
| [DNS Non-Secure Dynamic Updates](../templates/template-DNS-Non-Secure-Dynamic-Updates.tar.gz) | High | 8.6 | — |
| [Domain Object Description: Cleartext Credentials](../templates/template-Domain-Object-Description-Cleartext-Credentials.tar.gz) | High | 8.6 | — |
| [Excessive DNS Zone ACL](../templates/template-Excessive-DNS-Zone-ACL.tar.gz) | High | 8.6 | — |
| [Excessive Domain Object ACL](../templates/template-Excessive-Domain-Object-ACL.tar.gz) | High | 8.6 | — |
| [Excessive Microsoft SQL Server Access](../templates/template-Excessive-Microsoft-SQL-Server-Access.tar.gz) | High | 8.6 | — |
| [Excessive SMB Share ACL](../templates/template-Excessive-SMB-Share-ACL.tar.gz) | High | 8.6 | `windows` |
| [Ghost SPN (CVE-2025-58726)](../templates/template-Ghost-SPN-CVE-2025-58726.tar.gz) | High | 8.6 | `kerberos` `relay` |
| [Insufficient Privilege Separation](../templates/template-Insufficient-Privilege-Separation.tar.gz) | High | 8.6 | — |
| [noPac (CVE-2021-42278 and CVE-2021-42287)](../templates/template-noPac-CVE-2021-42278-and-CVE-2021-42287.tar.gz) | High | 8.6 | `kerberos` |
| [NTLM MIC Bypass (CVE-2025-54918)](../templates/template-NTLM-MIC-Bypass-CVE-2025-54918.tar.gz) | High | 8.6 | `ntlm` `relay` |
| [NTLM Reflection (CVE-2025-33073)](../templates/template-NTLM-Reflection-CVE-2025-33073.tar.gz) | High | 8.6 | `ntlm` |
| [PrintNightmare (CVE-2021-34527)](../templates/template-PrintNightmare-CVE-2021-34527.tar.gz) | High | 8.6 | `windows` |
| [ResetNightmare (CVE-2026-27912)](../templates/template-ResetNightmare-CVE-2026-27912.tar.gz) | High | 8.6 | `kerberos` |
| [Service Account: Privileged Group Membership](../templates/template-Service-Account-Privileged-Group-Membership.tar.gz) | High | 8.6 | `kerberos` |
| [Shared Password: Domain Accounts](../templates/template-Shared-Password-Domain-Accounts.tar.gz) | High | 8.6 | — |
| [Shared Password: Local Accounts](../templates/template-Shared-Password-Local-Accounts.tar.gz) | High | 8.6 | `windows` |
| [Shared Password: Local and Domain Account](../templates/template-Shared-Password-Local-and-Domain-Account.tar.gz) | High | 8.6 | `windows` |
| [Kerberos Pre-Authentication Not Required](../templates/template-Kerberos-Pre-Authentication-Not-Required.tar.gz) | High | 8.3 | `kerberos` |
| [Weak Password: Domain Account](../templates/template-Weak-Password-Domain-Account.tar.gz) | High | 8.3 | — |
| [Weak Password: Pre2k Computer Account](../templates/template-Weak-Password-Pre2k-Computer-Account.tar.gz) | High | 8.3 | — |
| [DNS Zone Transfer](../templates/template-DNS-Zone-Transfer.tar.gz) | Medium | 6.9 | — |
| [Kerberos Armoring Not Enforced](../templates/template-Kerberos-Armoring-Not-Enforced.tar.gz) | Medium | 6.9 | `kerberos` |
| [LDAP Anonymous Bind](../templates/template-LDAP-Anonymous-Bind.tar.gz) | Medium | 6.9 | — |
| [SMB Null or Guest Session - Object Enumeration](../templates/template-SMB-Null-or-Guest-Session-Object-Enumeration.tar.gz) | Medium | 6.9 | `windows` |
| [Adversary-in-the-Middle: ARP](../templates/template-Adversary-in-the-Middle-ARP.tar.gz) | Medium | 6.0 | `ntlm` |
| [Adversary-in-the-Middle: DHCPv6](../templates/template-Adversary-in-the-Middle-DHCPv6.tar.gz) | Medium | 6.0 | `ntlm` |
| [Adversary-in-the-Middle: LLMNR](../templates/template-Adversary-in-the-Middle-LLMNR.tar.gz) | Medium | 6.0 | `ntlm` |
| [Adversary-in-the-Middle: mDNS](../templates/template-Adversary-in-the-Middle-mDNS.tar.gz) | Medium | 6.0 | `ntlm` |
| [Adversary-in-the-Middle: NBT-NS](../templates/template-Adversary-in-the-Middle-NBT-NS.tar.gz) | Medium | 6.0 | `ntlm` |
| [Adversary-in-the-Middle: WPAD](../templates/template-Adversary-in-the-Middle-WPAD.tar.gz) | Medium | 6.0 | `ntlm` |
| [Adversary-in-the-Middle: WSUS over HTTP](../templates/template-Adversary-in-the-Middle-WSUS-over-HTTP.tar.gz) | Medium | 6.0 | `ntlm` |
| [Insufficient LAN Manager Authentication Level](../templates/template-Insufficient-LAN-Manager-Authentication-Level.tar.gz) | Medium | 6.0 | `ntlm` |
| [ADCS ESC9: Certificate Template Missing Security Extension](../templates/template-ADCS-ESC9-Certificate-Template-Missing-Security-Extension.tar.gz) | Medium | 5.3 | `adcs` |
| [ADCS ESC10: Weak Certificate Mapping](../templates/template-ADCS-ESC10-Weak-Certificate-Mapping.tar.gz) | Medium | 5.3 | `adcs` |
| [ADCS ESC16: Security Extension Disabled on CA](../templates/template-ADCS-ESC16-Security-Extension-Disabled-on-CA.tar.gz) | Medium | 5.3 | `adcs` |
| [Deprecated Protocol: WebDAV](../templates/template-Deprecated-Protocol-WebDAV.tar.gz) | Medium | 5.3 | `relay` |
| [Domain Object Description: Cleartext Sensitive Information](../templates/template-Domain-Object-Description-Cleartext-Sensitive-Information.tar.gz) | Medium | 5.3 | — |
| [Excessive Machine Account Quota](../templates/template-Excessive-Machine-Account-Quota.tar.gz) | Medium | 5.3 | — |
| [Forced Authentication: MS-DFSNM (DFSCoerce)](../templates/template-Forced-Authentication-MS-DFSNM-DFSCoerce.tar.gz) | Medium | 5.3 | `relay` |
| [Forced Authentication: MS-EFSRPC (PetitPotam)](../templates/template-Forced-Authentication-MS-EFSRPC-PetitPotam.tar.gz) | Medium | 5.3 | `relay` |
| [Forced Authentication: MS-FSRVP (ShadowCoerce)](../templates/template-Forced-Authentication-MS-FSRVP-ShadowCoerce.tar.gz) | Medium | 5.3 | `relay` |
| [Forced Authentication: MS-RPRN (PrinterBug)](../templates/template-Forced-Authentication-MS-RPRN-PrinterBug.tar.gz) | Medium | 5.3 | `relay` |
| [Forced Authentication: PushSubscription API (PrivExchange)](../templates/template-Forced-Authentication-PushSubscription-API-PrivExchange.tar.gz) | Medium | 5.3 | `relay` |
| [LDAP Signing or Channel Binding Not Enforced](../templates/template-LDAP-Signing-or-Channel-Binding-Not-Enforced.tar.gz) | Medium | 5.3 | — |
| [Service Account: Insecure Kerberos Encryption Types](../templates/template-Service-Account-Insecure-Kerberos-Encryption-Types.tar.gz) | Medium | 5.3 | `kerberos` |
| [SMB Null Session - Forced Authentication: MS-EFSRPC (CVE-2021-36942)](../templates/template-SMB-Null-Session-Forced-Authentication-MS-EFSRPC-CVE-2021-36942.tar.gz) | Medium | 5.3 | `relay` |
| [SMB Signing Not Enforced](../templates/template-SMB-Signing-Not-Enforced.tar.gz) | Medium | 5.3 | `windows` |
| [Weak Password Storage: LAN Manager (LM) Hashing](../templates/template-Weak-Password-Storage-LAN-Manager-LM-Hashing.tar.gz) | Medium | 5.3 | `windows` |
| [Weak Password Storage: Reversible Encryption](../templates/template-Weak-Password-Storage-Reversible-Encryption.tar.gz) | Medium | 5.3 | — |
| [Protected Users Group Missing Privileged Accounts](../templates/template-Protected-Users-Group-Missing-Privileged-Accounts.tar.gz) | Low | 2.3 | — |
| [Weak Password Policy: Domain Account](../templates/template-Weak-Password-Policy-Domain-Account.tar.gz) | Low | 2.3 | — |

### Web Application (43)

| Finding | Severity | CVSS | Tags |
|---|---|---|---|
| [Command Injection](../templates/template-Command-Injection.tar.gz) | Critical | 9.3 | `injection` |
| [Insecure Deserialization](../templates/template-Insecure-Deserialization.tar.gz) | Critical | 9.3 | — |
| [Insecure Password Reset](../templates/template-Insecure-Password-Reset.tar.gz) | Critical | 9.3 | — |
| [JWT: Improper Signature Validation](../templates/template-JWT-Improper-Signature-Validation.tar.gz) | Critical | 9.3 | `jwt` |
| [LDAP Injection](../templates/template-LDAP-Injection.tar.gz) | Critical | 9.3 | `injection` |
| [NoSQL Injection](../templates/template-NoSQL-Injection.tar.gz) | Critical | 9.3 | `injection` |
| [Predictable or Forgeable Session Token](../templates/template-Predictable-or-Forgeable-Session-Token.tar.gz) | Critical | 9.3 | — |
| [Server-Side Code Injection](../templates/template-Server-Side-Code-Injection.tar.gz) | Critical | 9.3 | `injection` |
| [Server-Side Template Injection](../templates/template-Server-Side-Template-Injection.tar.gz) | Critical | 9.3 | `injection` |
| [SQL Injection](../templates/template-SQL-Injection.tar.gz) | Critical | 9.3 | `injection` |
| [Unauthenticated Access: Administrative Interface](../templates/template-Unauthenticated-Access-Administrative-Interface.tar.gz) | Critical | 9.3 | — |
| [Cleartext Credentials in Client-Side Code](../templates/template-Cleartext-Credentials-in-Client-Side-Code.tar.gz) | High | 8.7 | — |
| [File Inclusion Vulnerability](../templates/template-File-Inclusion-Vulnerability.tar.gz) | High | 8.7 | — |
| [Path Traversal](../templates/template-Path-Traversal.tar.gz) | High | 8.7 | — |
| [Unauthenticated Access: Sensitive Files](../templates/template-Unauthenticated-Access-Sensitive-Files.tar.gz) | High | 8.7 | — |
| [XML External Entities](../templates/template-XML-External-Entities.tar.gz) | High | 8.7 | — |
| [Client-Controlled Authorization Parameter](../templates/template-Client-Controlled-Authorization-Parameter.tar.gz) | High | 8.6 | — |
| [Cross-Site Scripting: Stored](../templates/template-Cross-Site-Scripting-Stored.tar.gz) | High | 8.6 | `xss` |
| [Dangerous HTTP Methods Enabled](../templates/template-Dangerous-HTTP-Methods-Enabled.tar.gz) | High | 8.6 | — |
| [File Upload Vulnerability](../templates/template-File-Upload-Vulnerability.tar.gz) | High | 8.6 | — |
| [Insecure Direct Object Reference](../templates/template-Insecure-Direct-Object-Reference.tar.gz) | High | 8.6 | — |
| [Mass Assignment](../templates/template-Mass-Assignment.tar.gz) | High | 8.6 | — |
| [Missing Function-Level Access Control](../templates/template-Missing-Function-Level-Access-Control.tar.gz) | High | 8.6 | — |
| [Multi-Factor Authentication Bypass](../templates/template-Multi-Factor-Authentication-Bypass.tar.gz) | High | 8.6 | — |
| [Server-Side Request Forgery](../templates/template-Server-Side-Request-Forgery.tar.gz) | High | 8.6 | `ssrf` |
| [JWT: Weak Signing Secret](../templates/template-JWT-Weak-Signing-Secret.tar.gz) | High | 8.3 | `jwt` |
| [Weak Password: Web Login Portal](../templates/template-Weak-Password-Web-Login-Portal.tar.gz) | High | 8.3 | — |
| [Unauthenticated Username Enumeration](../templates/template-Unauthenticated-Username-Enumeration.tar.gz) | Medium | 6.9 | — |
| [Cleartext Transmission of Credentials](../templates/template-Cleartext-Transmission-of-Credentials.tar.gz) | Medium | 6.0 | — |
| [Business Logic Flaw](../templates/template-Business-Logic-Flaw.tar.gz) | Medium | 5.3 | — |
| [Cross-Origin Resource Sharing Misconfiguration](../templates/template-Cross-Origin-Resource-Sharing-Misconfiguration.tar.gz) | Medium | 5.3 | — |
| [Excessive Data Exposure: API Response](../templates/template-Excessive-Data-Exposure-API-Response.tar.gz) | Medium | 5.3 | `api` |
| [Exposed Diagnostic Endpoint](../templates/template-Exposed-Diagnostic-Endpoint.tar.gz) | Medium | 5.3 | — |
| [Insufficient Brute-Force Protections](../templates/template-Insufficient-Brute-Force-Protections.tar.gz) | Medium | 5.3 | — |
| [Race Condition](../templates/template-Race-Condition.tar.gz) | Medium | 5.3 | — |
| [Sensitive Data Stored Unencrypted](../templates/template-Sensitive-Data-Stored-Unencrypted.tar.gz) | Medium | 5.3 | — |
| [Weak Password Storage](../templates/template-Weak-Password-Storage.tar.gz) | Medium | 5.3 | — |
| [Cross-Site Request Forgery](../templates/template-Cross-Site-Request-Forgery.tar.gz) | Medium | 5.1 | `csrf` |
| [Cross-Site Scripting: DOM-Based](../templates/template-Cross-Site-Scripting-DOM-Based.tar.gz) | Medium | 5.1 | `xss` |
| [Cross-Site Scripting: Reflected](../templates/template-Cross-Site-Scripting-Reflected.tar.gz) | Medium | 5.1 | `xss` |
| [Excessively Verbose Error Messages](../templates/template-Excessively-Verbose-Error-Messages.tar.gz) | Low | 2.3 | — |
| [Open Redirect](../templates/template-Open-Redirect.tar.gz) | Low | 2.3 | — |
| [Weak Password Policy: Web Application](../templates/template-Weak-Password-Policy-Web-Application.tar.gz) | Low | 2.3 | — |

### Network Service (25)

| Finding | Severity | CVSS | Tags |
|---|---|---|---|
| [FTP Anonymous Access](../templates/template-FTP-Anonymous-Access.tar.gz) | Critical | 9.3 | `ftp` |
| [Insecure Protocol: Cisco Smart Install](../templates/template-Insecure-Protocol-Cisco-Smart-Install.tar.gz) | Critical | 9.3 | `cisco` |
| [iSCSI Target Public Access](../templates/template-iSCSI-Target-Public-Access.tar.gz) | Critical | 9.3 | `iscsi` |
| [NFS Publicly Mountable Export](../templates/template-NFS-Publicly-Mountable-Export.tar.gz) | Critical | 9.3 | `nfs` |
| [SMB Null or Guest Session - Share Access](../templates/template-SMB-Null-or-Guest-Session-Share-Access.tar.gz) | Critical | 9.3 | `smb` |
| [SNMP Weak Community String - Read-Write](../templates/template-SNMP-Weak-Community-String-Read-Write.tar.gz) | Critical | 9.3 | `snmp` |
| [VNC Unauthenticated Access](../templates/template-VNC-Unauthenticated-Access.tar.gz) | Critical | 9.3 | `vnc` |
| [FTP Directory Traversal](../templates/template-FTP-Directory-Traversal.tar.gz) | High | 8.7 | `ftp` |
| [Insecure Protocol: IPMI Version 2.0](../templates/template-Insecure-Protocol-IPMI-Version-2-0.tar.gz) | High | 8.7 | `ipmi` |
| [SNMP Weak Community String - Read-Only](../templates/template-SNMP-Weak-Community-String-Read-Only.tar.gz) | High | 8.7 | `snmp` |
| [TFTP Directory Traversal](../templates/template-TFTP-Directory-Traversal.tar.gz) | High | 8.7 | `tftp` |
| [TFTP Guessable Filename](../templates/template-TFTP-Guessable-Filename.tar.gz) | High | 8.7 | `tftp` |
| [File Content: Cleartext Credentials](../templates/template-File-Content-Cleartext-Credentials.tar.gz) | High | 8.6 | — |
| [Outdated Software](../templates/template-Outdated-Software.tar.gz) | High | 8.3 | — |
| [Weak Password: Local Account](../templates/template-Weak-Password-Local-Account.tar.gz) | High | 8.3 | — |
| [Weak Password: Service Account](../templates/template-Weak-Password-Service-Account.tar.gz) | High | 8.3 | — |
| [SMTP Open Relay](../templates/template-SMTP-Open-Relay.tar.gz) | Medium | 6.9 | `smtp` |
| [Cleartext Authentication: FTP](../templates/template-Cleartext-Authentication-FTP.tar.gz) | Medium | 6.0 | `ftp` |
| [Cleartext Authentication: POP3/IMAP](../templates/template-Cleartext-Authentication-POP3-IMAP.tar.gz) | Medium | 6.0 | `mail` |
| [Cleartext Authentication: SNMP](../templates/template-Cleartext-Authentication-SNMP.tar.gz) | Medium | 6.0 | `snmp` |
| [Cleartext Authentication: Telnet](../templates/template-Cleartext-Authentication-Telnet.tar.gz) | Medium | 6.0 | `telnet` |
| [Cleartext Authentication: VNC](../templates/template-Cleartext-Authentication-VNC.tar.gz) | Medium | 6.0 | `vnc` |
| [File Content: Cleartext Sensitive Information](../templates/template-File-Content-Cleartext-Sensitive-Information.tar.gz) | Medium | 5.3 | — |
| [Insecure Protocol: TFTP](../templates/template-Insecure-Protocol-TFTP.tar.gz) | Low | 2.3 | `tftp` |
| [Weak Password Policy: Local Account](../templates/template-Weak-Password-Policy-Local-Account.tar.gz) | Low | 2.3 | — |

### Unclassified (1)

| Finding | Severity | CVSS | Tags |
|---|---|---|---|
| [SSH: guessable user and password](../templates/template-SSH-guessable-user-and-password.tar.gz) | — | 7.1 | `ssh` |

> **Unfinished template:** *SSH: guessable user and password* is a stub that was added separately. Its status is `needs-improvement`. It has no `severity`, `environment`, `references`, `short_recommendation` or `vulnerability`, and it uses a CVSS **3.1** vector where every other template uses 4.0. Its body is plain prose without the markdown structure the other templates use. Until it is finished, use [Weak Password: Local Account](../templates/template-Weak-Password-Local-Account.tar.gz) or [Weak Password: Service Account](../templates/template-Weak-Password-Service-Account.tar.gz) for guessable SSH credentials.

## Archive format

Each `template-<Title>.tar.gz` contains a single `<uuid>.json` in SysReptor's `templates/v2` export format, with one `en-US` translation and no images. Every translation has status `finished` except the SSH stub. The file name is the template title with every run of non-alphanumeric characters replaced by a single `-`, keeping the original case.

To look inside one without importing it:

```bash
tar -xzOf templates/template-FTP-Anonymous-Access.tar.gz | jq '.translations[0].data | {title, severity, cvss, environment}'
```
