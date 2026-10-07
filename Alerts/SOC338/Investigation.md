# SOC338 Lumma Stealer: DLL Side-Loading via Click Fix Phishing — SOC Investigation Walkthrough

> Training-lab write-up. Separate reported observations from hypotheses and recommended actions. Missing source evidence remains unverified; proposed detections and remediation are not claims of deployment.

## 2. Executive Summary

This investigation details the analysis of a critical data leakage alert (SOC338) triggered on March 13, 2025. The alert identified a targeted phishing campaign aiming to distribute the Lumma Stealer malware to an internal user (`dylan@letsdefend.io`). The attack leveraged a deceptive "Windows 11 Pro" upgrade lure and directed the user to a malicious domain utilizing a "Click Fix" social engineering technique. This tactic tricks users into manually executing a malicious PowerShell script that facilitates DLL side-loading to deploy the infostealer. Because the email was marked as "Allowed" by the gateway, the investigation focused on identifying the threat infrastructure and determining the required steps to validate endpoint execution. The alert is confirmed as a **True Positive**, representing a severe credential theft threat.

## 3. Alert Overview

| Field | Details |
| --- | --- |
| **Platform** | LetsDefend |
| **Severity** | Critical |
| **Category** | Data Leakage |
| **Source** | Email Gateway / Phishing Alert |
| **Timestamp** | Mar, 13, 2025, 09:44 AM |
| **Username** | Target: `dylan@letsdefend.io` |
| **Source IP** | `132.232.40.201` (SMTP) |
| **Domain/URL** | `windows-update.site` |
| **Status** | True Positive |

## 4. Initial Triage

A SOC analyst approaching this alert must immediately prioritize it due to the "Critical" severity and the destructive nature of Lumma Stealer, a known credential and session token harvester.

**Triage Objectives:**

1. **Identify the Delivery Mechanism:** Analyze the sender email, subject, and SMTP IP to understand the phishing lure.
2. **Understand the Attack Vector (Click Fix):** Recognize that "Click Fix" attacks rely on user interaction (e.g., prompting the user to copy/paste PowerShell code into a run dialog or terminal) to bypass automated sandbox detection.
3. **Assess the Threat Status:** Since the Device Action was marked as "Allowed," the malicious email successfully reached the user's inbox.
4. **Determine the Missing Links:** The immediate priority is to validate whether the user clicked the link and, more importantly, whether they executed the copied PowerShell script on their endpoint.

*Hypothesis:* The user received the phishing email, was tempted by the free Windows 11 upgrade, clicked through to `windows-update.site`, and was presented with a fake error or CAPTCHA (the Click Fix script) instructing them to execute malicious code leading to DLL side-loading of Lumma Stealer.

---

## 5. Investigation Methodology

### Step 1 — Email and Lure Analysis

**Objective:** Determine the intent and sophistication of the incoming email.
**Evidence:**

* **Sender:** `update@windows-update.site`
* **Subject:** Upgrade your system to Windows 11 Pro for FREE
* **Action:** Allowed

**Analysis:**
The attacker spoofed a legitimate-sounding administrative domain (`windows-update.site`) and utilized a high-enticement lure (free OS upgrade). Because the email bypassed initial filters, the threat heavily relies on the user's trust in the branding.
**Finding:** A targeted social engineering attempt successfully delivered to the user's inbox.

### Step 2 — Web Infrastructure Analysis

**Objective:** Analyze the destination website and the "Click Fix" tactic.
**Evidence:**

* **Domain:** `windows-update.site`
* **Alert Trigger Reason:** Redirected site contains a click fix type script for Lumma Stealer distribution.
* *[Full page source, network logs, and script contents: Evidence not provided]*

**Analysis:**
Click Fix attacks typically display a fake error or verification page (like a fake reCAPTCHA or browser update). The page provides instructions for the user to press `Win + R`, `Ctrl + V`, and `Enter`. Hidden JavaScript on the page automatically copies a malicious, base64-encoded PowerShell script into the user's clipboard. If the user follows the instructions, they manually execute the downloader for Lumma Stealer. The platform guidance suggested using Any.run if the domain was offline to safely observe this behavior.
**Finding:** The domain hosts a malicious Lumma Stealer delivery mechanism requiring human interaction.

### Step 3 — Endpoint Execution Validation

**Objective:** Determine if the user executed the PowerShell payload and if DLL side-loading occurred.
**Evidence:**

* *[Endpoint telemetry, PowerShell operational logs, and process creation logs: Evidence not provided]*

**Analysis:**
Because the alert only confirms the email delivery ("Allowed"), endpoint process investigation is absolutely critical. We must look for `powershell.exe` launching with encoded commands, or suspicious child processes downloading secondary payloads. Furthermore, the alert indicates the final stage relies on DLL side-loading. We would need to hunt for vulnerable, signed executables loading unsigned, malicious DLLs from temporary directories (like `C:\Users\Public` or `%APPDATA%`).
**Finding:** [Unconfirmed] Additional EDR evidence is required to prove if the user executed the script and infected their machine.

---

## 6. Evidence Analysis

### Important Artifacts

* **`update@windows-update.site` (Email Address):**
* *Context:* The sender of the phishing email.
* *Interpretation:* A typosquatted/spoofed domain designed to mimic official Microsoft Windows Update communications.
* *Security significance:* Highly suspicious and should be blacklisted at the Secure Email Gateway (SEG).


* **`132.232.40.201` (IPv4):**
* *Context:* The SMTP originating IP address.
* *Interpretation:* The infrastructure used by the threat actor to send the campaign.
* *Security significance:* Indicator of the attacker's mailing infrastructure; prime candidate for perimeter blocking.


* **`windows-update.site` (Domain):**
* *Context:* The destination URL provided in the email.
* *Interpretation:* Hosts the "Click Fix" script designed to distribute Lumma Stealer.
* *Security significance:* The core malicious infrastructure driving the social engineering component of the attack.



---

## 7. Timeline Reconstruction

| Time | Event | Evidence | Significance |
| --- | --- | --- | --- |
| Mar, 13, 2025, 09:44 AM | Phishing email delivered | Alert metadata (Subject: "Upgrade your system to Windows 11 Pro for FREE") | Initial access attempt bypassed email gateway filters. |
| *[Evidence not provided]* | User interaction with email | *[Network proxy / DNS logs missing]* | Unknown if `dylan@letsdefend.io` clicked the link. |
| *[Evidence not provided]* | Payload Execution & DLL Side-Loading | *[EDR / Process logs missing]* | Unknown if the Click Fix script was executed on the endpoint. |

---

## 8. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence | Confidence |
| --- | --- | --- | --- | --- |
| **Initial Access** | Phishing: Spearphishing Link | T1566.002 | Email sent to `dylan@letsdefend.io` containing a link to a malicious domain. | Confirmed |
| **Execution** | User Execution: Malicious Link | T1204.001 | The attack relies on the victim clicking the link in the email. | Likely |
| **Execution** | Command and Scripting Interpreter: PowerShell | T1059.001 | Click Fix tactic tricks users into running a PowerShell script via their clipboard. | Possible |
| **Defense Evasion** | Hijack Execution Flow: DLL Side-Loading | T1574.002 | Alert definition specifies Lumma Stealer uses this technique post-execution. | Possible |

---

## 9. Indicators of Compromise (IOCs)

| Type | Indicator | Context | Confidence |
| --- | --- | --- | --- |
| **Email** | `update@windows-update.site` | Sender address used in the phishing campaign. | High |
| **IP Address** | `132.232.40.201` | Originating SMTP server IP. | High |
| **Domain** | `windows-update.site` | Malicious domain hosting the Click Fix script. | High |
| **File / Hash** | `Not Provided` | Lumma Stealer payload / Malicious DLL. | N/A |
| **Process** | `svchost.exe` | PowerShell execution or vulnerable executable for DLL side-loading. | N/A |

---

## 10. Detection & Hunting Opportunities

Because the email was allowed, defenders must hunt for subsequent attacker activity on the endpoints.

**Splunk SPL — Hunting for the Phishing Email:**
To identify if other users received this email across the environment:

```spl
index=email sourcetype=mime (source_address="update@windows-update.site" OR src_ip="132.232.40.201")
| table _time, source_address, dest_address, subject, action

```

**Microsoft Sentinel / KQL — Hunting for Click Fix PowerShell Execution:**
Click Fix attacks rely on the clipboard to transfer the script. We can hunt for PowerShell executing directly from encoded strings or clipboard commands.

```kusto
DeviceProcessEvents
| where ProcessName =~ "powershell.exe"
| where ProcessCommandLine contains "-EncodedCommand" 
   or ProcessCommandLine contains "clipboard" 
   or ProcessCommandLine contains "iex"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine

```

*(Note: Validation of this query requires the missing endpoint telemetry).*

---

## 11. Investigation Findings

**Confirmed Findings:**

* A targeted phishing attack mimicking a Windows 11 Pro upgrade successfully bypassed email perimeter defenses (Action: Allowed).
* The sender IP (`132.232.40.201`) and domain (`windows-update.site`) are malicious infrastructure actively distributing Lumma Stealer.
* The threat actor is utilizing the "Click Fix" social engineering technique to bypass automated analysis by requiring manual user execution.

**Supporting Findings:**

* Platform intelligence confirms the final payload mechanism relies on DLL Side-Loading to execute the stealer stealthily.

**Unconfirmed / Unknown:**

* Without endpoint logs, network logs, or EDR telemetry, it is **unknown** if the user clicked the link, copied the payload, or successfully executed the script resulting in a Lumma Stealer infection.

---

## 12. Final Verdict

**True Positive — Malicious (Attack Attempt)**

**Reasoning:**
The infrastructure, email lure, and underlying threat intelligence confirm this is a real, active attack attempting to distribute a critical infostealer. The alert accurately detected the malicious nature of the redirected site. However, because endpoint evidence is not provided, we can only confirm the *delivery* of the threat, not the successful *compromise* of the endpoint.

---

## 13. Recommended Response Actions

1. **Email Eradication:** Immediately purge the email from `dylan@letsdefend.io`'s inbox and search the enterprise for any other deliveries from `update@windows-update.site` or `132.232.40.201`.
2. **Infrastructure Blocking:** Add the domain `windows-update.site` and IP `132.232.40.201` to firewall, DNS sinkhole, and proxy blocklists.
3. **Endpoint Validation:** Isolate Dylan's workstation pending a full EDR review. Check for anomalous PowerShell execution, unauthorized scheduled tasks, or suspicious DLL side-loading events.
4. **Credential Reset:** If endpoint compromise is confirmed, Lumma Stealer acts rapidly. Immediately rotate all credentials, session tokens, and MFA keys associated with Dylan's workstation and browser data.
5. **Sandbox Analysis:** If the domain goes offline, utilize platforms like Any.run (as suggested by the playbook) to retrieve cached copies of the attack chain to extract the specific PowerShell commands and payload hashes for further hunting.

---

## 14. Lessons Learned

* **Human-Driven Execution Defeats Sandboxes:** The "Click Fix" tactic forces the user to be the execution mechanism (copy/paste). Because there is no malicious executable attached to the email, traditional sandboxes often score the initial link as benign.
* **"Allowed" Requires Immediate Endpoint Pivot:** When a critical alert shows a device action of "Allowed", the investigation cannot stop at the email headers. The analyst must immediately pivot to endpoint telemetry to determine the blast radius.
* **Stealer Speed:** Lumma Stealer relies on rapid exfiltration. If a user executes a Click Fix script, the theft of session tokens and passwords often occurs within seconds, making proactive blocking and rapid credential resets vital.

---

### Analyst Takeaway

1. **Beware the Clipboard:** Click Fix represents a shift from "malware-as-an-attachment" to "malware-via-clipboard." User awareness training must explicitly warn against copying and pasting code from random prompts into terminals.
2. **Hunt for Anomalous Script Execution:** Relying on EDR to catch obfuscated PowerShell or abnormal DLL side-loading is the best fallback defense when email gateways fail to drop the initial lure.
3. **Evidence Gaps Limit Dispositions:** You cannot confirm an infection without endpoint telemetry. Always distinguish between a successfully *delivered* attack and a successfully *executed* attack.

---

