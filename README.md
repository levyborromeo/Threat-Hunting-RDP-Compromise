# **SOC Investigation Report**

## **RDP Compromise Incident**

**Report ID:** INC-2025-092301

**Analyst:** Levy Borromeo

**Date:** 23-September-2025

**Incident Date:** 14-September-2025

---

## 1\. Findings 

*List the key evidence you discovered during your investigation*

### Key Indicators of Compromise (IOCs):

* **Attack Source IP:** 159.26.106.84  
* **Compromised Account:** slflare  
* **Malicious File:** msupdate.exe  
* **Persistence Mechanism:** Scheduled task named MicrosoftUpdateSync  
* **C2 Server:** 185.92.220.87  
* **Exfiltration Destination:** 185.92.220.87:8081

### KQL Queries Used:

**Query 1 \- Initial Access Detection:**

DeviceLogonEvents  
| where DeviceName contains "flare"  
| summarize ActionTypeCount \= count() by RemoteIP, ActionType  
| where ActionType \== "LogonSuccess"

DeviceLogonEvents  
| where DeviceName contains "flare"  
| summarize ActionTypeCount \= count() by RemoteIP, ActionType  
| where RemoteIP in ("79.127.146.221" , "159.26.106.84")  
| order by RemoteIP, ActionType, ActionTypeCount desc

DeviceLogonEvents  
| where DeviceName contains "flare"  
| where RemoteIP \== "159.26.106.84"  
| where ActionType \== "LogonSuccess"  
| where LogonType \== "RemoteInteractive"  
| order by Timestamp desc

**Results:** 

![][image1]

![][image2]![][image3]

**Query 2 \- Malicious Execution:**

SecurityEvent  
| where EventSourceName \== "Microsoft-Windows-Sysmon"  
| where EventID \== 1  
| where Computer contains "flare"  
| where EventData contains "T1059" or EventData contains "T1059.003" or EventData contains "T1204.002"  
| where TimeGenerated \>= todatetime('2025-09-16T18:43:46.8644523Z')  
| extend parsed \= parse\_xml(EventData)  
| mv-expand Data \= parsed.EventData.Data  
| extend Name \= tostring(Data\["@Name"\]), Value \= tostring(Data\["\#text"\])  
| where Name \== "CommandLine"  
| project TimeGenerated, Computer, CommandLine \= Value, EventData

SecurityEvent  
| where EventSourceName \== "Microsoft-Windows-Sysmon"  
| where EventID \== 1  
| where Computer contains "flare"  
| where EventData contains "msupdate.exe"  
| where TimeGenerated \>= todatetime('2025-09-16T18:43:46.8644523Z')  
| extend parsed \= parse\_xml(EventData)  
| mv-expand Data \= parsed.EventData.Data  
| extend Name \= tostring(Data\["@Name"\]), Value \= tostring(Data\["\#text"\])  
| where Name \== "CommandLine"  
| project TimeGenerated, Computer, CommandLine \= Value, EventData

### **Results:** 

![][image4]

![][image5]

![][image6]

**Query 3 \- Persistence Detection:**

DeviceProcessEvents  
| where DeviceName contains "flare"  
| where FileName contains "msupdate"

**Results:** 

![][image7]

**Query 4:**

let selectedTimestamp \= datetime(2025-09-16T19:38:40.0542219Z);  
search in (DeviceProcessEvents,DeviceNetworkEvents,DeviceFileEvents,DeviceRegistryEvents,DeviceLogonEvents,DeviceImageLoadEvents,DeviceEvents,BehaviorEntities)  
Timestamp between ((selectedTimestamp \- 30m) .. (selectedTimestamp \+ 30m))  
and DeviceId \== "401039d292f73a34a435e685c7090049cb7ce6d5"  
| sort by Timestamp desc  
| extend Relevance \= iff(Timestamp \== selectedTimestamp, "Selected event", iff(Timestamp \< selectedTimestamp, "Earlier event", "Later event"))  
| project-reorder Relevance

**Results:** 

**![][image8]![][image9]![][image10]**

**Query 5:**

**let selectedTimestamp \= datetime(2025-09-16T19:38:40.0542219Z);**  
**search in (DeviceProcessEvents,DeviceNetworkEvents,DeviceFileEvents,DeviceRegistryEvents,DeviceLogonEvents,DeviceImageLoadEvents,DeviceEvents,BehaviorEntities)**  
**Timestamp between ((selectedTimestamp \- 30m) .. (selectedTimestamp \+ 30m))**  
**and DeviceId \== "401039d292f73a34a435e685c7090049cb7ce6d5"**  
**and FileName has\_any ("zip","tar","7z")**  
**| sort by Timestamp desc**  
**| extend Relevance \= iff(Timestamp \== selectedTimestamp, "Selected event", iff(Timestamp \< selectedTimestamp, "Earlier event", "Later event"))**  
**| project-reorder Relevance**

**Results:**

**![][image11]**

**![][image12]**

**Query 6:**

**DeviceNetworkEvents**  
**| where DeviceId \== "401039d292f73a34a435e685c7090049cb7ce6d5"**  
**| where Timestamp \>= todatetime('2025-09-16T19:38:40.0542219Z')**  
**| where RemoteIP \== "185.92.220.87"**

**Results:**

**![][image13]**

**![][image14]**

---

## **2\. Investigation Summary** 

**What Happened:** 

An attacker brute-forced RDP credentials from IP *159.26.106.84* and successfully logged in using the account *slflare*. Once inside, they executed a malicious binary (*msupdate.exe*) via PowerShell to run a script (*update\_check.ps1*), then established persistence by creating a scheduled task named *MicrosoftUpdateSync*. To evade detection, they excluded *C:\\Windows\\Temp* from Defender scans, performed system reconnaissance with *systeminfo*, archived stolen data into *backup\_sync.zip*, and attempted exfiltration to external IP *185.92.220.87:8081*.

---

**Attack Timeline:**

* **Started:** 2025-09-16T18:36:55.2404102Z \- Initial brute-force RDP login attempts began   
* **Ended:** 2025-09-16T19:41:09.0000000Z \- Detected system executable rename and launch  
* **Duration:** Approximately 65 minutes

**Impact Level:** High

This attack is high impact because the adversary gained access using valid credentials, established persistence through a scheduled task, and disabled Defender protections to operate undetected. They exfiltrated sensitive data to an external server and maintained command-and-control communication, compromising confidentiality, integrity, and long-term system security.

---

## 3\. Who, What, When, Where, Why, How

### **Who:**

* **Attacker:** *159.26.106.84*  
* **Victim Account:** *slflare*  
* **Affected System:** slflarewinsysmo, 10.0.0.15  
* **Impact on Users:** users are at risk of data theft, surveillance, and ongoing compromise

### **What:**

* **Attack Type:** This is a multi-stage targeted attack that combines several tactics from the MITRE ATT\&CK framework. The primary attack type is: 🧨 *Brute-force enabled Remote Access Intrusion with Post-exploitation Persistence and Exfiltration*  
    
* **Malicious Activities:**

  * 🔓 Initial Access   
    * Brute-force RDP login from external IP 159.26.106.84   
    * T1110.001 \- Password Guessing  
      The attacker repeatedly attempted logins until successfully accessing the system.  
  * 👤 Credential Abuse  
    * Login using valid account slflare  
    * T1078 \- Valid Accounts   
      This allowed the attacker to bypass security controls and operate with legitimate privileges.  
  * ⚙️ Execution  
    * Ran msupdate.exe via PowerShell   
    * T1059.003 \- Windows Command Shell  
    * T1204.002 \- User Execution: Malicious File   
      The binary executed a script (update\_check.ps1) likely containing payloads or further instructions.  
  * 🔁 Persistence   
    * Created scheduled task MicrosoftUpdateSync   
    * T1053.005 \- Scheduled Task   
      Ensured the attacker’s code would run after reboot or logoff.  
  * 🛡️ Defense Evasion   
    * Modified Defender settings to exclude C:\\Windows\\Temp   
    * T1562.001 \- Impair Defenses   
      Prevented detection of malicious files stored in that directory.  
  * 🔍 Discovery   
    * Executed systeminfo via cmd.exe   
    * T1082 \- System Information Discovery   
      Gathered host details to assess environment and plan next steps.  
  * 📦 Data Collection & Staging   
    * Created archive Backup\_sync.zip   
    * T1560.001 \- Archive Collected Data   
      Prepared stolen data for exfiltration.  
  * 🌐 Command & Control   
    * Connected to external IP 185.92.220.87   
    * T1071.001 \- Web Protocols  
    * T1105 \- Ingress Tool Transfer   
      Likely used for beaconing or downloading additional tools.  
  * 📤 Exfiltration   
    * Sent data to 185.92.220.87:8081   
    * T1048.003 \- Exfiltration Over Unencrypted Protocol   
      Transferred the archive outside the network without encryption.

### **When:**

* **First Malicious Activity:** 2025-09-16T18:36:55.2404102Z  
* **Last Observed Activity:** 2025-09-16T19:39:45.0000000Z  
* **Detection Time:** 2025-09-16T19:41:09.0000000Z  
* **Total Attack Duration:** approximately 65 minutes  
* **Is it still active?** No

### **Where:**

* **Target System:** Cloud-hosted Windows Server   
* **Attack Origin:** IP 159.26.106.84 \- likely geolocated to Europe (exact country may vary based on IP lookup)   
* **Network Segment:** Public-facing DMZ or exposed RDP segment in cloud infrastructure   
* **Affected Directories/Files: ⁠**  
  * C:\\Users\\Public\\update\_check.ps1 (malicious script) ⁠  
  * C:\\Windows\\Temp (excluded from Defender scans) ⁠  
  * MicrosoftUpdateSync (scheduled task) ⁠  
  * Backup\_sync.zip (archived exfiltration payload)

### **Why:** 

* **Likely Motive:** Data theft and persistent access   
  The attacker exfiltrated sensitive data (Backup\_sync.zip) and established a scheduled task (MicrosoftUpdateSync) to maintain long-term control over the system.  
* **Target Value:** Exposed cloud-hosted Windows server with RDP access   
  This system likely held valuable operational data and was accessible from the internet, making it an attractive entry point for lateral movement or staging further attacks.

### **How:**

* **Initial Access Method:** Brute-force RDP login using valid credentials (slflare) from external IP 159.26.106.84   
* **Tools/Techniques Used:** msupdate.exe executed via PowerShell with bypassed execution policy; script update\_check.ps1 used for payload delivery   
* **Persistence Method:** Scheduled task named MicrosoftUpdateSync created to ensure recurring execution of malicious code   
* **Data Collection Method:** System enumeration via systeminfo; sensitive data archived locally into Backup\_sync.zip   
* **Communication Method:** Unencrypted outbound HTTP connection to external IP 185.92.220.87:8081 for command-and-control and data exfiltration

---

## **4\. Recommendations**

### **Immediate Actions Needed:**

1. Isolate the compromised system from the network to prevent further attacker activity or data exfiltration.   
2. Terminate the scheduled task MicrosoftUpdateSync and remove the malicious script update\_check.ps1 and binary msupdate.exe.   
3. Revoke credentials for the compromised account slflare and force password resets for all privileged accounts.   
4. Remove Defender exclusions for C:\\Windows\\Temp and initiate a full endpoint scan.  
5. Block outbound traffic to IP 185.92.220.87 and port 8081 at the firewall and proxy level.   
6. Preserve forensic evidence: collect logs, memory dumps, and file artifacts for investigation and legal purposes.

### **Short-term Improvements (1-30 days):**

1. Enable multi-factor authentication (MFA) for all remote access, especially RDP.   
2. Implement RDP access controls: restrict to known IP ranges, enforce just-in-time access, or disable if not needed.   
3. Deploy endpoint detection rules for suspicious binaries in public/temp folders and PowerShell execution with \-ExecutionPolicy Bypass.   
4. Audit scheduled tasks across all systems for unauthorized entries.   
5. Review Defender configuration and enforce centralized policies to prevent local exclusions.   
6. Conduct a credential hygiene review: rotate service account passwords and audit group memberships.

### **Long-term Security Enhancements:**

1. Implement network segmentation to isolate public-facing systems from internal assets.   
2. Integrate threat intelligence feeds to proactively block known malicious IPs and domains.   
3. Deploy centralized logging and SIEM correlation to detect brute-force patterns, lateral movement, and persistence mechanisms.   
4. Conduct regular red team exercises to simulate attacker behavior and validate detection coverage.   
5. Establish a formal incident response playbook that includes MITRE mapping, containment protocols, and communication plans.   
6. Invest in user training and awareness to reduce credential compromise and improve reporting of suspicious activity.

### **Detection Improvements:**

* **Monitoring Gaps Identified:**  
  * Lack of brute-force detection for RDP login attempts from external IPs  
  * No alerting on scheduled task creation or Defender exclusion registry changes   
  * Insufficient visibility into PowerShell execution with \-ExecutionPolicy Bypass   
  * No correlation between archive creation and outbound traffic to unknown IPs  
* **Recommended Alerts:**  
  * Alert on multiple failed RDP logins followed by a successful login from the same external IP   
  * Alert on scheduled task creation by non-administrative users or from suspicious paths   
  * Alert on Defender configuration changes, especially folder exclusions   
  * Alert on execution of binaries from Public, Temp, or Downloads directories   
  * Alert on creation of archive files (.zip, .rar, .7z) followed by outbound traffic   
  * Alert on PowerShell execution with suspicious flags (-ExecutionPolicy Bypass, \-File)  
* **Query Improvements:**  
  * Enhance KQL to correlate SecurityEvent 4625 (failed login) with 4624 (successful login) by IP and username   
  * Build a scheduled task hunting query using SecurityEvent (EventID 4698\) and DeviceProcessEvents   
  * Create a Defender exclusion detection query using DeviceRegistryEvents filtering on HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions   
  * Develop a process lineage query to trace execution from msupdate.exe to update\_check.ps1   
  * Add logic to flag outbound connections to non-whitelisted IPs, especially after archive creation
