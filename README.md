<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/andremeansx/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Queried the `DeviceFileEvents` table for any file containing the string "tor" and identified activity by the user **"employee"** beginning at `2025-07-11T19:07:02.2738735Z`. The logs indicate that the user downloaded a Tor installer and executed actions that resulted in multiple Tor-related files being copied to the desktop. Notably, a file named `tor-shopping-list.txt` was created on the desktop at `2025-07-11T19:36:26.0296502Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "vm-lab-target"
| where InitiatingProcessAccountName contains "employee"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-07-11T19:07:02.2738735Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType,FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
<img width="2276" height="871" alt="image" src="https://github.com/user-attachments/assets/e9208629-0e37-4f9d-93a8-ab3f8c64744b" />



---

### 2. Searched the `DeviceProcessEvents` Table

Queried the `DeviceProcessEvents` table for any `ProcessCommandLine` containing the string `tor-browser-windows-x86_64-portable`. The results show that on `2025-07-11T19:22:19.777453Z`, the user `employee` executed the file `tor-browser-windows-x86_64-portable-14.5.4.exe` from the Downloads folder on the `vm-lab-target` device. The command included a silent installation switch, indicating an unattended setup of the Tor Browser.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "vm-lab-target"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine, FolderPath, SHA256
```
<img width="2625" height="142" alt="image" src="https://github.com/user-attachments/assets/2fe0ff37-6a21-49f3-bb03-2e9c1ba0cb4c" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the `DeviceProcessEvents` table for evidence that the user `employee` launched the Tor Browser. Logs confirm that it was opened at `2025-07-11T19:23:12.5878887Z`. Multiple subsequent instances of `firefox.exe` (Tor) and `tor.exe` were also observed, indicating continued usage.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "vm-lab-target"
| where FileName has_any ("tor.exe","firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```
<img width="2660" height="766" alt="image" src="https://github.com/user-attachments/assets/13a060cb-df83-4aa0-baff-461270d1e54e" />



---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the `DeviceNetworkEvents` table for any indication that the Tor Browser was used to establish a connection over known Tor ports. On `2025-07-11T19:23:19.4301914Z`, a successful network connection was observed on the device `vm-lab-target`. The connection was initiated by the `employee` account using the file `firefox.exe`, located in the Tor Browser folder on the desktop. It connected to `127.0.0.1` on port `9151`, which is commonly used as the Tor control port. Additional outbound connections were also made over port `443`, consistent with Tor network activity.


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "vm-lab-target"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9050", "9051", "9150", "9151")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName,InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
