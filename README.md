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
<img width="2245" height="510" alt="image" src="https://github.com/user-attachments/assets/31c58149-ab50-4514-b23a-0271dc99540a" />


---

### 🕒 Chronological Events Timeline  — Tor Browser Activity on `vm-lab-target` Device

| **Time (UTC)**         | **Event**                                                                                                                                              |
|------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| `19:07:02.273Z`        | **Download begins** – `tor-browser-windows-x86_64-portable-14.5.4.exe` saved to `C:\Users\employee\Downloads` (hash recorded).                          |
| `19:22:19.777Z`        | **Silent installation executed** – `employee` runs the portable installer with the `/S` switch from the Downloads folder, indicating an unattended setup. |
| `19:22:26.682Z`        | **Tor files deployed to desktop** – Multiple Tor-related binaries and shortcuts copied to `C:\Users\employee\Desktop\Tor Browser\`. `tor-shopping-list.txt` is created. |
| `19:22:35 – 19:22:44Z` | **Additional components written** – Files like `tor.exe`, `Tor Browser.lnk`, `Torbutton.txt`, and `Tor-Launcher.txt` appear on the desktop.              |
| `19:23:12.588Z`        | **First Tor Browser launch** – `firefox.exe` (part of the Tor Browser bundle) is executed from the desktop path.                                         |
| `19:23:13 – 19:23:18Z` | **Child processes spawn** – Multiple instances of `tor.exe` and `firefox.exe` are created as the Tor circuit initializes.                               |
| `19:23:19.430Z`        | **Network connection established** – `firefox.exe` (run by `employee`) successfully connects to `127.0.0.1:9151`, the Tor control port.                  |
| `19:23:20 – 19:24:10Z` | **Outbound traffic observed** – Encrypted connections occur over TCP port `443` to public IPs associated with Tor guard/exit relays.                    |
| `19:36:26.682Z`        | **User activity artifact** – `tor-shopping-list.txt` is updated, suggesting interaction with or data retention from within Tor Browser.                  |
| `19:45:xxZ → onwards`  | **Repeated Tor usage** – Ongoing logs show periodic launches of `firefox.exe` and `tor.exe`, and continued outbound traffic over port `443`.            |

> **Note:** All timestamps are in UTC. The user account involved throughout this activity is `employee`.

---

## Summary

On `11 July 2025`, the user `employee` intentionally installed and executed the Tor Browser on the `vm-lab-target` device. They subsequently launched the browser, established connections within the Tor network, and created multiple Tor-related artifacts on the desktop, including a file named `tor-shopping-list.txt`. This activity was deliberate, sustained, and generated several host- and network-level indicators of use.

---

## Response Taken

TOR usage was confirmed on the endpoint `vm-lab-target` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
