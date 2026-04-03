# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/MasrurAhmed64782/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Searched for any file that had the string "tor" in it and discovered what looks like the user "labuser" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-03-28T18:04:05.3226251Z`. These events began at `2026-03-28T18:04:05.3226251Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "ahmed-test-vm"
| where InitiatingProcessAccountName == "labuser"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-03-28T18:04:05.3226251Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1889" height="796" alt="image" src="https://github.com/user-attachments/assets/07772886-a105-446b-8a6b-1c1b0de25090" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-15.0.8.exe". Based on the logs returned, at `2026-03-28T18:26:19.2049394Z`, an employee on the "ahmed-test-vm" device ran the file `tor-browser-windows-x86_64-portable-15.0.8.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "ahmed-test-vm"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.8.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1716" height="264" alt="image" src="https://github.com/user-attachments/assets/78009b82-d537-4056-85bf-2af7ce5909fa" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "labuser" actually opened the TOR browser. There was evidence that they did open it at `2026-03-28T18:25:48.0763126Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "ahmed-test-vm"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1687" height="542" alt="image" src="https://github.com/user-attachments/assets/08f82d8d-b0d7-4b21-bc8b-0e72fe009485" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-03-28T18:26:25.9882264Z`, an employee on the "ahmed-test-vm" device successfully established a connection to the remote IP address `85.195.253.142` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "ahmed-test-vm"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1716" height="412" alt="image" src="https://github.com/user-attachments/assets/9fa0340a-064e-4ace-a888-a949b55865ef" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-03-28T18:04:05.3226251Z`
- **Event:** The user "labuser" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.8.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-03-28T18:26:19.2049394Z`
- **Event:** The user "labuser" executed the file `tor-browser-windows-x86_64-portable-15.0.8.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.8.exe /s`
- **File Path:** `C:\Users\LABUSER\Downloads\tor-browser-windows-x86_64-portable-15.0.8.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-03-28T18:25:48.0763126Z`
- **Event:** User "labuser" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\LABUSER\Downloads\tor-browser-windows-x86_64-portable-15.0.8.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-03-28T18:26:25.9882264Z`
- **Event:** A network connection to IP `85.195.253.142` on port `9001` by user "labuser" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\LABUSER\Downloads\tor-browser-windows-x86_64-portable-15.0.8.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-03-28T18:27:25.096692Z` - Connected to `96.9.98.57` on port `443`.
  - `2026-03-28T18:26:25.9882264Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "labuser" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-03-28T18:38:28.7615428Z`
- **Event:** The user "labuser" created a file named `tor-shopping-list.txt` on the downloads, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\LABUSER\Documents\tor-shopping-list.txt`

---

## Summary

The user "labuser" on the "ahmed-test-vm" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `ahmed-test-vm` by the user `labuser`. The device was isolated, and the user's direct manager was notified.

---
