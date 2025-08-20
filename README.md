# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/TiaraYancey/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Searched for any file that had the string "tor" in it and discovered what looks like the user "labuser" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-08-20T14:16:11.137549Z `. These events began at `2025-08-20T14:05:20.0720207Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName contains "tor"
| where DeviceName == "final-lab-tiara"
| where Timestamp >= datetime(2025-08-20T14:05:20.0720207Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, account = InitiatingProcessAccountName

```
<img width="1135" height="278" alt="Screenshot 2025-08-20 141528" src="https://github.com/user-attachments/assets/94e77e23-53ce-43b2-8c58-da8b3b8bad26" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows". Based on the logs returned, at `August 20, 2025 at 10:08 AM`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows"
| where DeviceName == "final-lab-tiara"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, FolderPath, SHA256, AccountName
```
<img width="1160" height="104" alt="Screenshot 2025-08-20 141700" src="https://github.com/user-attachments/assets/9ec0dd4d-b0fd-4c67-9112-32a970bbb253" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "labuser" actually opened the TOR browser. There was evidence that they did open it at `2025-08-20T14:08:31.1958179Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "final-lab-tiara"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-brower.exe")
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, FolderPath, SHA256, AccountName
| order by Timestamp desc 
```
<img width="1134" height="352" alt="Screenshot 2025-08-20 142105" src="https://github.com/user-attachments/assets/ab16dae7-9d20-469b-864d-df58136d04f2" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-08-20T14:09:08.3283146Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "final-lab-tiara"
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl, ActionType
| order by Timestamp desc
```
<img width="1148" height="145" alt="Screenshot 2025-08-20 142345" src="https://github.com/user-attachments/assets/1fe3e585-88bf-4927-b348-a37dbf273f4c" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-08-20T14:05:20.0720207Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `August 20, 2025 at 10:08 AM`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-08-20T14:08:31.1958179Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-08-20T14:09:08.3283146Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-08-08T14:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2025-08-08T14:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-08-20T14:16:11.137549Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\labuser\Desktop\tor-shopping-list.txt`

---

## Summary

The user "labuser" on the "final-lab-tiara" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `final-lab-tiara` by the user `labuser`. The device was isolated, and the user's direct manager was notified.

---
