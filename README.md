```# VibeCoded_Chrysalis_PoC_Detection_Attempt_20260204.ps1

AI written (but working) Chrysalis Detection Script with Self-Elevation + Persistent Admin Window based on Rapid 7 and Kaspersky PoC info.

Asks for admin privilages, do not trust me - make sure you analyze the code before running. I am taking no responsibility for your system / PC etc.

Run the script from its folder with

powershell.exe -ExecutionPolicy Bypass -File .\VibeCoded_Chrysalis_PoC_Detection_Attempt_20260204..ps1

Result:

1 window asking for Admin privs:

PS D:\TestUser\Desktop\Notepad++ Chrysalis> powershell.exe -ExecutionPolicy Bypass -File .\VibeCoded_Chrysalis_PoC_Detection_Attempt_20260204..ps1
[*] Administrator privileges required.
[*] Requesting elevation...
[+] Elevated PowerShell launched.
Press ENTER to close this window:

2 Window with results:

Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

--- Starting system scan for Notepad++ Hijack / Chrysalis IoCs ---
Log file: D:\TestUser\Desktop\Notepad++ Chrysalis\OPTIPLEX-7010_2026-02-04_13-26.txt
[+] Directory not found: C:\Users\TestUser\AppData\Roaming\Bluetooth
[+] Directory not found: C:\Users\TestUser\AppData\Roaming\ProShow
[+] Directory not found: C:\Users\TestUser\AppData\Roaming\Adobe\Scripts
[!] ALERT: Suspicious directory present: C:\Users\TestUser\AppData\Roaming\Microsoft\Windows\Themes
    [?] File found: C:\Users\TestUser\AppData\Roaming\Microsoft\Windows\Themes\TranscodedWallpaper
    [?] File found: C:\Users\TestUser\AppData\Roaming\Microsoft\Windows\Themes\Transcoded_001
[+] Directory not found: C:\ProgramData\Windows\Themes
[+] Directory not found: C:\ProgramData\Microsoft\Bluetooth
[!] ALERT: Suspicious directory present: C:\ProgramData\Microsoft\Windows
    [?] File found: C:\ProgramData\Microsoft\Windows\AppxProvisioning.xml
[+] Chrysalis mutex not found: Global\Jdhfv_1.0.1
--- Scan complete ---
Results saved to: D:\TestUser\Desktop\Notepad++ Chrysalis\OPTIPLEX-7010_2026-02-04_13-26.txt

========== SUMMARY ==========
Scan completed successfully.
Log file saved at:
  D:\TestUser\Desktop\Notepad++ Chrysalis\OPTIPLEX-7010_2026-02-04_13-26.txt
=============================
Press ENTER to close this window:

And a log file saved in the same folder as script.

Catch you on the flip side,

AndrzejL

