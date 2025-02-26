# ESXi8-STIG-Compliance-Tool
This script automates the STIG check an remediation for an ESXi 8 host. Simply replace values at the top of the script with your own (such as target IP address) and execute script for the STIG check to commence.

The tool was built for **VMware vSphere 8.0 ESXi Security Technical Implementation Guide :: Version 2, Release: 2 Benchmark Date: 30 Jan 2025**  specifically, but may be inaccurate for future versions dependent on DISA changes. Checklists are publicly available on disa public cyber mil so I've included a blank one in this repo for convenience.

The first function is the STIG check, which identifies open vulnerabilities and fills out a corresponding output .ckl file. This data is then passed to the remediation function which will first identify your open vulnerability, and ask for permission to execute the fix command. All commands executed as well as output are transcribed to a log file.



Pre-requisites:
- Vmware.PowerCLI Module

HOW TO USE:
- Git clone repo to desired location
- Open script in powershell ISE (or favored text editor) and replace static values such as target IP adderess
- Execute script - you will be prompted for the credentials necessary for accessing your target ESXi host
- Output saved to a .ckl file (located in desktop by default) as well as log file



EXAMPLE:

![MicrosoftPowerShellISE2025 02 25-22 14 58 05-ezgif com-video-to-gif-converter](https://github.com/user-attachments/assets/c1a823c9-f5dd-471d-b2ef-956b16a66e84)
