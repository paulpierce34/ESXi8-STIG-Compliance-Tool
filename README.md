# ESXi8-STIG-Compliance-Tool
This script automates the STIG check for an ESXi 8 host. Simply replace values at the top of the script with your own (such as target IP address) and execute script for the STIG check to commence.

The tool was built for **VMware vSphere 8.0 ESXi Security Technical Implementation Guide :: Version 2, Release: 2 Benchmark Date: 30 Jan 2025**  specifically, but may be inaccurate for future versions dependent on DISA changes. Checklists are publicly available on disa public cyber mil so I've included a blank one in this repo for convenience.

In the future I will build in a remediation function that goes through anything marked as non-compliant and remediates. The tricky part with this is consideration of different enterprise environments, but I've already built this version of the script nearly capable to remediate, so expect this functionality in the future.



Pre-requisites:
- Vmware.PowerCLI Module

HOW TO USE:
- Git clone repo to desired location
- Open script in powershell ISE (or favored text editor) and replace static values such as target IP adderess
- Execute script - you will be prompted for the credentials necessary for accessing your target ESXi host
- Output saved to a .ckl file (located in desktop by default) as well as log file



EXAMPLE:

![MicrosoftPowerShellISE2025 02 25-16 11 07 04-ezgif com-video-to-gif-converter](https://github.com/user-attachments/assets/6ac1119f-cd5f-4e71-9368-ad4a201940b1)
