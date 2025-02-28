# ESXi8-STIG-Compliance-Tool
This script automates the STIG check and remediation for an ESXi 8 host. Simply replace values at the top of the script with your own (such as target IP address) and execute script for the STIG check to commence.

The tool was built for **VMware vSphere 8.0 ESXi Security Technical Implementation Guide :: Version 2, Release: 2 Benchmark Date: 30 Jan 2025**  specifically, but may be inaccurate for future versions dependent on DISA changes. Checklists are publicly available on disa public cyber mil so I've included a blank one in this repo for convenience.

The first function is the STIG check, which identifies open vulnerabilities and fills out a corresponding output .ckl file. This data is then passed to the remediation function which will first identify your open vulnerability, and ask for permission to execute the fix command. All commands executed as well as output are transcribed to a log file.



**Pre-requisites:**
- Vmware.PowerCLI Module

**HOW TO USE:**
- Git clone repo to desired location
- Open script in powershell ISE (or favored text editor) and replace static values such as target IP address
- Execute script - you will be prompted for the credentials necessary for accessing your target ESXi host
- STIG check output saved to a .ckl file (located in desktop by default) as well as log file
- Remediation function begins automatically, press 'Enter' to continue
- You will be prompted for each 'Open' vulnerability and if you want to execute the fix command
- Type 'no' or 'skip' to skip remediation of prompted item
- All remediation input/output PowerShell transcription logs will be saved on disk


**EXAMPLES:**

![image](https://github.com/user-attachments/assets/47543684-643b-44db-9d81-d0932ca5ef21)


STIG Check:

![MicrosoftPowerShellISE2025 02 25-22 14 58 05-ezgif com-video-to-gif-converter](https://github.com/user-attachments/assets/c1a823c9-f5dd-471d-b2ef-956b16a66e84)

STIG Stats:
![image](https://github.com/user-attachments/assets/494a9bf8-df01-4442-9649-ac42c8aec100)

Remediation Function Prompt **(you can say no to remediating individual STIG items)**:
![image](https://github.com/user-attachments/assets/b64f675a-5375-43ee-a6d8-f628e73dc2c9)

Successful Remediation Transcription Log:
![image](https://github.com/user-attachments/assets/177e3c9a-fe09-4efe-8a4a-3d3d34b98179)
