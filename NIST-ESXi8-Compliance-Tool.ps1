## The purpose of this script is to automate the STIG check, checklist, and remediation parts of the system hardening process
## This script attempts to login to your ESXi host via connect-viserver and will prompt you for credentials.




Import-Module Vmware.PowerCLI

## REPLACE VALUES IN THIS SECTION BEFORE RUNNING SCRIPT ################################################

$TargetServer = "192.168.5.5" ## Replace with your esxi server IP (MANDATORY replace)

[XML]$BlankFile = Get-Content -Path "$env:USERPROFILE\Desktop\blank-esxi.ckl" ## Path to blank STIG checklist file (expects version 2, release 2 benchmark date 30 Jan 2025) (replace optional)

$DestinationFile = "$env:USERPROFILE\Desktop\STIGged-esxi.ckl" ## Output STIG .ckl file (replace optional)

$Timestamp = Get-Date -Format "yyyy-MM-dd-ss"
$LogOutputFile = "$env:USERPROFILE\Desktop\$Timestamp-esx-stig-script-logs_pre-remediation.txt" ## Log output file (replace optional)
$RemediationLogOutputFile = "$env:USERPROFILE\Desktop\$Timestamp-esx-stig-script-logs_transcript-post-remediation.txt"
######################################################################################################

## Connect to ESX host and prompt user for creds
Connect-VIServer -Server $TargetServer

sleep(5)
write-warning "About to begin STIG check process. No system changes will be made. Press enter to continue"
pause









## Save all vulns from the blank checklist above to a variable
$AllVulns = $BlankFile.CHECKLIST.STIGs.iSTIG.VULN



$DODBannerConfig = @"
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. 
By using this IS (which includes any device attached to this IS), you consent to the following conditions: 
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. 
-At any time, the USG may inspect and seize data stored on this IS. 
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. 
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. 
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. 
Such communications and work product are private and confidential. See User Agreement for details.
"@

## for use with some commands
$esxcli = Get-EsxCli -v2

#Elements in array are as follows [VulnID, {Check Cmd}, {Fix Cmd}, 'Desired Result', 'NotReviewed' (if you want to mark as not reviewed regardless of results)]
$Vuln258728 = 'V-258728',{Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures},{Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures | Set-AdvancedSetting -Value 3},'Security.AccountLockFailures:3','$false',''
$Vuln258729 = 'V-258729',{Get-VMHost | Get-AdvancedSetting -Name Annotations.WelcomeMessage},{Get-VMHost | Get-AdvancedSetting -Name Annotations.WelcomeMessage | Set-AdvancedSetting -Value $DODBannerConfig},'$DODBannerConfig','$false',''
$Vuln258730 = 'V-258730',{(Get-VMHost | Select Name,@{N="Lockdown";E={$_.Extensiondata.Config.LockdownMode}}).Lockdown},{},'lockdownEnabled','$false',''
$Vuln258731 = 'V-258731',{(Get-VMHost | Get-AdvancedSetting -Name UserVars.HostClientSessionTimeout).Value},{Get-VMHost | Get-AdvancedSetting -Name UserVars.HostClientSessionTimeout | Set-AdvancedSetting -Value "900"},'900','$false',''
$Vuln258732 = 'V-258732',{$esxcli = Get-EsxCli -v2; $arguments = $esxcli.system.security.fips140.ssh.set.CreateArgs(); $arguments.enable = $true; $esxcli.system.security.fips140.ssh.set.Invoke($arguments)},{$arguments = $esxcli.system.security.fips140.ssh.set.CreateArgs();$arguments.enable=$True;$esxcli.system.security.fips140.ssh.set.Invoke($arguments)},'true','$false',''
$Vuln258733 = 'V-258733',{Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.log.level},{},'info','',''
$Vuln258734 = 'V-258734',{Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl},{Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl | Set-AdvancedSetting -Value "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"},'similar=deny retry=3 min=disabled,disabled,disabled,disabled,15','$false',''
$Vuln258735 = 'V-258735',{Get-VMHost | Get-AdvancedSetting -Name Security.PasswordHistory},{Get-VMHost | Get-AdvancedSetting -Name Security.PasswordHistory | Set-AdvancedSetting -Value 5},'5','$false',''
$Vuln258736 = 'V-258736',{Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob},{Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob | Set-AdvancedSetting -Value false},'false','$false',''
$Vuln258737 = 'V-258737',{Get-VMHost | Get-VMHostAuthentication},{Get-VMHost},'Active','NotReviewed',''
$Vuln258738 = 'V-258738',{$esxcli = Get-EsxCli -v2; ($esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'ignorerhosts'}).Value},{},'yes','',''
$Vuln258739 = 'V-258739',{Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut},{Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Set-AdvancedSetting -Value 900},'900','',''
$Vuln258740 = 'V-258740',{$esxcli = Get-EsxCli -v2; ($esxcli.system.settings.encryption.get.invoke() | Select RequireSecureBoot).RequireSecureBoot},{},'true','',''
$Vuln258741 = 'V-258741',{((Get-VMHost).ExtensionData.Capability).UefiSecureBoot},{},'enabled','',''
$Vuln258742 = 'V-258742',{Get-VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime},{Get-VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime | Set-AdvancedSetting -Value 900},'900','',''
$Vuln258743 = 'V-258743',{Get-VMHost | Get-AdvancedSetting -Name Syslog.global.auditRecord.storageCapacity},{Get-VMHost | Get-AdvancedSetting -Name Syslog.global.auditRecord.storageCapacity | Set-AdvancedSetting -Value 100},'100','',''
$Vuln258744 = 'V-258744',{Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost},{},'logserver','NotReviewed',''
$Vuln258745 = 'V-258745',{(Get-VMHost | Get-VMHostService | Where {$_.Label -eq "NTP Daemon" -or $_.Label -eq "PTP Daemon"}).running[1]},{},'true','',''
$Vuln258746 = 'V-258746',{$esxcli = Get-EsxCli -v2; $esxcli.software.acceptance.get.Invoke()},{$esxcli = Get-EsxCli -v2; $arguments = $esxcli.software.acceptance.set.CreateArgs(); $arguments.level = "PartnerSupported"; $esxcli.software.acceptance.set.Invoke($arguments)},'PartnerSupported','',''
$Vuln258747 = 'V-258747',{Get-VMHost | Get-VMHostHba | Where {$_.Type -eq "iscsi"} | Select AuthenticationProperties -ExpandProperty AuthenticationProperties},{},'','NotReviewed',''
$Vuln258748 = 'V-258748',{},{},'','NotReviewed',''
$Vuln258750 = 'V-258750',{($esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'ciphers'}).Value},{$esxcli = Get-EsxCli -v2; $arguments = $esxcli.system.ssh.server.config.set.CreateArgs(); $arguments.keyword = 'ciphers'; $arguments.value = 'aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr'; $esxcli.system.ssh.server.config.set.Invoke($arguments)},'aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr','',''
$Vuln258751 = 'V-258751',{(Get-VMHost | Get-AdvancedSetting -Name DCUI.Access).Value},{},'root','',''
$Vuln258752 = 'V-258752',{Get-VMHost | Get-AdvancedSetting -Name Config.Etc.issue},{Get-VMHost | Get-AdvancedSetting -Name Config.Etc.issue | Set-AdvancedSetting -Value $DoDBannerConfig}, $DODBannerConfig,'',''
$Vuln258753 = 'V-258753',{$esxcli = Get-EsxCli -v2; ($esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'banner'}).Value},{$esxcli = Get-EsxCli -v2; $arguments = $esxcli.system.ssh.server.config.set.CreateArgs(); $arguments.keyword = 'banner'; $arguments.value = '/etc/issue'; $esxcli.system.ssh.server.config.set.Invoke($arguments)},'/etc/issue','',''
$Vuln258754 = 'V-258754',{(Get-VMHost | Get-VMHostService | Where {$_.Label -eq "SSH"}).Running},{Get-VMHost | Get-VMHostService | Where {$_.Label -eq "SSH"} | Set-VMHostService -Policy Off; Get-VMHost | Get-VMHostService | Where {$_.Label -eq "SSH"} | Stop-VMHostService},'false','',''
$Vuln258755 = 'V-258755',{(Get-VMHost | Get-VMHostService | Where {$_.Label -eq "ESXi Shell"}).Running},{Get-VMHost | Get-VMHostService | Where {$_.Label -eq "ESXi Shell"} | Set-VMHostService -Policy Off; Get-VMHost | Get-VMHostService | Where {$_.Label -eq "ESXi Shell"} | Stop-VMHostService},'false','',''
$Vuln258756 = 'V-258756',{(Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut).Value},{Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut | Set-AdvancedSetting -Value 600},'600','',''
$Vuln258757 = 'V-258757',{(Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut).Value},{Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut | Set-AdvancedSetting -Value 600},'600','',''
$Vuln258758 = 'V-258758',{},{},'','NotReviewed',''
$Vuln258759 = 'V-258759',{},{},'','NotReviewed',''
$Vuln258760 = 'V-258760',{},{},'','NotReviewed',''
$Vuln258761 = 'V-258761',{$esxcli = Get-EsxCli -v2; ($esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'hostbasedauthentication'}).Value.ToString()},{$esxcli = Get-EsxCli -v2; $arguments = $esxcli.system.ssh.server.config.set.CreateArgs(); $arguments.keyword = 'hostbasedauthentication'; $arguments.value = 'no'; $esxcli.system.ssh.server.config.set.Invoke($arguments)},'no','',''
$Vuln258762 = 'V-258762',{$esxcli = Get-EsxCli -v2; ($esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'permituserenvironment'}).Value.ToString()},{$esxcli = Get-EsxCli -v2; $arguments = $esxcli.system.ssh.server.config.set.CreateArgs(); $arguments.keyword = 'permituserenvironment'; $arguments.value = 'no'; $esxcli.system.ssh.server.config.set.Invoke($arguments)},'no','',''
$Vuln258763 = 'V-258763',{$esxcli = Get-EsxCli -v2; ($esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'gatewayports'}).Value.ToString()},{$esxcli = Get-EsxCli -v2; $arguments = $esxcli.system.ssh.server.config.set.CreateArgs(); $arguments.keyword = 'gatewayports'; $arguments.value = 'no'; $esxcli.system.ssh.server.config.set.Invoke($arguments)},'no',''
$Vuln258764 = 'V-258764',{$esxcli = Get-EsxCli -v2; ($esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'permittunnel'}).Value.ToString()},{$esxcli = Get-EsxCli -v2; $arguments = $esxcli.system.ssh.server.config.set.CreateArgs(); $arguments.keyword = 'permittunnel'; $arguments.value = 'no'; $esxcli.system.ssh.server.config.set.Invoke($arguments)},'no','',''
$Vuln258765 = 'V-258765',{$esxcli = Get-EsxCli -v2; ($esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'clientalivecountmax'}).Value.ToString()},{$esxcli = Get-EsxCli -v2; $arguments = $esxcli.system.ssh.server.config.set.CreateArgs(); $arguments.keyword = 'clientalivecountmax'; $arguments.value = '3'; $esxcli.system.ssh.server.config.set.Invoke($arguments)},'3','',''
$Vuln258766 = 'V-258766',{$esxcli = Get-EsxCli -v2; ($esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'clientaliveinterval'}).Value.ToString()},{$esxcli = Get-EsxCli -v2; $arguments = $esxcli.system.ssh.server.config.set.CreateArgs(); $arguments.keyword = 'clientaliveinterval'; $arguments.value = '200'; $esxcli.system.ssh.server.config.set.Invoke($arguments)},'200','',''
$Vuln258767 = 'V-258767',{(Get-VMHostSnmp | Select *).Enabled},{Get-VMHostSnmp | Set-VMHostSnmp -Enabled $false},'False','',''
$Vuln258768 = 'V-258768',{(Get-VMHost | Get-AdvancedSetting -Name Mem.ShareForceSalting).ToString()},{Get-VMHost | Get-AdvancedSetting -Name Mem.ShareForceSalting | Set-AdvancedSetting -Value 2},'2','',''
$Vuln258769 = 'V-258769',{$esxcli = Get-EsxCli -v2; ($esxcli.network.firewall.get.invoke()).Enabled},{$esxcli = Get-EsxCli -v2; $arguments = $esxcli.network.firewall.set.CreateArgs(); $arguments.enabled = $true; $arguments.defaultaction = $false; $esxcli.network.firewall.set.Invoke($arguments)},'true','',''
$Vuln258770 = 'V-258770',{(Get-VMHost | Get-AdvancedSetting -Name Net.BlockGuestBPDU).ToString()},{Get-VMHost | Get-AdvancedSetting -Name Net.BlockGuestBPDU | Set-AdvancedSetting -Value 1},'1','',''
$Vuln258771 = 'V-258771',{(Get-VirtualSwitch | Get-SecurityPolicy).ForgedTransmits},{Get-VirtualSwitch | Get-SecurityPolicy | Set-SecurityPolicy -ForgedTransmits $false; Get-VirtualPortGroup | Get-SecurityPolicy | Set-SecurityPolicy -ForgedTransmitsInherited $true},'False','',''
$Vuln258772 = 'V-258772',{(Get-VirtualSwitch | Get-SecurityPolicy).MacChanges},{Get-VirtualSwitch | Get-SecurityPolicy | Set-SecurityPolicy -MacChanges $false; Get-VirtualPortGroup | Get-SecurityPolicy | Set-SecurityPolicy -MacChangesInherited $true},'False','',''
$Vuln258773 = 'V-258773',{(Get-VirtualSwitch | Get-SecurityPolicy).AllowPromiscuous},{Get-VirtualSwitch | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuous $false; Get-VirtualPortGroup | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuousInherited $true},'False','',''
$Vuln258774 = 'V-258774',{(Get-VMHost | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress).Value},{Get-VMHost | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress | Set-AdvancedSetting -Value ""},'','',''
$Vuln258775 = 'V-258775',{(Get-VirtualPortGroup | Select Name, VLanID).VlanID},{},'','NotReviewed',''
$Vuln258776 = 'V-258776',{},{},'','NotReviewed',''
$Vuln258777 = 'V-258777',{(Get-VMHost | Get-AdvancedSetting -Name UserVars.SuppressShellWarning).Value},{Get-VMHost | Get-AdvancedSetting -Name UserVars.SuppressShellWarning | Set-AdvancedSetting -Value 0},'0','',''
$Vuln258778 = 'V-258778',{(Get-VMHost | Get-AdvancedSetting -Name UserVars.SuppressHyperthreadWarning).Value},{Get-VMHost | Get-AdvancedSetting -Name UserVars.SuppressHyperthreadWarning | Set-AdvancedSetting -Value 0},'0','',''
$Vuln258779 = 'V-258779',{(Get-VMHost | Get-AdvancedSetting -Name Syslog.global.certificate.checkSSLCerts).ToString()},{Get-VMHost | Get-AdvancedSetting -Name Syslog.global.certificate.checkSSLCerts | Set-AdvancedSetting -Value "true"},'True','',''
$Vuln258780 = 'V-258780',{(Get-VMHost | Get-AdvancedSetting -Name Mem.MemEagerZero).ToString()},{Get-VMHost | Get-AdvancedSetting -Name Mem.MemEagerZero | Set-AdvancedSetting -Value 1},'1','',''
$Vuln258781 = 'V-258781',{(Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.vmacore.soap.sessionTimeout).ToString()},{Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.vmacore.soap.sessionTimeout | Set-AdvancedSetting -Value 30},'30','',''
$Vuln258782 = 'V-258782',{(Get-VMHost | Get-AdvancedSetting -Name Security.PasswordMaxDays).ToString()},{Get-VMHost | Get-AdvancedSetting -Name Security.PasswordMaxDays | Set-AdvancedSetting -Value 90},'90','',''
$Vuln258783 = 'V-258783',{(Get-VMHost | Get-VMHostService | Where {$_.Label -eq "CIM Server"}).Running},{Get-VMHost | Get-VMHostService | Where {$_.Label -eq "CIM Server"} | Set-VMHostService -Policy Off; Get-VMHost | Get-VMHostService | Where {$_.Label -eq "CIM Server"} | Stop-VMHostService},'False','',''
$Vuln258784 = 'V-258784',{},{},'','NotReviewed',''
$Vuln258785 = 'V-258785',{$esxcli = Get-EsxCli -v2; ($esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'allowtcpforwarding'}).Value.ToString()},{$esxcli = Get-EsxCli -v2; $arguments = $esxcli.system.ssh.server.config.set.CreateArgs(); $arguments.keyword = 'allowtcpforwarding'; $arguments.value = 'no'; $esxcli.system.ssh.server.config.set.Invoke($arguments)},'no','',''
$Vuln258786 = 'V-258786',{(Get-VMHost | Get-VMHostService | Where {$_.Label -eq "slpd"}).Running},{Get-VMHost | Get-VMHostService | Where {$_.Label -eq "slpd"} | Set-VMHostService -Policy Off; Get-VMHost | Get-VMHostService | Where {$_.Label -eq "slpd"} | Stop-VMHostService},'False','',''
$Vuln258787 = 'V-258787',{(Get-VMHost | Get-AdvancedSetting -Name Syslog.global.auditRecord.storageEnable).ToString()},{Get-VMHost | Get-AdvancedSetting -Name Syslog.global.auditRecord.storageEnable | Set-AdvancedSetting -Value "true"},'True','',''
$Vuln258788 = 'V-258788',{(Get-VMHost | Get-AdvancedSetting -Name Syslog.global.auditRecord.remoteEnable).ToString()},{Get-VMHost | Get-AdvancedSetting -Name Syslog.global.auditRecord.remoteEnable | Set-AdvancedSetting -Value "true"},'True','',''
$Vuln258789 = 'V-258789',{(Get-VMHost | Get-AdvancedSetting -Name Syslog.global.certificate.strictX509Compliance).ToString()},{Get-VMHost | Get-AdvancedSetting -Name Syslog.global.certificate.strictX509Compliance | Set-AdvancedSetting -Value "true"},'True','',''
$Vuln258790 = 'V-258790',{(Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logLevel).ToString()},{Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logLevel | Set-AdvancedSetting -Value "info"},'info','',''
$Vuln258791 = 'V-258791',{},{},'','NotReviewed',''
$Vuln258792 = 'V-258792',{},{},'','NotReviewed',''
$Vuln258793 = 'V-258793',{$esxcli = Get-EsxCli -v2; ($esxcli.system.settings.encryption.get.invoke() | Select Mode).Mode},{$esxcli = Get-EsxCli -v2; $arguments = $esxcli.system.settings.encryption.set.CreateArgs(); $arguments.mode = "TPM"; $esxcli.system.settings.encryption.set.Invoke($arguments)},'TPM','',''
$Vuln258794 = 'V-258794',{Get-VMHost | Get-VMHostFirewallException | Where {($_.Enabled -eq $true) -and ($_.ExtensionData.IpListUserConfigurable -eq $true)}},{},'','NotReviewed',''
$Vuln258795 = 'V-258795',{Get-VMHostProfile},{},'','NotReviewed',''
$Vuln258796 = 'V-258796',{(Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup).ToString()},{},'','NotReviewed',''
$Vuln258797 = 'V-258797',{$esxcli = Get-EsxCli -v2; ($esxcli.system.syslog.config.get.Invoke() | Select LocalLogOutput,LocalLogOutputIsPersistent).LocalLogOutputIsPersistent},{Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logDir | Set-AdvancedSetting -Value "/scratch/log"},'true','',''
$Vuln258798 = 'V-258798',{(Get-VMHost | Get-AdvancedSetting -Name VMkernel.Boot.execInstalledOnly).Value},{Get-VMHost | Get-AdvancedSetting -Name VMkernel.Boot.execInstalledOnly | Set-AdvancedSetting -Value True},'True','',''
$Vuln258799 = 'V-258799',{$esxcli = Get-EsxCli -v2; ($esxcli.system.settings.kernel.list.invoke() | Where {$_.Name -eq "disableHwrng" -or $_.Name -eq "entropySources"}).Configured},{},'false','',''
$Vuln258800 = 'V-258800',{$esxcli = Get-EsxCli -v2; ($esxcli.system.syslog.config.logfilter.get.invoke()).LogFilteringEnabled},{$esxcli = Get-EsxCli -v2; $arguments = $esxcli.system.syslog.config.logfilter.set.CreateArgs(); $arguments.logfilteringenabled = $false; $esxcli.system.syslog.config.logfilter.set.invoke($arguments)},'false','',''
$Vuln265974 = 'V-265974',{},{},'','NotReviewed',''
$Vuln265975 = 'V-265975',{},{},'','NotReviewed',''
$Vuln265976 = 'V-265976',{$esxcli = Get-EsxCli -v2; ($esxcli.system.account.list.Invoke() | Where-Object {$_.UserID -eq 'dcui'}).Shellaccess},{$esxcli = Get-EsxCli -v2; $arguments = $esxcli.system.account.set.CreateArgs(); $arguments.id = "dcui"; $arguments.shellaccess = "false"; $esxcli.system.account.set.invoke($arguments)},'false','',''
$Vuln265977 = 'V-265977',{(Get-VMHost | Get-AdvancedSetting -Name Net.BMCNetworkEnable).ToString()},{Get-VMHost | Get-AdvancedSetting -Name Net.BMCNetworkEnable | Set-AdvancedSetting -Value 0},'0','',''

## Huge array of all the above data for each vuln
$VulnList = $Vuln258728,$Vuln258729,$Vuln258730,$Vuln258731,$Vuln258732,$Vuln258733,$Vuln258734,$Vuln258735,$Vuln258736, $Vuln258737, $Vuln258738, $Vuln258739, $Vuln258740, $Vuln258741, $Vuln258742, $Vuln258743, $Vuln258744, $Vuln258745, $Vuln258746, $Vuln258747, $Vuln258748, $Vuln258750, $Vuln258751, $Vuln258752, $Vuln258753, $Vuln258754, $Vuln258755, $Vuln258756, $Vuln258757, $Vuln258758, $Vuln258759, $Vuln258760, $Vuln258761, $Vuln258762, $Vuln258763, $Vuln258764, $Vuln258765, $Vuln258766, $Vuln258767, $Vuln258768, $Vuln258769, $Vuln258770, $Vuln258771, $Vuln258772, $Vuln258773, $Vuln258774, $Vuln258775, $Vuln258776, $Vuln258777, $Vuln258778, $Vuln258779, $Vuln258780, $Vuln258781, $Vuln258782, $Vuln258783, $Vuln258784, $Vuln258785, $Vuln258786, $Vuln258787, $Vuln258788, $Vuln258789, $Vuln258790, $Vuln258791, $Vuln258792, $Vuln258793, $Vuln258794, $Vuln258795, $Vuln258796, $Vuln258797, $Vuln258798, $Vuln258799, $Vuln258800, $Vuln265974, $Vuln265975, $Vuln265976, $Vuln265977


function Confirm-STIGStatus{

## Variables for counting
$VulnCount = 0 ## Number of vulns in total
$Compliant = 0 ## Number of compliant controls
$QuestionableCompliant = 0 ## Number of vulns marked for review
$NonCompliant = 0 ## Number of noncompliant vulns

foreach ($CKLVuln in $AllVulns){

## Create variables for vuln number, status, finding details, and comments found in the blank checklist.
$CKLVulnNumber = $CKLVuln.Childnodes[0].ATTRIBUTE_DATA
$CKLStatus = $CKLVuln.Status
$CKLFindingDetails = $CKLVuln.FINDING_DETAILS
$CKLComments = $CKLVuln.Comments

foreach ($Vulnitem in $VulnList){

## Save the command we are executing on ESX host to a variable so we can add to comments
$STIGCommand = $VulnItem[1].ToSTring()

## If V- number from our array above matches the V- number in the blank STIG checklist
if ($Vulnitem[0] -match $CKLVulnNumber){

write-host "===================================================="
write-host $Vulnitem[0]

## Increment vuln count by 1
$VulnCount += 1

## Save result to a variable
$ActualResult = Invoke-command $VulnItem[1]

## if not reviewed
if ($Vulnitem[4] -eq "NotReviewed"){
    $QuestionableCompliant += 1
    write-host -foregroundcolor yellow "NOT_REVIEWED: Saving for manual human interaction"

    ## Update status
    $CKLVuln.Status = "Not_Reviewed"
    $CKLVuln.FINDING_Details = "Marked as not reviewed for human review"
    $CKLVuln.Comments = "Tested by command: $STIGCommand"
    break
}


## If compliant
if ($ActualResult -match $Vulnitem[3]){
    $Compliant += 1
    write-host -foregroundcolor green "COMPLIANT value: $ActualResult"

    ## Update status
    $CKLVuln.Status = "NotAFinding"
    $CKLVuln.FINDING_Details = $ActualResult.ToString()
    $CKLVuln.Comments = "Tested by command: $STIGCommand"
    break
}




## If non-compliant
else {
    $NonCompliant += 1
    $Vulnitem[5] = "RemediateMe"
    write-host -foregroundcolor red "NON-COMPLIANT value: $ActualResult"
    ## yell at user
    #write-host Bad server! You need to be remediated for item $Vulnitem[0]

    if ($ActualResult -ne $null){
    $CKLVuln.Status = "Open"
    $CKLVuln.FINDING_Details = $ActualResult.ToString()
    $CKLVuln.Comments = "Tested by command: $STIGCommand"
    }
    else {
    $CKLVuln.Status = "Open"
    $CKLVuln.Comments = "Tested by command: $STIGCommand"
    }

    ## Write vuln status to host
    write-host $CKLVuln.Status

    ## Output to log file
    write-output Non-Compliant: $Vulnitem[0] >> $LogOutputFile

    break

} ## end non-compliant else






} ## end if vuln number matches

} ## end foreach


} ## end foreach CKL vuln

## Write friendly messages to host
write-host "================================================="
write-host "Total Vulnerability Count: $VulnCount"
write-host "Total Not Reviewed Count: $QuestionableCompliant"
write-host "Compliant Count: $Compliant"
write-host "Noncompliant Count: $NonCompliant"
write-host "================================================="

## Log file output
write-output "=================================================" >> $LogOutputFile
write-output "Total Vulnerability Count: $VulnCount" >> $LogOutputFile
write-output "Total Not Reviewed Count: $QuestionableCompliant" >> $LogOutputFile
write-output "Compliant Count: $Compliant" >> $LogOutputFile
write-output "Noncompliant Count: $NonCompliant" >> $LogOutputFile
write-output "=================================================" >> $LogOutputFile

} ## end function

Confirm-STIGStatus




## XML Settings to try and replicate those of STIGViewer #######################################################################################################################
$XMLSettings = New-Object -TypeName System.XML.XMLWriterSettings
$XMLSettings.Indent = $true;
$XMLSettings.IndentChars = "`t"
$XMLSettings.NewLineChars="`n"
$XMLSettings.Encoding = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList @($false)
$XMLSettings.ConformanceLevel = [System.Xml.ConformanceLevel]::Document
### End of STIGViewer settings ########################################################################################################################################

## Creates the XML (.ckl) doc
$XMLWriter = [System.XML.XmlWriter]::Create($DestinationFile, $XMLSettings)  ## creates file at $Destination location with $XMLSettings -- (blank)
$BlankFile.Save($XMLWriter) ## Saves the originally blank file with modifications to a new file. Does not modify original blank file on disk.
$XMLWriter.Flush()
$XMLWriter.Dispose()


if (Test-Path $DestinationFile){
write-host -foregroundcolor Green "Completed checklist found here: $DestinationFile"
}
else {
write-host "Failed to output to $DestinationFile"
}
write-host "`n"
write-host "STIG CHECK complete. Please see output .ckl and log file for more details."


function Remediate-STIG{

Start-Transcript -Path $RemediationLogOutputFile

write-host "`n"
write-host "`n"
write-host "`n"

write-host "=================================================================="
write-host "REMEDIATION FUNCTION AUTO START. NO COMMANDS WILL BE EXECUTED WITHOUT YOUR PERMISSION. YOU WILL BE PROMPTED FOR EACH ITEM FOUND. PRESS ENTER TO CONTINUE."
write-host "=================================================================="
write-host "`n"
write-host "`n"
write-host "`n"
pause

$ExcludeList = @("V-258730", "V-258740", "V-258741", "V-258745")


foreach ($Vulnitem in $VulnList){

## Notify user of what will be excluded
if ($ExcludeList -contains $Vulnitem[0]){

write-host -foreground red Excluding $Vulnitem[0]

}

if ($Vulnitem[5] -match "RemediateMe" -and $Vulnitem[2] -ne $null -and $ExcludeList -notcontains $Vulnitem[0]){
write-host "=============================================================="
write-warning "The following item has been marked as non-compliant:"

write-host $Vulnitem[0]
write-host "`n"
write-host -foregroundcolor Yellow Fix command:
write-host  $Vulnitem[2]
## Perhaps tell the user here what the current setting is?
write-host "`n"

$ContinueOrNot = read-host "Do you want to execute the above fix command for this vulnerability? (type no to skip remediation)"
if ($ContinueOrNot -notmatch "skip" -and $ContinueOrNot -notmatch "n" -and $ContinueOrNot -notmatch "no"){

invoke-command $Vulnitem[2]

} ## end user prompt
else {

write-host -foregroundcolor yellow Skipping item $Vulnitem[0]
write-host "`n"
write-host "`n"

}

} ## end if item needs remediation condition

} ## end foreach 

write-host -Foregroundcolor Green "Remediation section has been completed. Feel free to re-run this script for another pass through"
Stop-Transcript

} ## end function



write-host "`n"
write-host "`n"
Remediate-STIG
