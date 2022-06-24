rule AnyDeskExeOnDisk
{
meta:
 author = "Ollie"
 description = "Finds Anydesk Executables on disk"
 filetype = "exe"
strings:
 $string0 = "anydesk" nocase
condition:
 (filesize < 10MB) and (uint16(0) == 0x5a4d) and all of them
}

rule TeamViewerExeOnDisk
{
meta:
 author = "Ollie"
 description = "Finds TeamViewer Executables on disk"
  filetype = "exe"
strings:
 $string0 = "teamviewer" nocase
condition:
 (filesize < 50MB) and (uint16(0) == 0x5a4d) and all of them
}

rule TightVNCExeOnDisk
{
meta:
 author = "Ollie"
 description = "Finds Tight VNC Executables on disk"
  filetype = "exe"
strings:
 $string0 = "support@glavsoft.com" nocase
 $string1 = "adfind -default" nocase
condition:
 (filesize < 5MB) and (uint16(0) == 0x5a4d) and 1 of them
}

rule SplashtopExeOnDisk
{
meta:
 author = "Ollie"
 description = "Finds SplashtopExecutables on disk"
  filetype = "exe"
strings:
 $string0 = "splashtop" nocase
condition:
 (filesize < 50MB) and (uint16(0) == 0x5a4d) and all of them
}

/*
TOOLS
*/
rule ADFindExeOnDisk
{
meta:
 author = "Ollie"
 description = "Finds ADFind Executables on disk"
  filetype = "exe"
strings:
 $string0 = "adfind" nocase
 $string1 = "adfind -default" nocase
condition:
 (filesize < 5MB) and (uint16(0) == 0x5a4d) and 1 of them
}

rule BloodhoundExeOnDisk
{
meta:
 author = "Ollie"
 description = "Finds Bloodhound executables on disk"
  filetype = "exe"
strings:
 $string0 = "bloodhound" nocase
condition:
 (filesize < 200MB) and (uint16(0) == 0x5a4d) and all of them
}

rule AdvancedIPScannerExeOnDisk
{
meta:
 author = "Ollie"
 description = "Finds Advanced IP scanner Executables on disk"
strings:
 $string0 = "Advanced IP Scanner" ascii wide
 $string1 = "advanced_ip_scanner" nocase
 condition:
 (filesize < 50MB) and (uint16(0) == 0x5a4d) and 1 of them
}

rule AngryIPScannerExeOnDisk
{
meta:
 author = "Ollie"
 description = "Finds Angry IP Scanner Executables on disk"
  filetype = "exe"
strings:
 $string0 = "angryip.org" nocase
 $string1 = "Angry IP Scanner" ascii wide
condition:
 (filesize < 10MB) and (uint16(0) == 0x5a4d) and 1 of them
}


/*
Persistence
*/
rule GOSimpleTunnelExeOnDisk
{
meta:
 author = "Ollie"
 description = "Finds Go Simple Tunnel Executables on disk"
  filetype = "exe"
strings:
 $string0 = "github.com/ginuerzh/gost" nocase
condition:
 (filesize < 20MB) and (uint16(0) == 0x5a4d) and all of them
}

rule ngrok_binaries {
  meta:
    author      = "Moath Maharmeh"
    date        = "2021/Sep/28"
    description = "Find NGROK agent binaries"
    filetype    = "exe"
  strings:
    $s1 = "ngrok" fullword
    $s2 = "go.ngrok.com"
    $s3 = "https://s3.amazonaws.com/dns.ngrok.com/tunnel.json"
    $s4 = "ngrokService"
    $s5 = "HTTPRoundTrip_KeyVal"
  condition:
    (
      uint16(0) == 0x5a4d
    ) and
    (3 of ($s*))
}

rule Ngrok_Config_Files {
  meta:
    description = "Detects Ngrok config file"
    autho = "Florian Roth"
    date = "201-05-14"

  strings:
    $s1 = "proto: tcp" ascii
    $s2 = "addr:" ascii fullword
    $s3 = "authtoken:" ascii fullword

  condition:
   filesize < 200KB and 
   all of them
}

rule PlinkExeOnDisk
{
meta:
 author = "Ollie"
 description = "Finds Plink Executables on disk"
  filetype = "exe"
strings:
 $string0 = "plink" nocase
 $string1 = "PLINK_PROTOCOL" nocase
condition:
 (filesize < 5MB) and (uint16(0) == 0x5a4d) and 1 of them
}

rule PuttyExeOnDisk
{
meta:
 author = "Ollie"
 description = "Finds PuTTy Executables on disk"
  filetype = "exe"
strings:
 $string0 = "putty@projects.tartarus.org" nocase
 $string1 = "PuTTy" nocase
condition:
 (filesize < 5MB) and (uint16(0) == 0x5a4d) and 1 of them
}


/*
Exfiltration
*/
rule rclone_binaries {
  meta:
    author      = "Elida Leite"
    date        = "2022/Jan/26"
    description = "Find RCLONE binary. Application used by attackers to exfiltrate data"
    filetype    = "exe"
    reference   = "https://rclone.org/"

  strings:
     $s1 = "https://rclone.org"
     $s2 = "The Rclone Authors" ascii wide

  condition:
    uint16(0) == 0x5a4d and all of them
}

rule Rclone_Config_Files {
  meta:
    description = "Detects Rclone config file"
    author = "Elida Leite"
    date = "2022/Feb/16"
    filetype    = "conf"
    reference   = "https://rclone.org/"

  strings:
    $s1 = "type =" ascii
    $s2 = "user =" ascii 
    $s3 = "pass =" ascii

  condition:
   filesize < 10KB and 
   all of them
}

rule FilezillaExeOnDisk
{
meta:
 author = "Ollie"
 description = "Finds Filezilla Executables on disk"
 filetype = "exe"
strings:
 $string0 = "tim.kosse" nocase
 $string0 = "FileZilla" nocase
condition:
 (filesize < 25MB) and (uint16(0) == 0x5a4d) and all of them
}

rule MEGASyncExeOnDisk
{
meta:
 author = "Ollie"
 description = "Finds MEGASync Executables on disk"
 filetype = "exe"
strings:
 $string0 = "mega limited" nocase
condition:
 (filesize < 75MB) and (uint16(0) == 0x5a4d) and all of them
}

/*
Credential Access
*/
rule ProcdumpExeOnDisk
{
meta:
 author = "Ollie"
 description = "Finds Procdump Executables on disk"
 filetype = "exe"
strings:
 $string0 = "procdump" nocase
condition:
 (filesize < 2MB) and (uint16(0) == 0x5a4d) and all of them
}

rule MimikatzExeOnDisk
{
meta:
 author = "Ollie"
 description = "Finds Mimikatz Executables on disk"
  filetype = "exe"
strings:
 $string0 = "gentilkiwi" nocase
 $string1 = "mimikatz" nocase
condition:
 (filesize < 10MB) and (uint16(0) == 0x5a4d) and 1 of them
}

rule LazagneExeOnDisk
{
meta:
 author = "Ollie"
 description = "Finds Lazagne Executables on disk"
  filetype = "exe"
strings:
 $string0 = "lazagne" nocase
condition:
 (filesize < 10MB) and (uint16(0) == 0x5a4d) and all of them
}
