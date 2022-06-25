/*
______            _              __   _____  ______  ___   ______      _           
| ___ \          | |             \ \ / / _ \ | ___ \/ _ \  | ___ \    | |          
| |_/ /__ _ _ __ | |_ ___  _ __   \ V / /_\ \| |_/ / /_\ \ | |_/ /   _| | ___  ___ 
|    // _` | '_ \| __/ _ \| '__|   \ /|  _  ||    /|  _  | |    / | | | |/ _ \/ __|
| |\ \ (_| | |_) | || (_) | |      | || | | || |\ \| | | | | |\ \ |_| | |  __/\__ \
\_| \_\__,_| .__/ \__\___/|_|      \_/\_| |_/\_| \_\_| |_/ \_| \_\__,_|_|\___||___/
           | |                                                                     
           |_|                                                                     
                                                     ___._
                                                   .'  <0>'-.._
                                                  /  /.--.____")
                                                 |   \   __.-'~
                                                 |  :  -'/
                                                /:.  :.-'
__________                                     | : '. |
'--.____  '--------.______       _.----.-----./      :/
        '--.__            `'----/       '-.      __ :/
              '-.___           :           \   .'  )/
                    '---._           _.-'   ] /  _/
                         '-._      _/     _/ / _/
                             \_ .-'____.-'__< |  \___
                               <_______.\    \_\_---.7
                              |   /'=r_.-'     _\\ =/
                          .--'   /            ._/'>
                        .'   _.-'
                       / .--'
                      /,/
                      |/`)
                      'c=,
*/


/*
RATS
*/
//Anydesk
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

//TeamViewer
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

//TightVNC
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

//Splashtop
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

//ATERA Agent - Need to collect binaries

//Screenconnect - Need to collect binaries

/*
TOOLS
*/
//ADFind
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

//Bloodhound
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

//Advanced IP scanner
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

//Angry IP Scanner
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
//GO Simple Tunnel GOST
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

//ngrok
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

//Plink
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

//Putty
rule PuttyExeOnDisk
{
meta:
 author = "Ollie"
 description = "Finds PuTTy Executables on disk"
  filetype = "exe"
strings:
 $string0 = "putty@projects.tartarus.org" nocase
 $string1 = "SimonTatham.PuTTy" nocase
condition:
 (filesize < 5MB) and (uint16(0) == 0x5a4d) and 1 of them
}


/*
Exfiltration
*/
//Rclone
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

//Filezilla
rule FilezillaExeOnDisk
{
meta:
 author = "Ollie"
 description = "Finds Filezilla Executables on disk"
 filetype = "exe"
strings:
 $string0 = "tim.kosse" nocase
 $string1 = "FileZilla" nocase
condition:
 (filesize < 25MB) and (uint16(0) == 0x5a4d) and all of them
}


//MEGASync
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
//Procdump
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

//Mimikatz
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

//Lazagne
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
