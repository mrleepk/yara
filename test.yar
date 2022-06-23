rule RemoteControlUrlAccessed

{

meta:

 author = "@neonprimetime"

 description = "Cloud Remote Control Url Accessed"

strings:

 $string0 = "teamviewer" nocase

 $string1 = "splashtop" nocase

 $string2 = "ammyy" nocase

 $string3 = "mikogo" nocase

 $string4 = "uvnc" nocase

 $string5 = "gbchcmhmhahfdphkhkmpfmihenigjmpp" nocase

 $string6 = "logmein" nocase

 $string7 = "join.me" nocase

 $string8 = "realvnc" nocase

 $string9 = "dameware" nocase

 $string10 = "dwservice" nocase

 $string11 = "anydesk" nocase

condition:

 1 of them

}
