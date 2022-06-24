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
