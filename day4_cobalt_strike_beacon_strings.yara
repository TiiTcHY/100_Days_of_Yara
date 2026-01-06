rule cobalt_strike_beacon_strings
{
  meta:
    description = "Heuristic detection for Cobalt Strike Beacon artifacts in PE/DLL or memory. Evasive against customized profiles."
    reference = "Cobalt Strike blog discusses removing strings like ReflectiveLoader/beacon.dll"
	author = "TiiTcHY"
    confidence = "medium"
    fp_note = "May match legitimate red team usage or repacked samples."

  strings:
    $s1 = "ReflectiveLoader" ascii nocase
    $s2 = "beacon.dll" ascii nocase
    $s3 = "beacon.x64.dll" ascii nocase
    $s4 = "This program cannot be run in DOS mode" ascii

  condition:
    2 of ($s*) 
}
