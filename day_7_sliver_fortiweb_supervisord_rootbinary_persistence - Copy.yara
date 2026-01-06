rule sliver_fortiweb_supervisord_rootbinary_persistence
{
  meta:
    description = "Detects supervisord persistence used in Ctrl-Alt-Int3l FortiWeb->Sliver campaign."
    reference = "https://ctrlaltintel.com/threat%20research/FortiWeb-Sliver/"
    confidence = "high"
	author = "TiiTcHY"

  strings:
    $sup1 = "[supervisord]" ascii
    $sup2 = "nodaemon=true" ascii

    $prog = "[program:rootbinary]" ascii
    $cmd  = "command=/bin/.root/system-updater" ascii
    $as   = "autostart=true" ascii
    $ar   = "autorestart=true" ascii

  condition:
    $cmd and 3 of ($sup1,$sup2,$prog,$as,$ar)
}