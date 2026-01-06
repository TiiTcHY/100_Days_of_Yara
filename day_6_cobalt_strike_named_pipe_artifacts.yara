rule cobalt_strike_named_pipe_artifacts
{
  meta:
    description = "Detects default-ish Cobalt Strike named pipe patterns often present in Beacon/in-memory strings."
    author = "TiiTcHY"
    confidence = "medium"
    reference = "DFIR Report + Cobalt Strike blog + Sekoia notes on default pipe conventions"

  strings:
    $p1 = "\\\\.\\pipe\\MSSE-" ascii nocase
    $p2 = "\\pipe\\MSSE-" ascii nocase
    $p3 = "msagent_" ascii nocase

  condition:
    any of ($p*)
}
