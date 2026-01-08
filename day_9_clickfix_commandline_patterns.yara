rule clickfix_commandline_patterns
{
  meta:
    description = "Detects common execution patterns in ClickFix / fake BSOD campaigns (PowerShell/VBS/curl/mshta/msiexec)"
    reference = "https://clickfix.carsonww.com/domains?limit=50"
    confidence = "medium"
    author = "TiiTcHY"

  strings:
        // PowerShell usage
        $ps1 = /powershell(\.exe)?\s+/ nocase
        $ps_enc = /-enc(odedcommand)?/ nocase
        $ps_iwr = /\b(iwr|invoke-webrequest)\b/i

        // TEMP staging paths
        $temp_path = /%temp%/ nocase

        // VBScript dropper chain
        $cmd_c = /cmd\s+\/c/i
        $curl = /\bcurl\b/i
        $vbs_ext = /\.vbs\b/i
        $wscript_vbs = /wscript\.exe\s+\/\/B\s+\/\/E:VBScript/i

        // mshta remote execution
        $mshta_remote = /\bmshta\b\s+https?:\/\//i

        // msiexec pulling from URL
        $msiexec_remote = /\bmsiexec\b.*https?:\/\//i

        // base64 → bash (linux/mac exposure)
        $b64_bash = /base64\s+-d\s+\|\s+bash/i

        // repeated ports & filenames
        $port5506 = /:5506\//i
        $dd_vbs = /dd\.vbs/i
        $qk_vbs = /qk\.vbs/i

    condition:
        // PowerShell download/execute
        ( $ps1 and ( $ps_enc or $ps_iwr ) )
        or
        // CMD + curl + VBS + wscript chain using %TEMP%
        ( $cmd_c and $curl and $wscript_vbs and $temp_path and $vbs_ext )
        or
        // mshta or msiexec remote execution
        ( $mshta_remote or $msiexec_remote )
        or
        // Base64 → bash pipeline
        $b64_bash
        or
        // Known repeated artifacts
        any of ( $port5506, $dd_vbs, $qk_vbs )
}