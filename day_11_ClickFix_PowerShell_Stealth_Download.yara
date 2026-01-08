rule ClickFix_PowerShell_Stealth_Download
{
  meta:
    description = "Detects hidden PowerShell commands downloading and running secondary stages"
    reference = "https://clickfix.carsonww.com/domains?limit=50"
    confidence = "medium"
    author = "TiiTcHY"
	threat_actor = "ClickFix"

strings:
        $ps = "powershell" nocase
        $hidden = /-wind(owstyle)?\s+(mi|hi)/ nocase
        $enc = /-(enc|encodedcommand)/ nocase
        $dl = /iwr|Invoke-WebRequest|DownloadFile|DownloadString/ nocase
        $temp = /%temp%|\$env:temp|C:\\Users\\Public/ nocase
        $exec = /Start-Process|iex|Invoke-Expression/ nocase

    condition:
        $ps and ($hidden or $enc) and ($dl and ($temp or $exec))
}