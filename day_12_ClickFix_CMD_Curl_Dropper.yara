rule sliver_fortiweb_campaign_infra_strings
{
  meta:
    description = "Detects CMD/Curl being used to download and execute malicious vbs/bat files"
    reference = "https://clickfix.carsonww.com/domains?limit=50"
    confidence = "medium"
    author = "TiiTcHY"
	threat_actor = "ClickFix"

  strings:
        $cmd = "cmd /c" nocase
        $curl = "curl" nocase
        $silent = "-s -L"
        $output = "-o %temp%" nocase
        $run = /&& start|wscript\.exe|cscript\.exe/ nocase

    condition:
        $cmd and $curl and $silent and $output and $run
}