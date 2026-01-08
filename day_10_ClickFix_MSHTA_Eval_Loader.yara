rule ClickFix_MSHTA_Eval_Loader
{
  meta:
    description = "Detects MSHTA being used to eval obfuscated javascript/vbscript"
    reference = "https://clickfix.carsonww.com/domains?limit=50"
    confidence = "medium"
    author = "TiiTcHY"
	threat_actor = "ClickFix / ClearFake"

	strings:
			$mshta = "mshta" nocase
			$eval = /javascript:eval|vbscript:execute/ nocase
			$char = "String.fromCharCode" nocase
			$close = /window\.close|self\.close/ nocase
			$shell = "ActiveXObject(\"WScript.Shell\")" nocase

		condition:
			$mshta and ($eval and ($char or $close or $shell))
}