rule cobalt_strike_sleepmask_bytes
{
  meta:
    description = "Detects Cobalt Strike sleep mask function bytes (x64) as published by MDSec"
    author = "TiiTcHY"
    reference = "https://www.mdsec.co.uk/2022/07/part-2-how-i-met-your-beacon-cobalt-strike/"
    confidence = "high"
    scope = "memory"

  strings:
    $sleep_mask = {
      48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20
      45 33 DB 45 33 D2 33 FF 33 F6 48 8B E9 BB 03 00 00 00
      85 D2 0F 84 81 00 00 00 0F B6 45
    }

  condition:
    $sleep_mask
}
