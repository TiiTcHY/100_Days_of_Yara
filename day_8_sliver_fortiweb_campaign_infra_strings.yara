rule sliver_fortiweb_campaign_infra_strings
{
  meta:
    description = "Tracks Ctrl-Alt-Int3l FortiWeb-Sliver campaign via domain/URL strings and tool drop paths."
    reference = "https://ctrlaltintel.com/threat%20research/FortiWeb-Sliver/"
    confidence = "medium"
    author = "TiiTcHY"

  strings:
    $c2a = "ns1.ubunutpackages.store" ascii nocase
    $c2b = "ns1.bafairforce.army" ascii nocase
    $frp = "45.83.181.160:8003/frpc.toml" ascii

    // Deployment paths called out
    $p1 = "/bin/.root/system-updater" ascii
    $p2 = "/app/web/system-updater" ascii

  condition:
    // Require at least one infra IOC AND one on-host artifact to reduce FPs
    ( $c2a or $c2b or $frp ) and ( $p1 or $p2 )
}
