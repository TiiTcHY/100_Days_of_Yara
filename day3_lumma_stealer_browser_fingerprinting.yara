rule lumma_stealer_browser_fingerprinting {
  meta:
    description = "Detect outbound HTTP traffic consistent with Lumma Stealer browser fingerprinting: /api/set_agent with id(32-hex), token, agent; plus optional POST logging."
	author = "TiiTcHY"
    reference = "https://www.trendmicro.com/en_us/research/25/k/lumma-stealer-browser-fingerprinting.html"
    false_positives = "Apps could expose /api/set_agent. Tune via domain exclusions and stricter token/agent constraints."

  events:
    $http.metadata.event_type = "NETWORK_HTTP"
    $url = coalesce($http.network.http.url, $http.network.http.request_url)
    $domain = coalesce($http.network.http.domain, $http.network.http.host)
	
    re.regex($url, `(?i)\/api\/set_agent(?:\?|$)`)

    (
      // GET: /api/set_agent?id=<32hex>&token=<...>&agent=<...>
      (
        $http.network.http.method = "GET"
        and re.regex($url, `(?i)(?:\?|&)id=[0-9a-f]{32}(?:&|$)`)
        and re.regex($url, `(?i)(?:\?|&)token=[^&]{8,256}(?:&|$)`)
        and re.regex($url, `(?i)(?:\?|&)agent=(?:chrome|chromium|edge|firefox|safari|opera)[^&]{0,32}(?:&|$)`)
      )
      or
      // POST: /api/set_agent ... often used to submit fingerprint logs (variant-dependent)
      (
        $http.network.http.method = "POST"
        and (
          // Some telemetry sources keep params in URL even for POST
          re.regex($url, `(?i)(?:\?|&)id=[0-9a-f]{32}(?:&|$)`)
          or re.regex($url, `(?i)(?:\?|&)act=log(?:&|$)`)
        )
      )
    )

    
    $http.principal.ip = $src_ip
    $domain = $dst_domain

  match:
    $src_ip, $dst_domain over 10m

  outcome:
    $risk_score = 75
    $principal_ip = array_distinct($http.principal.ip)
    $principal_hostname = array_distinct($http.principal.hostname)
    $target_domain = array_distinct($dst_domain)
    $target_url = array_distinct($url)
    $http_method = array_distinct($http.network.http.method)
    $user_agent = array_distinct($http.network.http.user_agent)
    $event_count = count_distinct($http.metadata.id)

  condition:
    $http
}
