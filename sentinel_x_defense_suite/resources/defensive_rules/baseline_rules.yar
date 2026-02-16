rule Suspicious_Domain_Pattern {
  meta:
    author = "Sentinel X"
    description = "Detección base de patrones de dominio sospechosos"
  strings:
    $d1 = "onion" nocase
    $d2 = "pastebin" nocase
    $d3 = "dynDNS" nocase
  condition:
    any of them
}
