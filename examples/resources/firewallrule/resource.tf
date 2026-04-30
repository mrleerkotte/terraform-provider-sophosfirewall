resource "sophosfirewall_firewallrule" "allow_internal_web" {
  name        = "Allow Internal Web Traffic"
  description = "Allow HTTP/HTTPS traffic from LAN to WAN"
  policy_type = "Network"

  action              = "Accept"
  log_traffic         = "Enable"

  source_zones      = ["LAN"]
  destination_zones = ["WAN"]

  source_networks      = ["LAN_NETWORK"]
  destination_networks = ["Any"]
  services             = ["HTTP", "HTTPS"]
}
