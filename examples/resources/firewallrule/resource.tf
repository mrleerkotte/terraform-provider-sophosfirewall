resource "sophosfirewall_firewallrule" "allow_internal_web" {
  name        = "Allow Internal Web Traffic"
  description = "Allow HTTP/HTTPS traffic from LAN to WAN"
  policy_type = "Network"
  status      = "Enable"
  position    = "Top"
  ip_family   = "IPv4"
  schedule    = "All The Time"

  action              = "Accept"
  log_traffic         = "Enable"
  skip_local_destined = "Disable"

  source_zones      = ["LAN"]
  destination_zones = ["WAN"]

  source_networks      = ["LAN_NETWORK"]
  destination_networks = ["Any"]
  services             = ["HTTP", "HTTPS"]
}
