resource "sophosfirewall_iphostgroup" "example_host_group" {
  name      = "example-host-group"
  ip_family = "IPv4"
  host_list = ["testHG"]
}
