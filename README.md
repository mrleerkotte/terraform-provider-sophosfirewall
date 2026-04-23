---
page_title: "Sophos Firewall Provider"
subcategory: "Firewall"
description: |-
  Manage Sophos Firewall objects and firewall rules with Terraform.
---

# Sophos Firewall Provider

This provider exposes Sophos Firewall XML API objects using the `sophosfirewall` provider name.

## Provider Configuration

```hcl
provider "sophosfirewall" {
  endpoint = "https://192.168.1.1:4444"
  username = "admin"
  password = var.sophosfirewall_password
  insecure = true
}
```

## Resource Names

The provider uses compound resource names consistently:

* `sophosfirewall_iphost`
* `sophosfirewall_iphostgroup`
* `sophosfirewall_machost`
* `sophosfirewall_firewallrule`

## Example Usage

### IP Host

```hcl
resource "sophosfirewall_iphost" "web_server" {
  name       = "web_server"
  ip_family  = "IPv4"
  host_type  = "IP"
  ip_address = "192.168.1.10"
}
```

### IP Host Group

```hcl
resource "sophosfirewall_iphostgroup" "web_servers" {
  name      = "web_servers"
  ip_family = "IPv4"
  host_list = [sophosfirewall_iphost.web_server.name]
}
```

### MAC Host

```hcl
resource "sophosfirewall_machost" "example_mac" {
  name        = "example_mac"
  type        = "MACAddress"
  description = "Example MAC host"
  mac_address = "00:16:76:49:33:CE"
}
```

### Firewall Rule

```hcl
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

  source_networks      = [sophosfirewall_iphost.web_server.name]
  destination_networks = ["Any"]
}
```

## Import

Resources can be imported by Sophos Firewall object name:

```sh
terraform import sophosfirewall_iphost.web_server web_server
terraform import sophosfirewall_iphostgroup.web_servers web_servers
terraform import sophosfirewall_machost.example_mac example_mac
terraform import sophosfirewall_firewallrule.allow_internal_web "Allow Internal Web Traffic"
```
