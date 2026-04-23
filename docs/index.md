---
page_title: "Provider: Sophos Firewall"
description: |-
  The Sophos Firewall provider is used to interact with resources supported by Sophos Firewall. The provider needs to be configured with proper credentials before it can be used.
---

# Sophos Firewall Provider

The Sophos Firewall provider is used to interact with resources supported by Sophos Firewall. The provider needs to be configured with proper credentials before it can be used.

Use the navigation on the left to read about the available resources.

## Example Usage

```hcl
# Configure the Sophos Firewall provider
provider "sophosfirewall" {
  endpoint = "https://192.168.1.1:4444"
  username = "admin"
  password = var.sophosfirewall_password
  insecure = true
}

# Create a firewall rule
resource "sophosfirewall_firewallrule" "example" {
  # ...resource configuration...
}
```

## Authentication

Static credentials can be provided by specifying the `username` and `password` attributes in the provider block:

```hcl
provider "sophosfirewall" {
  endpoint = "https://192.168.1.1:4444"
  username = "admin"
  password = "your-password"
}
```

## Argument Reference

The following arguments are supported in the provider block:

* `endpoint` - (Required) The endpoint URL of the Sophos Firewall XML API.
* `username` - (Required) Username for Sophos Firewall.
* `password` - (Required, Sensitive) Password for Sophos Firewall.
* `insecure` - (Optional) Whether to skip TLS verification. Defaults to `false`.
