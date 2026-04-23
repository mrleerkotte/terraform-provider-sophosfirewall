---
page_title: "Sophos: sophosfirewall_machost"
subcategory: "Host & Objects > MAC Host"
description: |-
  Manages a Sophos Firewall MAC host.
---

# Resource: sophosfirewall_machost

Manages a MAC host. This resource allows you to create, update, and delete MAC hosts in your Sophos firewall.

## Example Usage for Single MAC host

```hcl
resource "sophosfirewall_machost" "ExampleMACAddress" {
  name        = "ExampleMACAddress"
  type        = "MACAddress"
  description = "test"
  mac_address = "00:16:76:49:33:CE"
}
```

## Example Usage for MAC List host

```hcl
resource "sophosfirewall_machost" "ExampleMACList" {
  name                  = "ExampleMACList"
  type                  = "MACLIST"
  description           = "test"
  list_of_mac_addresses = "00:16:76:49:33:CE,00:16:76:49:33:CB"
}

```

## Argument Reference

The following arguments are supported:

* `name` - (Required) Name of the MAC host. Cannot be modified after creation.
* `description` - (Optional) Description of the host.
* `type` - (Required) MAC Type (MACAddress or MACLIST).
* `mac_address` - (Required) Specify single MAC address.
* `list_of_mac_addresses` - (Required) List of MAC addresses commad separated.

## Import

MAC Hosts can be imported using the name, e.g.,

```
$ terraform import sophosfirewall_machost.example ExampleMACAddress
```
