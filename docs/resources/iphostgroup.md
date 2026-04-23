---
page_title: "Sophos: sophosfirewall_iphostgroup"
subcategory: "Host & Objects > Host Group"
description: |-
  Manages a Sophos IP Host Group object.
---

# Resource: sophosfirewall_iphostgroup

Manages a Sophos IP Host Group object. This resource allows you to create, update, and delete IP Host Group entries in your Sophos firewall.

## Example Usage for Single IP address

```hcl
resource "sophosfirewall_iphostgroup" "example_host_group" {
  name      = "example-host-group"
  ip_family = "IPv4"
  host_list = ["testHG"]
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required) Name of the IP Host Group.
* `ip_family` - (Required) IPv4 or IPv6
* `description` - (Optional) Description of the IP Host Group.

## Import

IP Host Groups can be imported using the name, e.g.,

```
$ terraform import sophosfirewall_iphostgroup.example_host_group example-host-group
```
