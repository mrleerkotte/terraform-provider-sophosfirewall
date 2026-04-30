---
page_title: "Sophos: sophosfirewall_firewallrule_group"
subcategory: "Firewall"
description: |-
  Manages a Sophos Firewall rule group.
---

# Resource: sophosfirewall_firewallrule_group

Manages a Sophos Firewall rule group. This resource allows you to create, update, and delete firewall rule groups in your Sophos firewall.

Use this resource as the ordering owner for managed rule sets. The order of entries in `security_policy_list` is the intended order of rules inside the Sophos group.

## Example Usage

```hcl
resource "sophosfirewall_firewallrule" "app_to_db" {
  name              = "example_app_to_db"
  policy_type       = "Network"
  action            = "Accept"
  source_zones      = ["APP"]
  destination_zones = ["DB"]
  services          = ["EXAMPLE-DB"]
}

resource "sophosfirewall_firewallrule" "backup_to_storage" {
  name              = "example_backup_to_storage"
  policy_type       = "Network"
  action            = "Accept"
  source_zones      = ["BACKUP"]
  destination_zones = ["STORAGE"]
  services          = ["EXAMPLE-BACKUP"]
}

resource "sophosfirewall_firewallrule_group" "managed" {
  name        = "example_managed_group"
  description = "Example managed firewall rules"
  policy_type = "Any"

  security_policy_list = [
    sophosfirewall_firewallrule.app_to_db.name,
    sophosfirewall_firewallrule.backup_to_storage.name,
  ]
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required) Name of the firewall rule group. Cannot be modified after creation.
* `description` - (Optional) Description of the rule group.
* `policy_type` - (Required) Policy type allowed in the group, such as `Network`, `User`, `WAF`, or `Any`.
* `source_zones` - (Optional) Source zones associated with the group.
* `destination_zones` - (Optional) Destination zones associated with the group.
* `security_policy_list` - (Required in practice) Ordered list of firewall rule names in the group. Sophos does not support creating empty firewall rule groups.

## Notes

* The order of `security_policy_list` is the provider's source of truth for rule order inside the group.
* Prefer this resource over per-rule ordering when you manage more than one related rule.
* Avoid mixing `security_policy_list` ordering with per-rule `position`, `after_rule`, or `before_rule` for the same managed ruleset.

## Import

Firewall rule groups can be imported using the name, e.g.,

```sh
$ terraform import sophosfirewall_firewallrule_group.managed "example_managed_group"
```
