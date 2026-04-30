---
page_title: "Sophos: sophosfirewall_firewallrule"
subcategory: "Firewall"
description: |-
  Manages a Sophos Firewall rule.
---

# Resource: sophosfirewall_firewallrule

Manages a Sophos Firewall rule. This resource allows you to create, update, and delete firewall rules in your Sophos firewall.

Use this resource for the rule body itself. If you want Terraform to manage ordered membership inside a Sophos rule group, use [`sophosfirewall_firewallrule_group`](./firewallrule_group.md) and put the rule names in `security_policy_list`.

## Example Usage

```hcl
resource "sophosfirewall_firewallrule" "allow_internal_web" {
  name        = "allow_internal_web"
  description = "Allow HTTP/HTTPS traffic from LAN to WAN"
  policy_type = "Network"
  
  # Rule action
  action      = "Accept"
  log_traffic = "Enable"
  
  # Zone settings
  source_zones      = ["LAN"]
  destination_zones = ["WAN"]
  
  # Network settings
  source_networks      = [sophosfirewall_iphost.terraformSrc2.name]
  destination_networks = [sophosfirewall_iphost.terraformDst3.name]
  services             = ["HTTP", "HTTPS"]

  depends_on = [
    sophosfirewall_iphost.terraformSrc2,
    sophosfirewall_iphost.terraformDst3
  ]
}
```

### Rule Body With Group-Owned Ordering

```hcl
resource "sophosfirewall_firewallrule" "app_to_db" {
  name        = "example_app_to_db"
  description = "Allow application traffic to the database tier"
  policy_type = "Network"
  action      = "Accept"

  source_zones      = ["APP"]
  destination_zones = ["DB"]
  source_networks   = ["app-node-a", "app-node-b"]
  services          = ["EXAMPLE-DB"]
}

resource "sophosfirewall_firewallrule_group" "managed" {
  name        = "example_managed_group"
  policy_type = "Any"

  security_policy_list = [
    sophosfirewall_firewallrule.app_to_db.name,
  ]
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required) Name of the firewall rule. Cannot be modified after creation.
* `description` - (Optional) Description of the rule.
* `ip_family` - (Optional) IP Family (IPv4 or IPv6). Defaults to IPv4.
* `status` - (Optional) Status (Enable or Disable). Defaults to Enable.
* `policy_type` - (Required) Policy Type (Network).
* `position` - (Optional) Position (Top, Bottom, After, Before). Use this only when you want the rule resource itself to control order. If you manage the rule through `sophosfirewall_firewallrule_group.security_policy_list`, omit per-rule ordering fields.
* `rule_group_name` - (Optional) Name of the Sophos firewall rule group for this rule. Prefer managing group membership and order through `sophosfirewall_firewallrule_group`.
* `after_rule` - (Optional) Rule to position after (used when position is 'After').
* `before_rule` - (Optional) Rule to position before (used when position is 'Before').
* `action` - (Required) Action (Accept, Reject, Drop).
* `log_traffic` - (Optional) Log traffic (Enable or Disable). Defaults to Disable.
* `skip_local_destined` - (Optional) Skip local destined (Enable or Disable). Defaults to Disable.
* `source_zones` - (Required) List of source zones.
* `destination_zones` - (Required) List of destination zones.
  `["Any"]` is supported and is normalized to Sophos' implicit API form.
* `schedule` - (Optional) Schedule name. Defaults to "".
* `source_networks` - (Optional) List of source networks.
* `destination_networks` - (Optional) List of destination networks.
* `services` - (Optional) List of Sophos service object names to match in the rule.

## Notes

* For managed ordered rule sets, use `sophosfirewall_firewallrule_group.security_policy_list` as the source of truth for order.
* Avoid mixing group-owned ordering with per-rule `position`, `after_rule`, or `before_rule` for the same ruleset.

## Import

Firewall rules can be imported using the name, e.g.,

```
$ terraform import sophosfirewall_firewallrule.allow_internal_web "Allow Internal Web Traffic"
```
