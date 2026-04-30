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
