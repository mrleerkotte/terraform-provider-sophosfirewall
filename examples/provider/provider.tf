provider "sophosfirewall" {
  endpoint = "https://192.168.1.1:4444"
  username = "admin"
  password = var.sophosfirewall_password
  insecure = true
}

variable "sophosfirewall_password" {
  type      = string
  sensitive = true
}
