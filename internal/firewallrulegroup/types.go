package firewallrulegroup

type FirewallRuleGroup struct {
	Name               string              `xml:"Name"`
	Description        string              `xml:"Description,omitempty"`
	SecurityPolicyList *SecurityPolicyList `xml:"SecurityPolicyList,omitempty"`
	SourceZones        *ZoneList           `xml:"SourceZones,omitempty"`
	DestinationZones   *ZoneList           `xml:"DestinationZones,omitempty"`
	PolicyType         string              `xml:"Policytype"`
	TransactionID      string              `xml:"transactionid,attr,omitempty"`
}

type SecurityPolicyList struct {
	SecurityPolicies []string `xml:"SecurityPolicy"`
}

type ZoneList struct {
	Zones []string `xml:"Zone"`
}
