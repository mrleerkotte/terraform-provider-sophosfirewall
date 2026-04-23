package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/firewallrule"
)

func TestFirewallRuleServiceMappingToAPI(t *testing.T) {
	resource := &firewallRuleResource{}
	model := firewallRuleResourceModel{
		Name:             types.StringValue("allow_web"),
		PolicyType:       types.StringValue("Network"),
		Action:           types.StringValue("Accept"),
		SourceZones:      []types.String{types.StringValue("LAN")},
		DestinationZones: []types.String{types.StringValue("WAN")},
		Services:         []types.String{types.StringValue("HTTP"), types.StringValue("HTTPS")},
	}

	rule := resource.modelToAPIFirewallRule(model)

	if rule.NetworkPolicy == nil || rule.NetworkPolicy.Services == nil {
		t.Fatalf("expected services to be mapped into network policy")
	}

	got := rule.NetworkPolicy.Services.Services
	if len(got) != 2 || got[0] != "HTTP" || got[1] != "HTTPS" {
		t.Fatalf("unexpected services mapping: %#v", got)
	}
}

func TestFirewallRuleServiceMappingFromAPI(t *testing.T) {
	resource := &firewallRuleResource{}
	rule := firewallrule.FirewallRule{
		Name:       "allow_web",
		PolicyType: "Network",
		NetworkPolicy: &firewallrule.NetworkPolicy{
			Action: "Accept",
			Services: &firewallrule.ServiceList{
				Services: []string{"HTTP", "HTTPS"},
			},
		},
	}

	model := resource.apiToModelFirewallRule(rule)

	if len(model.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(model.Services))
	}

	if model.Services[0].ValueString() != "HTTP" || model.Services[1].ValueString() != "HTTPS" {
		t.Fatalf("unexpected services in model: %#v", model.Services)
	}
}
