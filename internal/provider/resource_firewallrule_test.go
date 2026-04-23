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

func TestReconcileFirewallRuleStateKeepsBottomPosition(t *testing.T) {
	resource := &firewallRuleResource{}
	actual := firewallRuleResourceModel{
		Position:  types.StringValue("After"),
		AfterRule: types.StringValue("Default drop"),
	}
	expected := firewallRuleResourceModel{
		Position: types.StringValue("Bottom"),
	}

	reconciled := resource.reconcileFirewallRuleState(actual, expected)

	if reconciled.Position.ValueString() != "Bottom" {
		t.Fatalf("expected position Bottom, got %q", reconciled.Position.ValueString())
	}

	if !reconciled.AfterRule.IsNull() {
		t.Fatalf("expected after_rule to be null, got %q", reconciled.AfterRule.ValueString())
	}

	if !reconciled.BeforeRule.IsNull() {
		t.Fatalf("expected before_rule to be null, got %q", reconciled.BeforeRule.ValueString())
	}
}

func TestReconcileFirewallRuleStateKeepsBeforePosition(t *testing.T) {
	resource := &firewallRuleResource{}
	actual := firewallRuleResourceModel{
		Position:  types.StringValue("After"),
		AfterRule: types.StringValue("Internal to smarthost"),
	}
	expected := firewallRuleResourceModel{
		Position:   types.StringValue("Before"),
		BeforeRule: types.StringValue("FreeBSD Update"),
	}

	reconciled := resource.reconcileFirewallRuleState(actual, expected)

	if reconciled.Position.ValueString() != "Before" {
		t.Fatalf("expected position Before, got %q", reconciled.Position.ValueString())
	}

	if reconciled.BeforeRule.ValueString() != "FreeBSD Update" {
		t.Fatalf("expected before_rule to be preserved, got %q", reconciled.BeforeRule.ValueString())
	}

	if !reconciled.AfterRule.IsNull() {
		t.Fatalf("expected after_rule to be null, got %q", reconciled.AfterRule.ValueString())
	}
}
