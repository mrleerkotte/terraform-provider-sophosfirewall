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

func TestFirewallRuleEmptyDescriptionMapsToNull(t *testing.T) {
	resource := &firewallRuleResource{}
	rule := firewallrule.FirewallRule{
		Name:        "allow_web",
		Description: "",
		PolicyType:  "Network",
	}

	model := resource.apiToModelFirewallRule(rule)

	if !model.Description.IsNull() {
		t.Fatalf("expected empty description to map to null, got %#v", model.Description)
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

func TestReconcileFirewallRuleStateKeepsAnyZones(t *testing.T) {
	resource := &firewallRuleResource{}
	actual := firewallRuleResourceModel{}
	expected := firewallRuleResourceModel{
		SourceZones:      []types.String{types.StringValue("Any")},
		DestinationZones: []types.String{types.StringValue("Any")},
	}

	reconciled := resource.reconcileFirewallRuleState(actual, expected)

	if len(reconciled.SourceZones) != 1 || reconciled.SourceZones[0].ValueString() != "Any" {
		t.Fatalf("expected source_zones to remain Any, got %#v", reconciled.SourceZones)
	}

	if len(reconciled.DestinationZones) != 1 || reconciled.DestinationZones[0].ValueString() != "Any" {
		t.Fatalf("expected destination_zones to remain Any, got %#v", reconciled.DestinationZones)
	}
}

func TestReconcileFirewallRuleStateKeepsAnyServices(t *testing.T) {
	resource := &firewallRuleResource{}
	actual := firewallRuleResourceModel{}
	expected := firewallRuleResourceModel{
		Services: []types.String{types.StringValue("Any")},
	}

	reconciled := resource.reconcileFirewallRuleState(actual, expected)

	if len(reconciled.Services) != 1 || reconciled.Services[0].ValueString() != "Any" {
		t.Fatalf("expected services to remain Any, got %#v", reconciled.Services)
	}
}

func TestReconcileFirewallRuleStatePreservesSourceZoneOrderWhenSetMatches(t *testing.T) {
	resource := &firewallRuleResource{}
	actual := firewallRuleResourceModel{
		SourceZones: []types.String{
			types.StringValue("DMZ"),
			types.StringValue("SRV"),
			types.StringValue("WireGuard"),
			types.StringValue("MGMT"),
		},
	}
	expected := firewallRuleResourceModel{
		SourceZones: []types.String{
			types.StringValue("SRV"),
			types.StringValue("MGMT"),
			types.StringValue("DMZ"),
			types.StringValue("WireGuard"),
		},
	}

	reconciled := resource.reconcileFirewallRuleState(actual, expected)

	for i, zone := range expected.SourceZones {
		if reconciled.SourceZones[i].ValueString() != zone.ValueString() {
			t.Fatalf("expected source_zones order to match plan, got %#v", reconciled.SourceZones)
		}
	}
}

func TestReconcileFirewallRuleStatePreservesDestinationZoneOrderWhenSetMatches(t *testing.T) {
	resource := &firewallRuleResource{}
	actual := firewallRuleResourceModel{
		DestinationZones: []types.String{
			types.StringValue("WAN"),
			types.StringValue("VPN"),
		},
	}
	expected := firewallRuleResourceModel{
		DestinationZones: []types.String{
			types.StringValue("VPN"),
			types.StringValue("WAN"),
		},
	}

	reconciled := resource.reconcileFirewallRuleState(actual, expected)

	for i, zone := range expected.DestinationZones {
		if reconciled.DestinationZones[i].ValueString() != zone.ValueString() {
			t.Fatalf("expected destination_zones order to match plan, got %#v", reconciled.DestinationZones)
		}
	}
}

func TestReconcileFirewallRuleStateDoesNotMaskActualZoneChanges(t *testing.T) {
	resource := &firewallRuleResource{}
	actual := firewallRuleResourceModel{
		SourceZones: []types.String{
			types.StringValue("LAN"),
			types.StringValue("DMZ"),
		},
	}
	expected := firewallRuleResourceModel{
		SourceZones: []types.String{
			types.StringValue("LAN"),
			types.StringValue("WAN"),
		},
	}

	reconciled := resource.reconcileFirewallRuleState(actual, expected)

	if reconciled.SourceZones[1].ValueString() != "DMZ" {
		t.Fatalf("expected actual zone changes to remain visible, got %#v", reconciled.SourceZones)
	}
}

func TestReconcileFirewallRuleStatePreservesServiceOrderWhenSetMatches(t *testing.T) {
	resource := &firewallRuleResource{}
	actual := firewallRuleResourceModel{
		Services: []types.String{
			types.StringValue("HTTPS"),
			types.StringValue("HTTP"),
			types.StringValue("SMTP"),
		},
	}
	expected := firewallRuleResourceModel{
		Services: []types.String{
			types.StringValue("HTTP"),
			types.StringValue("SMTP"),
			types.StringValue("HTTPS"),
		},
	}

	reconciled := resource.reconcileFirewallRuleState(actual, expected)

	for i, service := range expected.Services {
		if reconciled.Services[i].ValueString() != service.ValueString() {
			t.Fatalf("expected services order to match plan, got %#v", reconciled.Services)
		}
	}
}

func TestReconcileFirewallRuleStateDoesNotMaskActualServiceChanges(t *testing.T) {
	resource := &firewallRuleResource{}
	actual := firewallRuleResourceModel{
		Services: []types.String{
			types.StringValue("HTTP"),
			types.StringValue("HTTPS"),
		},
	}
	expected := firewallRuleResourceModel{
		Services: []types.String{
			types.StringValue("HTTP"),
			types.StringValue("SMTP"),
		},
	}

	reconciled := resource.reconcileFirewallRuleState(actual, expected)

	if reconciled.Services[1].ValueString() != "HTTPS" {
		t.Fatalf("expected actual service changes to remain visible, got %#v", reconciled.Services)
	}
}

func TestReconcileFirewallRuleStatePreservesSourceNetworkOrderWhenSetMatches(t *testing.T) {
	resource := &firewallRuleResource{}
	actual := firewallRuleResourceModel{
		SourceNetworks: []types.String{
			types.StringValue("host-b"),
			types.StringValue("host-a"),
			types.StringValue("host-c"),
		},
	}
	expected := firewallRuleResourceModel{
		SourceNetworks: []types.String{
			types.StringValue("host-a"),
			types.StringValue("host-c"),
			types.StringValue("host-b"),
		},
	}

	reconciled := resource.reconcileFirewallRuleState(actual, expected)

	for i, network := range expected.SourceNetworks {
		if reconciled.SourceNetworks[i].ValueString() != network.ValueString() {
			t.Fatalf("expected source_networks order to match plan, got %#v", reconciled.SourceNetworks)
		}
	}
}

func TestReconcileFirewallRuleStatePreservesDestinationNetworkOrderWhenSetMatches(t *testing.T) {
	resource := &firewallRuleResource{}
	actual := firewallRuleResourceModel{
		DestinationNetworks: []types.String{
			types.StringValue("net-b"),
			types.StringValue("net-a"),
		},
	}
	expected := firewallRuleResourceModel{
		DestinationNetworks: []types.String{
			types.StringValue("net-a"),
			types.StringValue("net-b"),
		},
	}

	reconciled := resource.reconcileFirewallRuleState(actual, expected)

	for i, network := range expected.DestinationNetworks {
		if reconciled.DestinationNetworks[i].ValueString() != network.ValueString() {
			t.Fatalf("expected destination_networks order to match plan, got %#v", reconciled.DestinationNetworks)
		}
	}
}

func TestReconcileFirewallRuleStateDoesNotMaskActualSourceNetworkChanges(t *testing.T) {
	resource := &firewallRuleResource{}
	actual := firewallRuleResourceModel{
		SourceNetworks: []types.String{
			types.StringValue("host-a"),
			types.StringValue("host-b"),
		},
	}
	expected := firewallRuleResourceModel{
		SourceNetworks: []types.String{
			types.StringValue("host-a"),
			types.StringValue("host-c"),
		},
	}

	reconciled := resource.reconcileFirewallRuleState(actual, expected)

	if reconciled.SourceNetworks[1].ValueString() != "host-b" {
		t.Fatalf("expected actual source_network changes to remain visible, got %#v", reconciled.SourceNetworks)
	}
}

func TestReconcileFirewallRuleStateDoesNotMaskActualDestinationNetworkChanges(t *testing.T) {
	resource := &firewallRuleResource{}
	actual := firewallRuleResourceModel{
		DestinationNetworks: []types.String{
			types.StringValue("net-a"),
			types.StringValue("net-b"),
		},
	}
	expected := firewallRuleResourceModel{
		DestinationNetworks: []types.String{
			types.StringValue("net-a"),
			types.StringValue("net-c"),
		},
	}

	reconciled := resource.reconcileFirewallRuleState(actual, expected)

	if reconciled.DestinationNetworks[1].ValueString() != "net-b" {
		t.Fatalf("expected actual destination_network changes to remain visible, got %#v", reconciled.DestinationNetworks)
	}
}

func TestModelToAPIFirewallRuleOmitsAnyZones(t *testing.T) {
	resource := &firewallRuleResource{}
	model := firewallRuleResourceModel{
		Name:             types.StringValue("allow_any"),
		PolicyType:       types.StringValue("Network"),
		Action:           types.StringValue("Accept"),
		SourceZones:      []types.String{types.StringValue("Any")},
		DestinationZones: []types.String{types.StringValue("Any")},
	}

	rule := resource.modelToAPIFirewallRule(model)

	if rule.NetworkPolicy.SourceZones != nil {
		t.Fatalf("expected source_zones Any to be omitted from API payload, got %#v", rule.NetworkPolicy.SourceZones)
	}

	if rule.NetworkPolicy.DestinationZones != nil {
		t.Fatalf("expected destination_zones Any to be omitted from API payload, got %#v", rule.NetworkPolicy.DestinationZones)
	}
}

func TestModelToAPIFirewallRuleOmitsAnyServices(t *testing.T) {
	resource := &firewallRuleResource{}
	model := firewallRuleResourceModel{
		Name:       types.StringValue("allow_any_services"),
		PolicyType: types.StringValue("Network"),
		Action:     types.StringValue("Accept"),
		Services:   []types.String{types.StringValue("Any")},
	}

	rule := resource.modelToAPIFirewallRule(model)

	if rule.NetworkPolicy.Services != nil {
		t.Fatalf("expected services Any to be omitted from API payload, got %#v", rule.NetworkPolicy.Services)
	}
}

func TestUserPolicyExampleMappingToAPI(t *testing.T) {
	resource := &firewallRuleResource{}
	model := firewallRuleResourceModel{
		Name:                             types.StringValue("Marlon to Any"),
		PolicyType:                       types.StringValue("User"),
		Action:                           types.StringValue("Accept"),
		LogTraffic:                       types.StringValue("Enable"),
		Schedule:                         types.StringValue("All The Time"),
		SkipLocalDestined:                types.StringValue("Disable"),
		MatchIdentity:                    types.StringValue("Enable"),
		WebFilter:                        types.StringValue("None"),
		WebCategoryBaseQoSPolicy:         types.StringValue(" "),
		BlockQuickQuic:                   types.StringValue("Disable"),
		ScanVirus:                        types.StringValue("Disable"),
		ZeroDayProtection:                types.StringValue("Disable"),
		ProxyMode:                        types.StringValue("Disable"),
		DecryptHTTPS:                     types.StringValue("Disable"),
		ApplicationControl:               types.StringValue("None"),
		ApplicationBaseQoSPolicy:         types.StringValue(" "),
		IntrusionPrevention:              types.StringValue("WAN TO LAN"),
		TrafficShappingPolicy:            types.StringValue("None"),
		WebFilterInternetScheme:          types.StringValue("Disable"),
		ApplicationControlInternetScheme: types.StringValue("Disable"),
		DSCPMarking:                      types.StringValue("-1"),
		ScanSMTP:                         types.StringValue("Disable"),
		ScanSMTPS:                        types.StringValue("Disable"),
		ScanIMAP:                         types.StringValue("Disable"),
		ScanIMAPS:                        types.StringValue("Disable"),
		ScanPOP3:                         types.StringValue("Disable"),
		ScanPOP3S:                        types.StringValue("Disable"),
		ScanFTP:                          types.StringValue("Disable"),
		SourceSecurityHeartbeat:          types.StringValue("Disable"),
		MinimumSourceHBPermitted:         types.StringValue("No Restriction"),
		DestSecurityHeartbeat:            types.StringValue("Disable"),
		MinimumDestinationHBPermitted:    types.StringValue("No Restriction"),
		DataAccounting:                   types.StringValue("Disable"),
		ShowCaptivePortal:                types.StringValue("Disable"),
		IdentityMembers:                  []types.String{types.StringValue("marlon@leerkotte.net")},
	}

	rule := resource.modelToAPIFirewallRule(model)

	if rule.UserPolicy == nil {
		t.Fatalf("expected user policy to be populated")
	}

	if rule.NetworkPolicy != nil {
		t.Fatalf("expected network policy to be nil for user policy")
	}

	if got := rule.UserPolicy.WebFilterInternetScheme; got != "Disable" {
		t.Fatalf("expected web_filter_internet_scheme to map, got %q", got)
	}

	if got := rule.UserPolicy.ApplicationControlInternetScheme; got != "Disable" {
		t.Fatalf("expected application_control_internet_scheme to map, got %q", got)
	}

	if got := rule.UserPolicy.DSCPMarking; got != "-1" {
		t.Fatalf("expected dscp_marking to map, got %q", got)
	}

	if rule.UserPolicy.Identity == nil || len(rule.UserPolicy.Identity.Members) != 1 || rule.UserPolicy.Identity.Members[0] != "marlon@leerkotte.net" {
		t.Fatalf("unexpected identity mapping: %#v", rule.UserPolicy.Identity)
	}
}

func TestUserPolicyExampleMappingFromAPI(t *testing.T) {
	resource := &firewallRuleResource{}
	rule := firewallrule.FirewallRule{
		Name:       "Marlon to Any",
		PolicyType: "User",
		UserPolicy: &firewallrule.UserPolicy{
			Action:                           "Accept",
			LogTraffic:                       "Enable",
			Schedule:                         "All The Time",
			SkipLocalDestined:                "Disable",
			MatchIdentity:                    "Enable",
			WebFilter:                        "None",
			WebCategoryBaseQoSPolicy:         " ",
			BlockQuickQuic:                   "Disable",
			ScanVirus:                        "Disable",
			ZeroDayProtection:                "Disable",
			ProxyMode:                        "Disable",
			DecryptHTTPS:                     "Disable",
			ApplicationControl:               "None",
			ApplicationBaseQoSPolicy:         " ",
			IntrusionPrevention:              "WAN TO LAN",
			TrafficShappingPolicy:            "None",
			WebFilterInternetScheme:          "Disable",
			ApplicationControlInternetScheme: "Disable",
			DSCPMarking:                      "-1",
			ScanSMTP:                         "Disable",
			ScanSMTPS:                        "Disable",
			ScanIMAP:                         "Disable",
			ScanIMAPS:                        "Disable",
			ScanPOP3:                         "Disable",
			ScanPOP3S:                        "Disable",
			ScanFTP:                          "Disable",
			SourceSecurityHeartbeat:          "Disable",
			MinimumSourceHBPermitted:         "No Restriction",
			DestSecurityHeartbeat:            "Disable",
			MinimumDestinationHBPermitted:    "No Restriction",
			DataAccounting:                   "Disable",
			ShowCaptivePortal:                "Disable",
			Identity: &firewallrule.IdentityList{
				Members: []string{"marlon@leerkotte.net"},
			},
		},
	}

	model := resource.apiToModelFirewallRule(rule)

	if got := model.WebFilterInternetScheme.ValueString(); got != "Disable" {
		t.Fatalf("expected web_filter_internet_scheme to round-trip, got %q", got)
	}

	if got := model.ApplicationControlInternetScheme.ValueString(); got != "Disable" {
		t.Fatalf("expected application_control_internet_scheme to round-trip, got %q", got)
	}

	if got := model.DSCPMarking.ValueString(); got != "-1" {
		t.Fatalf("expected dscp_marking to round-trip, got %q", got)
	}

	if len(model.IdentityMembers) != 1 || model.IdentityMembers[0].ValueString() != "marlon@leerkotte.net" {
		t.Fatalf("unexpected identity round-trip: %#v", model.IdentityMembers)
	}
}

func TestValidateFirewallRulePlanRejectsIdentityOnNetworkPolicy(t *testing.T) {
	plan := firewallRuleResourceModel{
		PolicyType:      types.StringValue("Network"),
		IdentityMembers: []types.String{types.StringValue("marlon@leerkotte.net")},
	}

	diags := validateFirewallRulePlan(plan)
	if !diags.HasError() {
		t.Fatalf("expected validation error for identity_members on network policy")
	}
}

func TestValidateFirewallRulePlanAllowsIdentityOnUserPolicy(t *testing.T) {
	plan := firewallRuleResourceModel{
		PolicyType:      types.StringValue("User"),
		IdentityMembers: []types.String{types.StringValue("marlon@leerkotte.net")},
	}

	diags := validateFirewallRulePlan(plan)
	if diags.HasError() {
		t.Fatalf("expected no validation error for identity_members on user policy, got %#v", diags)
	}
}

func TestUserPolicyDefaultsDataAccountingToDisable(t *testing.T) {
	resource := &firewallRuleResource{}
	model := firewallRuleResourceModel{
		Name:       types.StringValue("allow_user_web"),
		PolicyType: types.StringValue("User"),
		Action:     types.StringValue("Accept"),
	}

	rule := resource.modelToAPIFirewallRule(model)

	if rule.UserPolicy == nil {
		t.Fatalf("expected user policy to be populated")
	}

	if got := rule.UserPolicy.DataAccounting; got != "Disable" {
		t.Fatalf("expected data_accounting default Disable, got %q", got)
	}
}

func TestUserPolicyDefaultsIdentityFlagsToDisable(t *testing.T) {
	resource := &firewallRuleResource{}
	model := firewallRuleResourceModel{
		Name:       types.StringValue("allow_user_web"),
		PolicyType: types.StringValue("User"),
		Action:     types.StringValue("Accept"),
	}

	rule := resource.modelToAPIFirewallRule(model)

	if rule.UserPolicy == nil {
		t.Fatalf("expected user policy to be populated")
	}

	if got := rule.UserPolicy.MatchIdentity; got != "Disable" {
		t.Fatalf("expected match_identity default Disable, got %q", got)
	}

	if got := rule.UserPolicy.ShowCaptivePortal; got != "Disable" {
		t.Fatalf("expected show_captive_portal default Disable, got %q", got)
	}
}
