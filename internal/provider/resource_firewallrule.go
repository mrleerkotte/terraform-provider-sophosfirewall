// Updated FirewallRule struct with all available fields
package provider

import (
	"context"
	"encoding/xml"
	"fmt"
	"strings"
	// "os"
	// "os/exec"
	// "bytes"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/firewallrule"
)

// FirewallRule represents a Sophos firewall rule with all available fields
type FirewallRule struct {
	XMLName       xml.Name       `xml:"FirewallRule"`
	Name          string         `xml:"Name"`
	Description   string         `xml:"Description"`
	IPFamily      string         `xml:"IPFamily"`
	Status        string         `xml:"Status"`
	Position      string         `xml:"Position"`
	PolicyType    string         `xml:"PolicyType"`
	After         *RulePosition  `xml:"After,omitempty"`
	Before        *RulePosition  `xml:"Before,omitempty"`
	NetworkPolicy *NetworkPolicy `xml:"NetworkPolicy,omitempty"`
	TransactionID string         `xml:"transactionid,attr,omitempty"`
}

// RulePosition specifies the position relative to another rule
type RulePosition struct {
	Name string `xml:"Name"`
}

// NetworkPolicy contains network policy settings with all available fields
type NetworkPolicy struct {
	Action                        string       `xml:"Action"`
	LogTraffic                    string       `xml:"LogTraffic"`
	SkipLocalDestined             string       `xml:"SkipLocalDestined"`
	Schedule                      string       `xml:"Schedule"`
	SourceZones                   *ZoneList    `xml:"SourceZones"`
	DestinationZones              *ZoneList    `xml:"DestinationZones"`
	SourceNetworks                *NetworkList `xml:"SourceNetworks,omitempty"`
	DestinationNetworks           *NetworkList `xml:"DestinationNetworks,omitempty"`
	Services                      *ServiceList `xml:"Services,omitempty"`
	DSCPMarking                   string       `xml:"DSCPMarking,omitempty"`
	WebFilter                     string       `xml:"WebFilter,omitempty"`
	WebCategoryBaseQoSPolicy      string       `xml:"WebCategoryBaseQoSPolicy,omitempty"`
	BlockQuickQuic                string       `xml:"BlockQuickQuic,omitempty"`
	ScanVirus                     string       `xml:"ScanVirus,omitempty"`
	ZeroDayProtection             string       `xml:"ZeroDayProtection,omitempty"`
	ProxyMode                     string       `xml:"ProxyMode,omitempty"`
	DecryptHTTPS                  string       `xml:"DecryptHTTPS,omitempty"`
	ApplicationControl            string       `xml:"ApplicationControl,omitempty"`
	ApplicationBaseQoSPolicy      string       `xml:"ApplicationBaseQoSPolicy,omitempty"`
	IntrusionPrevention           string       `xml:"IntrusionPrevention,omitempty"`
	TrafficShappingPolicy         string       `xml:"TrafficShappingPolicy,omitempty"`
	ScanSMTP                      string       `xml:"ScanSMTP,omitempty"`
	ScanSMTPS                     string       `xml:"ScanSMTPS,omitempty"`
	ScanIMAP                      string       `xml:"ScanIMAP,omitempty"`
	ScanIMAPS                     string       `xml:"ScanIMAPS,omitempty"`
	ScanPOP3                      string       `xml:"ScanPOP3,omitempty"`
	ScanPOP3S                     string       `xml:"ScanPOP3S,omitempty"`
	ScanFTP                       string       `xml:"ScanFTP,omitempty"`
	SourceSecurityHeartbeat       string       `xml:"SourceSecurityHeartbeat,omitempty"`
	MinimumSourceHBPermitted      string       `xml:"MinimumSourceHBPermitted,omitempty"`
	DestSecurityHeartbeat         string       `xml:"DestSecurityHeartbeat,omitempty"`
	MinimumDestinationHBPermitted string       `xml:"MinimumDestinationHBPermitted,omitempty"`
}

// ZoneList contains a list of zones
type ZoneList struct {
	Zones []string `xml:"Zone"`
}

// NetworkList contains a list of networks
type NetworkList struct {
	Networks []string `xml:"Network"`
}

// ServiceList contains a list of services
type ServiceList struct {
	Services []string `xml:"Service"`
}

// XML API firewall rule request structures
type firewallRuleRequestXML struct {
	XMLName xml.Name           `xml:"Request"`
	Login   LoginXML           `xml:"Login"`
	Set     firewallRuleSetXML `xml:"Set"`
}

type LoginXML struct {
	Username string `xml:"Username"`
	Password string `xml:"Password"`
}

type firewallRuleSetXML struct {
	Operation     string          `xml:"operation,attr"`
	FirewallRules []*FirewallRule `xml:"FirewallRule"`
}

// Ensure the implementation satisfies the expected interfaces
var _ resource.Resource = &firewallRuleResource{}
var _ resource.ResourceWithImportState = &firewallRuleResource{}

// firewallRuleResource is the resource implementation
type firewallRuleResource struct {
	client *firewallrule.Client
}

// Updated resource model with all available fields
type firewallRuleResourceModel struct {
	Name                             types.String   `tfsdk:"name"`
	Description                      types.String   `tfsdk:"description"`
	IPFamily                         types.String   `tfsdk:"ip_family"`
	Status                           types.String   `tfsdk:"status"`
	Position                         types.String   `tfsdk:"position"`
	PolicyType                       types.String   `tfsdk:"policy_type"`
	RuleGroupName                    types.String   `tfsdk:"rule_group_name"`
	AfterRule                        types.String   `tfsdk:"after_rule"`
	BeforeRule                       types.String   `tfsdk:"before_rule"`
	MatchIdentity                    types.String   `tfsdk:"match_identity"`
	ShowCaptivePortal                types.String   `tfsdk:"show_captive_portal"`
	IdentityMembers                  []types.String `tfsdk:"identity_members"`
	DataAccounting                   types.String   `tfsdk:"data_accounting"`
	Action                           types.String   `tfsdk:"action"`
	LogTraffic                       types.String   `tfsdk:"log_traffic"`
	SkipLocalDestined                types.String   `tfsdk:"skip_local_destined"`
	SourceZones                      []types.String `tfsdk:"source_zones"`
	DestinationZones                 []types.String `tfsdk:"destination_zones"`
	Schedule                         types.String   `tfsdk:"schedule"`
	SourceNetworks                   []types.String `tfsdk:"source_networks"`
	DestinationNetworks              []types.String `tfsdk:"destination_networks"`
	Services                         []types.String `tfsdk:"services"`
	DSCPMarking                      types.String   `tfsdk:"dscp_marking"`
	WebFilter                        types.String   `tfsdk:"web_filter"`
	WebCategoryBaseQoSPolicy         types.String   `tfsdk:"web_category_base_qos_policy"`
	BlockQuickQuic                   types.String   `tfsdk:"block_quick_quic"`
	ScanVirus                        types.String   `tfsdk:"scan_virus"`
	ZeroDayProtection                types.String   `tfsdk:"zero_day_protection"`
	ProxyMode                        types.String   `tfsdk:"proxy_mode"`
	DecryptHTTPS                     types.String   `tfsdk:"decrypt_https"`
	ApplicationControl               types.String   `tfsdk:"application_control"`
	ApplicationBaseQoSPolicy         types.String   `tfsdk:"application_base_qos_policy"`
	IntrusionPrevention              types.String   `tfsdk:"intrusion_prevention"`
	TrafficShappingPolicy            types.String   `tfsdk:"traffic_shapping_policy"`
	WebFilterInternetScheme          types.String   `tfsdk:"web_filter_internet_scheme"`
	ApplicationControlInternetScheme types.String   `tfsdk:"application_control_internet_scheme"`
	ScanSMTP                         types.String   `tfsdk:"scan_smtp"`
	ScanSMTPS                        types.String   `tfsdk:"scan_smtps"`
	ScanIMAP                         types.String   `tfsdk:"scan_imap"`
	ScanIMAPS                        types.String   `tfsdk:"scan_imaps"`
	ScanPOP3                         types.String   `tfsdk:"scan_pop3"`
	ScanPOP3S                        types.String   `tfsdk:"scan_pop3s"`
	ScanFTP                          types.String   `tfsdk:"scan_ftp"`
	SourceSecurityHeartbeat          types.String   `tfsdk:"source_security_heartbeat"`
	MinimumSourceHBPermitted         types.String   `tfsdk:"minimum_source_hb_permitted"`
	DestSecurityHeartbeat            types.String   `tfsdk:"dest_security_heartbeat"`
	MinimumDestinationHBPermitted    types.String   `tfsdk:"minimum_destination_hb_permitted"`
}

// NewFirewallRuleResource creates a new resource
func NewFirewallRuleResource() resource.Resource {
	return &firewallRuleResource{}
}

// Metadata returns the resource type name
func (r *firewallRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_firewallrule"
}

// Schema defines the schema for the resource with all available fields
func (r *firewallRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Sophos Firewall rule",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description: "Name of the firewall rule",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"description": schema.StringAttribute{
				Description: "Description of the rule",
				Optional:    true,
			},
			"ip_family": schema.StringAttribute{
				Description: "IP Family (IPv4 or IPv6)",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"status": schema.StringAttribute{
				Description: "Status (Enable or Disable)",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"position": schema.StringAttribute{
				Description: "Position (Top, Bottom, After, Before)",
				Optional:    true,
				Computed:    true,
			},
			"policy_type": schema.StringAttribute{
				Description: "Policy Type (Network or User)",
				Required:    true,
			},
			"rule_group_name": schema.StringAttribute{
				Description: "Optional Sophos firewall rule group this rule belongs to",
				Optional:    true,
			},
			"after_rule": schema.StringAttribute{
				Description: "Rule to position after (used when position is 'After')",
				Optional:    true,
				Computed:    true,
			},
			"before_rule": schema.StringAttribute{
				Description: "Rule to position before (used when position is 'Before')",
				Optional:    true,
				Computed:    true,
			},
			"match_identity": schema.StringAttribute{
				Description: "For user policies, whether to match known users (Enable or Disable)",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"show_captive_portal": schema.StringAttribute{
				Description: "For user policies, whether unknown users use captive portal authentication",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"identity_members": schema.ListAttribute{
				Description: "For user policies, users or groups matched by the rule",
				Optional:    true,
				ElementType: types.StringType,
			},
			"data_accounting": schema.StringAttribute{
				Description: "For user policies, data accounting behavior",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"action": schema.StringAttribute{
				Description: "Action (Accept, Reject, Drop)",
				Required:    true,
			},
			"log_traffic": schema.StringAttribute{
				Description: "Log traffic (Enable or Disable)",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"skip_local_destined": schema.StringAttribute{
				Description: "Skip local destined (Enable or Disable)",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"source_zones": schema.ListAttribute{
				Description: "List of source zones",
				Required:    true,
				ElementType: types.StringType,
			},
			"destination_zones": schema.ListAttribute{
				Description: "List of destination zones",
				Required:    true,
				ElementType: types.StringType,
			},
			"schedule": schema.StringAttribute{
				Description: "Schedule name",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"source_networks": schema.ListAttribute{
				Description: "List of source networks",
				Optional:    true,
				ElementType: types.StringType,
			},
			"destination_networks": schema.ListAttribute{
				Description: "List of destination networks",
				Optional:    true,
				ElementType: types.StringType,
			},
			"services": schema.ListAttribute{
				Description: "List of services matched by the firewall rule",
				Optional:    true,
				ElementType: types.StringType,
			},
			"dscp_marking": schema.StringAttribute{
				Description: "DSCP Marking value",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"web_filter": schema.StringAttribute{
				Description: "Web Filter policy",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"web_category_base_qos_policy": schema.StringAttribute{
				Description: "Web Category Base QoS Policy",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"block_quick_quic": schema.StringAttribute{
				Description: "Block Quick/QUIC protocol (Enable or Disable)",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"scan_virus": schema.StringAttribute{
				Description: "Scan for viruses (Enable or Disable)",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"zero_day_protection": schema.StringAttribute{
				Description: "Zero Day Protection (Enable or Disable)",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"proxy_mode": schema.StringAttribute{
				Description: "Proxy Mode (Enable or Disable)",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"decrypt_https": schema.StringAttribute{
				Description: "Decrypt HTTPS (Enable or Disable)",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"application_control": schema.StringAttribute{
				Description: "Application Control policy",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"application_base_qos_policy": schema.StringAttribute{
				Description: "Application Base QoS Policy",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"intrusion_prevention": schema.StringAttribute{
				Description: "Intrusion Prevention policy",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"traffic_shapping_policy": schema.StringAttribute{
				Description: "Traffic Shaping Policy",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"web_filter_internet_scheme": schema.StringAttribute{
				Description: "Web Filter Internet Scheme (Enable or Disable)",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"application_control_internet_scheme": schema.StringAttribute{
				Description: "Application Control Internet Scheme (Enable or Disable)",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"scan_smtp": schema.StringAttribute{
				Description: "Scan SMTP (Enable or Disable)",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"scan_smtps": schema.StringAttribute{
				Description: "Scan SMTPS (Enable or Disable)",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"scan_imap": schema.StringAttribute{
				Description: "Scan IMAP (Enable or Disable)",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"scan_imaps": schema.StringAttribute{
				Description: "Scan IMAPS (Enable or Disable)",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"scan_pop3": schema.StringAttribute{
				Description: "Scan POP3 (Enable or Disable)",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"scan_pop3s": schema.StringAttribute{
				Description: "Scan POP3S (Enable or Disable)",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"scan_ftp": schema.StringAttribute{
				Description: "Scan FTP (Enable or Disable)",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"source_security_heartbeat": schema.StringAttribute{
				Description: "Source Security Heartbeat (Enable or Disable)",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"minimum_source_hb_permitted": schema.StringAttribute{
				Description: "Minimum Source HB Permitted",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"dest_security_heartbeat": schema.StringAttribute{
				Description: "Destination Security Heartbeat (Enable or Disable)",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"minimum_destination_hb_permitted": schema.StringAttribute{
				Description: "Minimum Destination HB Permitted",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Configure adds the provider configured client to the resource
func (r *firewallRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*SophosClient)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *SophosClient, got: %T", req.ProviderData),
		)
		return
	}

	r.client = firewallrule.NewClient(client.BaseClient)
}

// Create creates a new firewall rule
func (r *firewallRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan firewallRuleResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(validateFirewallRulePlan(plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan = planWithDefaultCreateOrdering(plan)

	// Convert the model to API structure
	rule := r.modelToAPIFirewallRule(plan)

	// Create the firewall rule
	err := r.client.CreateFirewallRule(rule)
	if err != nil {
		resp.Diagnostics.AddError("Error creating firewall rule", err.Error())
		return
	}

	// Read the created rule to ensure state is up-to-date
	createdRule, err := r.client.ReadFirewallRule(plan.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading created firewall rule", err.Error())
		return
	}

	if createdRule == nil {
		resp.Diagnostics.AddError("Error after creation", "Firewall rule was not found after creation")
		return
	}

	liveRules, err := r.client.ReadFirewallRules()
	if err != nil {
		resp.Diagnostics.AddError("Error reading firewall rules after creation", err.Error())
		return
	}

	// Update the state with the actual created rule
	state := r.reconcileFirewallRulePostApply(r.apiToModelFirewallRule(*createdRule), plan, liveRules)
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

// Read refreshes the Terraform state with the latest data
func (r *firewallRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state firewallRuleResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the full firewall rule list so ordering checks can account for unmanaged rules.
	rules, err := r.client.ReadFirewallRules()
	if err != nil {
		resp.Diagnostics.AddError("Error reading firewall rules", err.Error())
		return
	}

	var rule *firewallrule.FirewallRule
	for i := range rules {
		if rules[i].Name == state.Name.ValueString() {
			rule = &rules[i]
			break
		}
	}

	if rule == nil {
		// Resource no longer exists
		resp.State.RemoveResource(ctx)
		return
	}

	// Update the Terraform state
	state = r.reconcileFirewallRuleRead(r.apiToModelFirewallRule(*rule), state, rules)

	// Save the updated state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

// Update updates the resource and sets the updated Terraform state
func (r *firewallRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan firewallRuleResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(validateFirewallRulePlan(plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	explicitOrdering := hasExplicitOrdering(plan)
	if !explicitOrdering {
		existingRule, err := r.client.ReadFirewallRule(plan.Name.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Error reading existing firewall rule", err.Error())
			return
		}
		if existingRule == nil {
			resp.Diagnostics.AddError("Error reading existing firewall rule", "Firewall rule was not found before update")
			return
		}
		plan = planWithExistingOrdering(plan, *existingRule)
	}

	liveRulesBefore, err := r.client.ReadFirewallRules()
	if err != nil {
		resp.Diagnostics.AddError("Error reading firewall rules before update", err.Error())
		return
	}

	// Convert the model to API structure
	rule := r.modelToAPIFirewallRule(plan)

	// Update the firewall rule
	err = r.client.UpdateFirewallRule(rule)
	if err != nil {
		resp.Diagnostics.AddError("Error updating firewall rule", err.Error())
		return
	}

	liveRulesAfter, err := r.client.ReadFirewallRules()
	if err != nil {
		resp.Diagnostics.AddError("Error reading firewall rules after update", err.Error())
		return
	}

	if explicitOrdering && shouldRetryFirewallRuleMove(plan, liveRulesBefore, liveRulesAfter) {
		stagedRule := cloneFirewallRule(rule)
		stagedRule.Position = stagingPositionForFirewallRuleMove(plan, liveRulesBefore)
		stagedRule.After = nil
		stagedRule.Before = nil

		err = r.client.UpdateFirewallRule(stagedRule)
		if err != nil {
			resp.Diagnostics.AddError("Error retrying firewall rule reorder", err.Error())
			return
		}

		err = r.client.UpdateFirewallRule(rule)
		if err != nil {
			resp.Diagnostics.AddError("Error applying firewall rule reorder after staging move", err.Error())
			return
		}

		liveRulesAfter, err = r.client.ReadFirewallRules()
		if err != nil {
			resp.Diagnostics.AddError("Error reading firewall rules after staged reorder", err.Error())
			return
		}
	}

	if explicitOrdering && !isFirewallRuleMoveSatisfied(plan, liveRulesAfter) {
		resp.Diagnostics.AddError(
			"Error updating firewall rule order",
			firewallRuleMoveFailureMessage(plan, liveRulesAfter),
		)
		return
	}

	// Read the updated rule to ensure state is up-to-date
	updatedRule, err := r.client.ReadFirewallRule(plan.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading updated firewall rule", err.Error())
		return
	}

	if updatedRule == nil {
		resp.Diagnostics.AddError("Error after update", "Firewall rule was not found after update")
		return
	}

	// Update the state with the actual updated rule
	state := r.reconcileFirewallRulePostApply(r.apiToModelFirewallRule(*updatedRule), plan, liveRulesAfter)
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

// Delete deletes the resource and removes the Terraform state
func (r *firewallRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state firewallRuleResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete the firewall rule
	err := r.client.DeleteFirewallRule(state.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error deleting firewall rule", err.Error())
		return
	}
}

// ImportState handles resource import
func (r *firewallRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import by name
	resource.ImportStatePassthroughID(ctx, path.Root("name"), req, resp)
}

// Helper method to convert from Terraform model to API structure
func (r *firewallRuleResource) modelToAPIFirewallRule(model firewallRuleResourceModel) *firewallrule.FirewallRule {
	rule := &firewallrule.FirewallRule{
		Name:          model.Name.ValueString(),
		Description:   model.Description.ValueString(),
		IPFamily:      model.IPFamily.ValueString(),
		Status:        model.Status.ValueString(),
		Position:      model.Position.ValueString(),
		PolicyType:    model.PolicyType.ValueString(),
		TransactionID: "",
	}

	// Set positioning (After or Before)
	if !model.AfterRule.IsNull() && model.AfterRule.ValueString() != "" {
		rule.After = &firewallrule.RulePosition{
			Name: model.AfterRule.ValueString(),
		}
	}

	if !model.BeforeRule.IsNull() && model.BeforeRule.ValueString() != "" {
		rule.Before = &firewallrule.RulePosition{
			Name: model.BeforeRule.ValueString(),
		}
	}

	if strings.EqualFold(model.PolicyType.ValueString(), "User") {
		rule.UserPolicy = &firewallrule.UserPolicy{
			Action:            model.Action.ValueString(),
			LogTraffic:        model.LogTraffic.ValueString(),
			SkipLocalDestined: model.SkipLocalDestined.ValueString(),
			Schedule:          model.Schedule.ValueString(),
			MatchIdentity:     stringValueOrDefault(model.MatchIdentity, "Disable"),
			ShowCaptivePortal: stringValueOrDefault(model.ShowCaptivePortal, "Disable"),
			DataAccounting:    stringValueOrDefault(model.DataAccounting, "Disable"),
		}
		populateCommonUserPolicyFields(rule.UserPolicy, model)

		if len(model.IdentityMembers) > 0 {
			rule.UserPolicy.Identity = &firewallrule.IdentityList{
				Members: make([]string, 0, len(model.IdentityMembers)),
			}
			for _, member := range model.IdentityMembers {
				rule.UserPolicy.Identity.Members = append(rule.UserPolicy.Identity.Members, member.ValueString())
			}
		}

		return rule
	}

	rule.NetworkPolicy = &firewallrule.NetworkPolicy{
		Action:            model.Action.ValueString(),
		LogTraffic:        model.LogTraffic.ValueString(),
		SkipLocalDestined: model.SkipLocalDestined.ValueString(),
		Schedule:          model.Schedule.ValueString(),
	}
	populateCommonNetworkPolicyFields(rule.NetworkPolicy, model)

	return rule
}

func hasExplicitOrdering(model firewallRuleResourceModel) bool {
	return (!model.Position.IsNull() && !model.Position.IsUnknown() && model.Position.ValueString() != "") ||
		(!model.AfterRule.IsNull() && !model.AfterRule.IsUnknown() && model.AfterRule.ValueString() != "") ||
		(!model.BeforeRule.IsNull() && !model.BeforeRule.IsUnknown() && model.BeforeRule.ValueString() != "")
}

func planWithDefaultCreateOrdering(plan firewallRuleResourceModel) firewallRuleResourceModel {
	if hasExplicitOrdering(plan) {
		return plan
	}

	plan.Position = types.StringValue("Bottom")
	plan.AfterRule = types.StringNull()
	plan.BeforeRule = types.StringNull()
	return plan
}

func planWithExistingOrdering(plan firewallRuleResourceModel, existing firewallrule.FirewallRule) firewallRuleResourceModel {
	plan.Position = stringValueOrNull(existing.Position)

	if existing.After != nil {
		plan.AfterRule = types.StringValue(existing.After.Name)
	} else {
		plan.AfterRule = types.StringNull()
	}

	if existing.Before != nil {
		plan.BeforeRule = types.StringValue(existing.Before.Name)
	} else {
		plan.BeforeRule = types.StringNull()
	}

	return plan
}

// Helper method to convert from API structure to Terraform model
func (r *firewallRuleResource) apiToModelFirewallRule(rule firewallrule.FirewallRule) firewallRuleResourceModel {
	model := firewallRuleResourceModel{
		Name:          types.StringValue(rule.Name),
		Description:   stringValueOrNull(rule.Description),
		IPFamily:      types.StringValue(rule.IPFamily),
		Status:        types.StringValue(rule.Status),
		Position:      types.StringValue(rule.Position),
		PolicyType:    types.StringValue(rule.PolicyType),
		RuleGroupName: types.StringNull(),
	}

	// Set position references
	if rule.After != nil {
		model.AfterRule = types.StringValue(rule.After.Name)
	} else {
		model.AfterRule = types.StringNull()
	}

	if rule.Before != nil {
		model.BeforeRule = types.StringValue(rule.Before.Name)
	} else {
		model.BeforeRule = types.StringNull()
	}

	if rule.UserPolicy != nil {
		model.Action = types.StringValue(rule.UserPolicy.Action)
		model.LogTraffic = types.StringValue(rule.UserPolicy.LogTraffic)
		model.SkipLocalDestined = types.StringValue(rule.UserPolicy.SkipLocalDestined)
		model.Schedule = types.StringValue(rule.UserPolicy.Schedule)
		model.MatchIdentity = types.StringValue(rule.UserPolicy.MatchIdentity)
		model.ShowCaptivePortal = types.StringValue(rule.UserPolicy.ShowCaptivePortal)
		model.DataAccounting = types.StringValue(rule.UserPolicy.DataAccounting)
		populateModelFromCommonUserPolicy(&model, rule.UserPolicy)
		if rule.UserPolicy.Identity != nil {
			model.IdentityMembers = make([]types.String, 0, len(rule.UserPolicy.Identity.Members))
			for _, member := range rule.UserPolicy.Identity.Members {
				model.IdentityMembers = append(model.IdentityMembers, types.StringValue(member))
			}
		}
	} else if rule.NetworkPolicy != nil {
		model.Action = types.StringValue(rule.NetworkPolicy.Action)
		model.LogTraffic = types.StringValue(rule.NetworkPolicy.LogTraffic)
		model.SkipLocalDestined = types.StringValue(rule.NetworkPolicy.SkipLocalDestined)
		model.Schedule = types.StringValue(rule.NetworkPolicy.Schedule)
		model.MatchIdentity = types.StringNull()
		model.ShowCaptivePortal = types.StringNull()
		model.DataAccounting = types.StringNull()
		model.IdentityMembers = nil
		populateModelFromCommonNetworkPolicy(&model, rule.NetworkPolicy)
	} else {
		model.Action = types.StringNull()
		model.LogTraffic = types.StringNull()
		model.SkipLocalDestined = types.StringNull()
		model.Schedule = types.StringNull()
		model.MatchIdentity = types.StringNull()
		model.ShowCaptivePortal = types.StringNull()
		model.DataAccounting = types.StringNull()
		model.IdentityMembers = nil
		model.DSCPMarking = types.StringNull()
		model.WebFilter = types.StringNull()
		model.WebCategoryBaseQoSPolicy = types.StringNull()
		model.BlockQuickQuic = types.StringNull()
		model.ScanVirus = types.StringNull()
		model.ZeroDayProtection = types.StringNull()
		model.ProxyMode = types.StringNull()
		model.DecryptHTTPS = types.StringNull()
		model.ApplicationControl = types.StringNull()
		model.ApplicationBaseQoSPolicy = types.StringNull()
		model.IntrusionPrevention = types.StringNull()
		model.TrafficShappingPolicy = types.StringNull()
		model.WebFilterInternetScheme = types.StringNull()
		model.ApplicationControlInternetScheme = types.StringNull()
		model.ScanSMTP = types.StringNull()
		model.ScanSMTPS = types.StringNull()
		model.ScanIMAP = types.StringNull()
		model.ScanIMAPS = types.StringNull()
		model.ScanPOP3 = types.StringNull()
		model.ScanPOP3S = types.StringNull()
		model.ScanFTP = types.StringNull()
		model.SourceSecurityHeartbeat = types.StringNull()
		model.MinimumSourceHBPermitted = types.StringNull()
		model.DestSecurityHeartbeat = types.StringNull()
		model.MinimumDestinationHBPermitted = types.StringNull()
		model.SourceZones = nil
		model.DestinationZones = nil
		model.SourceNetworks = nil
		model.DestinationNetworks = nil
		model.Services = nil
	}

	return model
}

func populateCommonNetworkPolicyFields(policy *firewallrule.NetworkPolicy, model firewallRuleResourceModel) {
	if !model.DSCPMarking.IsNull() {
		policy.DSCPMarking = model.DSCPMarking.ValueString()
	}
	if !model.WebFilter.IsNull() {
		policy.WebFilter = model.WebFilter.ValueString()
	}
	if !model.WebCategoryBaseQoSPolicy.IsNull() {
		policy.WebCategoryBaseQoSPolicy = model.WebCategoryBaseQoSPolicy.ValueString()
	}
	if !model.BlockQuickQuic.IsNull() {
		policy.BlockQuickQuic = model.BlockQuickQuic.ValueString()
	}
	if !model.ScanVirus.IsNull() {
		policy.ScanVirus = model.ScanVirus.ValueString()
	}
	if !model.ZeroDayProtection.IsNull() {
		policy.ZeroDayProtection = model.ZeroDayProtection.ValueString()
	}
	if !model.ProxyMode.IsNull() {
		policy.ProxyMode = model.ProxyMode.ValueString()
	}
	if !model.DecryptHTTPS.IsNull() {
		policy.DecryptHTTPS = model.DecryptHTTPS.ValueString()
	}
	if !model.ApplicationControl.IsNull() {
		policy.ApplicationControl = model.ApplicationControl.ValueString()
	}
	if !model.ApplicationBaseQoSPolicy.IsNull() {
		policy.ApplicationBaseQoSPolicy = model.ApplicationBaseQoSPolicy.ValueString()
	}
	if !model.IntrusionPrevention.IsNull() {
		policy.IntrusionPrevention = model.IntrusionPrevention.ValueString()
	}
	if !model.TrafficShappingPolicy.IsNull() {
		policy.TrafficShappingPolicy = model.TrafficShappingPolicy.ValueString()
	}
	if !model.WebFilterInternetScheme.IsNull() {
		policy.WebFilterInternetScheme = model.WebFilterInternetScheme.ValueString()
	}
	if !model.ApplicationControlInternetScheme.IsNull() {
		policy.ApplicationControlInternetScheme = model.ApplicationControlInternetScheme.ValueString()
	}
	if !model.ScanSMTP.IsNull() {
		policy.ScanSMTP = model.ScanSMTP.ValueString()
	}
	if !model.ScanSMTPS.IsNull() {
		policy.ScanSMTPS = model.ScanSMTPS.ValueString()
	}
	if !model.ScanIMAP.IsNull() {
		policy.ScanIMAP = model.ScanIMAP.ValueString()
	}
	if !model.ScanIMAPS.IsNull() {
		policy.ScanIMAPS = model.ScanIMAPS.ValueString()
	}
	if !model.ScanPOP3.IsNull() {
		policy.ScanPOP3 = model.ScanPOP3.ValueString()
	}
	if !model.ScanPOP3S.IsNull() {
		policy.ScanPOP3S = model.ScanPOP3S.ValueString()
	}
	if !model.ScanFTP.IsNull() {
		policy.ScanFTP = model.ScanFTP.ValueString()
	}
	if !model.SourceSecurityHeartbeat.IsNull() {
		policy.SourceSecurityHeartbeat = model.SourceSecurityHeartbeat.ValueString()
	}
	if !model.MinimumSourceHBPermitted.IsNull() {
		policy.MinimumSourceHBPermitted = model.MinimumSourceHBPermitted.ValueString()
	}
	if !model.DestSecurityHeartbeat.IsNull() {
		policy.DestSecurityHeartbeat = model.DestSecurityHeartbeat.ValueString()
	}
	if !model.MinimumDestinationHBPermitted.IsNull() {
		policy.MinimumDestinationHBPermitted = model.MinimumDestinationHBPermitted.ValueString()
	}

	if len(model.SourceZones) > 0 && !isAnyOnlyStringList(model.SourceZones) {
		policy.SourceZones = &firewallrule.ZoneList{Zones: make([]string, 0, len(model.SourceZones))}
		for _, zone := range model.SourceZones {
			policy.SourceZones.Zones = append(policy.SourceZones.Zones, zone.ValueString())
		}
	}
	if len(model.DestinationZones) > 0 && !isAnyOnlyStringList(model.DestinationZones) {
		policy.DestinationZones = &firewallrule.ZoneList{Zones: make([]string, 0, len(model.DestinationZones))}
		for _, zone := range model.DestinationZones {
			policy.DestinationZones.Zones = append(policy.DestinationZones.Zones, zone.ValueString())
		}
	}
	if len(model.SourceNetworks) > 0 {
		policy.SourceNetworks = &firewallrule.NetworkList{Networks: make([]string, 0, len(model.SourceNetworks))}
		for _, network := range model.SourceNetworks {
			policy.SourceNetworks.Networks = append(policy.SourceNetworks.Networks, network.ValueString())
		}
	}
	if len(model.DestinationNetworks) > 0 {
		policy.DestinationNetworks = &firewallrule.NetworkList{Networks: make([]string, 0, len(model.DestinationNetworks))}
		for _, network := range model.DestinationNetworks {
			policy.DestinationNetworks.Networks = append(policy.DestinationNetworks.Networks, network.ValueString())
		}
	}
	if len(model.Services) > 0 && !isAnyOnlyStringList(model.Services) {
		policy.Services = &firewallrule.ServiceList{Services: make([]string, 0, len(model.Services))}
		for _, service := range model.Services {
			policy.Services.Services = append(policy.Services.Services, service.ValueString())
		}
	}
}

func populateCommonUserPolicyFields(policy *firewallrule.UserPolicy, model firewallRuleResourceModel) {
	if !model.DSCPMarking.IsNull() {
		policy.DSCPMarking = model.DSCPMarking.ValueString()
	}
	if !model.WebFilter.IsNull() {
		policy.WebFilter = model.WebFilter.ValueString()
	}
	if !model.WebCategoryBaseQoSPolicy.IsNull() {
		policy.WebCategoryBaseQoSPolicy = model.WebCategoryBaseQoSPolicy.ValueString()
	}
	if !model.BlockQuickQuic.IsNull() {
		policy.BlockQuickQuic = model.BlockQuickQuic.ValueString()
	}
	if !model.ScanVirus.IsNull() {
		policy.ScanVirus = model.ScanVirus.ValueString()
	}
	if !model.ZeroDayProtection.IsNull() {
		policy.ZeroDayProtection = model.ZeroDayProtection.ValueString()
	}
	if !model.ProxyMode.IsNull() {
		policy.ProxyMode = model.ProxyMode.ValueString()
	}
	if !model.DecryptHTTPS.IsNull() {
		policy.DecryptHTTPS = model.DecryptHTTPS.ValueString()
	}
	if !model.ApplicationControl.IsNull() {
		policy.ApplicationControl = model.ApplicationControl.ValueString()
	}
	if !model.ApplicationBaseQoSPolicy.IsNull() {
		policy.ApplicationBaseQoSPolicy = model.ApplicationBaseQoSPolicy.ValueString()
	}
	if !model.IntrusionPrevention.IsNull() {
		policy.IntrusionPrevention = model.IntrusionPrevention.ValueString()
	}
	if !model.TrafficShappingPolicy.IsNull() {
		policy.TrafficShappingPolicy = model.TrafficShappingPolicy.ValueString()
	}
	if !model.WebFilterInternetScheme.IsNull() {
		policy.WebFilterInternetScheme = model.WebFilterInternetScheme.ValueString()
	}
	if !model.ApplicationControlInternetScheme.IsNull() {
		policy.ApplicationControlInternetScheme = model.ApplicationControlInternetScheme.ValueString()
	}
	if !model.ScanSMTP.IsNull() {
		policy.ScanSMTP = model.ScanSMTP.ValueString()
	}
	if !model.ScanSMTPS.IsNull() {
		policy.ScanSMTPS = model.ScanSMTPS.ValueString()
	}
	if !model.ScanIMAP.IsNull() {
		policy.ScanIMAP = model.ScanIMAP.ValueString()
	}
	if !model.ScanIMAPS.IsNull() {
		policy.ScanIMAPS = model.ScanIMAPS.ValueString()
	}
	if !model.ScanPOP3.IsNull() {
		policy.ScanPOP3 = model.ScanPOP3.ValueString()
	}
	if !model.ScanPOP3S.IsNull() {
		policy.ScanPOP3S = model.ScanPOP3S.ValueString()
	}
	if !model.ScanFTP.IsNull() {
		policy.ScanFTP = model.ScanFTP.ValueString()
	}
	if !model.SourceSecurityHeartbeat.IsNull() {
		policy.SourceSecurityHeartbeat = model.SourceSecurityHeartbeat.ValueString()
	}
	if !model.MinimumSourceHBPermitted.IsNull() {
		policy.MinimumSourceHBPermitted = model.MinimumSourceHBPermitted.ValueString()
	}
	if !model.DestSecurityHeartbeat.IsNull() {
		policy.DestSecurityHeartbeat = model.DestSecurityHeartbeat.ValueString()
	}
	if !model.MinimumDestinationHBPermitted.IsNull() {
		policy.MinimumDestinationHBPermitted = model.MinimumDestinationHBPermitted.ValueString()
	}

	if len(model.SourceZones) > 0 && !isAnyOnlyStringList(model.SourceZones) {
		policy.SourceZones = &firewallrule.ZoneList{Zones: make([]string, 0, len(model.SourceZones))}
		for _, zone := range model.SourceZones {
			policy.SourceZones.Zones = append(policy.SourceZones.Zones, zone.ValueString())
		}
	}
	if len(model.DestinationZones) > 0 && !isAnyOnlyStringList(model.DestinationZones) {
		policy.DestinationZones = &firewallrule.ZoneList{Zones: make([]string, 0, len(model.DestinationZones))}
		for _, zone := range model.DestinationZones {
			policy.DestinationZones.Zones = append(policy.DestinationZones.Zones, zone.ValueString())
		}
	}
	if len(model.SourceNetworks) > 0 {
		policy.SourceNetworks = &firewallrule.NetworkList{Networks: make([]string, 0, len(model.SourceNetworks))}
		for _, network := range model.SourceNetworks {
			policy.SourceNetworks.Networks = append(policy.SourceNetworks.Networks, network.ValueString())
		}
	}
	if len(model.DestinationNetworks) > 0 {
		policy.DestinationNetworks = &firewallrule.NetworkList{Networks: make([]string, 0, len(model.DestinationNetworks))}
		for _, network := range model.DestinationNetworks {
			policy.DestinationNetworks.Networks = append(policy.DestinationNetworks.Networks, network.ValueString())
		}
	}
	if len(model.Services) > 0 && !isAnyOnlyStringList(model.Services) {
		policy.Services = &firewallrule.ServiceList{Services: make([]string, 0, len(model.Services))}
		for _, service := range model.Services {
			policy.Services.Services = append(policy.Services.Services, service.ValueString())
		}
	}
}

func populateModelFromCommonNetworkPolicy(model *firewallRuleResourceModel, policy *firewallrule.NetworkPolicy) {
	model.DSCPMarking = types.StringValue(policy.DSCPMarking)
	model.WebFilter = types.StringValue(policy.WebFilter)
	model.WebCategoryBaseQoSPolicy = types.StringValue(policy.WebCategoryBaseQoSPolicy)
	model.BlockQuickQuic = types.StringValue(policy.BlockQuickQuic)
	model.ScanVirus = types.StringValue(policy.ScanVirus)
	model.ZeroDayProtection = types.StringValue(policy.ZeroDayProtection)
	model.ProxyMode = types.StringValue(policy.ProxyMode)
	model.DecryptHTTPS = types.StringValue(policy.DecryptHTTPS)
	model.ApplicationControl = types.StringValue(policy.ApplicationControl)
	model.ApplicationBaseQoSPolicy = types.StringValue(policy.ApplicationBaseQoSPolicy)
	model.IntrusionPrevention = types.StringValue(policy.IntrusionPrevention)
	model.TrafficShappingPolicy = types.StringValue(policy.TrafficShappingPolicy)
	model.WebFilterInternetScheme = types.StringValue(policy.WebFilterInternetScheme)
	model.ApplicationControlInternetScheme = types.StringValue(policy.ApplicationControlInternetScheme)
	model.ScanSMTP = types.StringValue(policy.ScanSMTP)
	model.ScanSMTPS = types.StringValue(policy.ScanSMTPS)
	model.ScanIMAP = types.StringValue(policy.ScanIMAP)
	model.ScanIMAPS = types.StringValue(policy.ScanIMAPS)
	model.ScanPOP3 = types.StringValue(policy.ScanPOP3)
	model.ScanPOP3S = types.StringValue(policy.ScanPOP3S)
	model.ScanFTP = types.StringValue(policy.ScanFTP)
	model.SourceSecurityHeartbeat = types.StringValue(policy.SourceSecurityHeartbeat)
	model.MinimumSourceHBPermitted = types.StringValue(policy.MinimumSourceHBPermitted)
	model.DestSecurityHeartbeat = types.StringValue(policy.DestSecurityHeartbeat)
	model.MinimumDestinationHBPermitted = types.StringValue(policy.MinimumDestinationHBPermitted)
	model.SourceZones = zoneModelValues(policy.SourceZones)
	model.DestinationZones = zoneModelValues(policy.DestinationZones)
	model.SourceNetworks = networkModelValues(policy.SourceNetworks)
	model.DestinationNetworks = networkModelValues(policy.DestinationNetworks)
	model.Services = serviceModelValues(policy.Services)
}

func populateModelFromCommonUserPolicy(model *firewallRuleResourceModel, policy *firewallrule.UserPolicy) {
	model.DSCPMarking = types.StringValue(policy.DSCPMarking)
	model.WebFilter = types.StringValue(policy.WebFilter)
	model.WebCategoryBaseQoSPolicy = types.StringValue(policy.WebCategoryBaseQoSPolicy)
	model.BlockQuickQuic = types.StringValue(policy.BlockQuickQuic)
	model.ScanVirus = types.StringValue(policy.ScanVirus)
	model.ZeroDayProtection = types.StringValue(policy.ZeroDayProtection)
	model.ProxyMode = types.StringValue(policy.ProxyMode)
	model.DecryptHTTPS = types.StringValue(policy.DecryptHTTPS)
	model.ApplicationControl = types.StringValue(policy.ApplicationControl)
	model.ApplicationBaseQoSPolicy = types.StringValue(policy.ApplicationBaseQoSPolicy)
	model.IntrusionPrevention = types.StringValue(policy.IntrusionPrevention)
	model.TrafficShappingPolicy = types.StringValue(policy.TrafficShappingPolicy)
	model.WebFilterInternetScheme = types.StringValue(policy.WebFilterInternetScheme)
	model.ApplicationControlInternetScheme = types.StringValue(policy.ApplicationControlInternetScheme)
	model.ScanSMTP = types.StringValue(policy.ScanSMTP)
	model.ScanSMTPS = types.StringValue(policy.ScanSMTPS)
	model.ScanIMAP = types.StringValue(policy.ScanIMAP)
	model.ScanIMAPS = types.StringValue(policy.ScanIMAPS)
	model.ScanPOP3 = types.StringValue(policy.ScanPOP3)
	model.ScanPOP3S = types.StringValue(policy.ScanPOP3S)
	model.ScanFTP = types.StringValue(policy.ScanFTP)
	model.SourceSecurityHeartbeat = types.StringValue(policy.SourceSecurityHeartbeat)
	model.MinimumSourceHBPermitted = types.StringValue(policy.MinimumSourceHBPermitted)
	model.DestSecurityHeartbeat = types.StringValue(policy.DestSecurityHeartbeat)
	model.MinimumDestinationHBPermitted = types.StringValue(policy.MinimumDestinationHBPermitted)
	model.SourceZones = zoneModelValues(policy.SourceZones)
	model.DestinationZones = zoneModelValues(policy.DestinationZones)
	model.SourceNetworks = networkModelValues(policy.SourceNetworks)
	model.DestinationNetworks = networkModelValues(policy.DestinationNetworks)
	model.Services = serviceModelValues(policy.Services)
}

func zoneModelValues(zones *firewallrule.ZoneList) []types.String {
	if zones == nil {
		return nil
	}
	values := make([]types.String, 0, len(zones.Zones))
	for _, zone := range zones.Zones {
		values = append(values, types.StringValue(zone))
	}
	return values
}

func networkModelValues(networks *firewallrule.NetworkList) []types.String {
	if networks == nil {
		return nil
	}
	values := make([]types.String, 0, len(networks.Networks))
	for _, network := range networks.Networks {
		values = append(values, types.StringValue(network))
	}
	return values
}

func serviceModelValues(services *firewallrule.ServiceList) []types.String {
	if services == nil {
		return nil
	}
	values := make([]types.String, 0, len(services.Services))
	for _, service := range services.Services {
		values = append(values, types.StringValue(service))
	}
	return values
}

func stringValueOrDefault(value types.String, defaultValue string) string {
	if value.IsNull() || value.IsUnknown() || value.ValueString() == "" {
		return defaultValue
	}

	return value.ValueString()
}

func stringValueOrNull(value string) types.String {
	if value == "" {
		return types.StringNull()
	}

	return types.StringValue(value)
}

func validateFirewallRulePlan(plan firewallRuleResourceModel) diag.Diagnostics {
	var diags diag.Diagnostics

	isUserPolicy := strings.EqualFold(plan.PolicyType.ValueString(), "User")

	hasUserOnlyFields := len(plan.IdentityMembers) > 0 ||
		(!plan.MatchIdentity.IsNull() && !plan.MatchIdentity.IsUnknown() && plan.MatchIdentity.ValueString() != "") ||
		(!plan.ShowCaptivePortal.IsNull() && !plan.ShowCaptivePortal.IsUnknown() && plan.ShowCaptivePortal.ValueString() != "") ||
		(!plan.DataAccounting.IsNull() && !plan.DataAccounting.IsUnknown() && plan.DataAccounting.ValueString() != "")

	if hasUserOnlyFields && !isUserPolicy {
		diags.AddError(
			"Invalid Firewall Rule Configuration",
			"`policy_type` must be `User` when using `identity_members`, `match_identity`, `show_captive_portal`, or `data_accounting`.",
		)
	}

	return diags
}

func (r *firewallRuleResource) reconcileFirewallRulePostApply(actual firewallRuleResourceModel, expected firewallRuleResourceModel, liveRules []firewallrule.FirewallRule) firewallRuleResourceModel {
	if !expected.Position.IsNull() && expected.Position.ValueString() == "Bottom" {
		actual.Position = types.StringValue("Bottom")
		actual.AfterRule = types.StringNull()
		actual.BeforeRule = types.StringNull()
	}

	if !expected.Position.IsNull() && expected.Position.ValueString() == "Before" {
		if shouldPreserveBeforeAnchor(actual.Name.ValueString(), expected.BeforeRule, liveRules) {
			actual.Position = types.StringValue("Before")
			actual.AfterRule = types.StringNull()
			if !expected.BeforeRule.IsNull() {
				actual.BeforeRule = expected.BeforeRule
			}
		}
	}

	if !expected.Position.IsNull() && expected.Position.ValueString() == "After" {
		if shouldPreserveAfterAnchor(actual.Name.ValueString(), expected.AfterRule, liveRules) {
			actual.Position = types.StringValue("After")
			actual.BeforeRule = types.StringNull()
			if !expected.AfterRule.IsNull() {
				actual.AfterRule = expected.AfterRule
			}
		}
	}

	if isAnyOnlyStringList(expected.SourceZones) && len(actual.SourceZones) == 0 {
		actual.SourceZones = []types.String{types.StringValue("Any")}
	}

	if isAnyOnlyStringList(expected.DestinationZones) && len(actual.DestinationZones) == 0 {
		actual.DestinationZones = []types.String{types.StringValue("Any")}
	}

	if isAnyOnlyStringList(expected.Services) && len(actual.Services) == 0 {
		actual.Services = []types.String{types.StringValue("Any")}
	}

	if sameStringSet(actual.SourceZones, expected.SourceZones) {
		actual.SourceZones = expected.SourceZones
	}

	if sameStringSet(actual.DestinationZones, expected.DestinationZones) {
		actual.DestinationZones = expected.DestinationZones
	}

	if sameStringSet(actual.SourceNetworks, expected.SourceNetworks) {
		actual.SourceNetworks = expected.SourceNetworks
	}

	if sameStringSet(actual.DestinationNetworks, expected.DestinationNetworks) {
		actual.DestinationNetworks = expected.DestinationNetworks
	}

	if sameStringSet(actual.Services, expected.Services) {
		actual.Services = expected.Services
	}

	return actual
}

func (r *firewallRuleResource) reconcileFirewallRuleRead(actual firewallRuleResourceModel, expected firewallRuleResourceModel, liveRules []firewallrule.FirewallRule) firewallRuleResourceModel {
	if !expected.Position.IsNull() && expected.Position.ValueString() == "Bottom" {
		actual.Position = types.StringValue("Bottom")
		actual.AfterRule = types.StringNull()
		actual.BeforeRule = types.StringNull()
	}

	if isAnyOnlyStringList(expected.SourceZones) && len(actual.SourceZones) == 0 {
		actual.SourceZones = []types.String{types.StringValue("Any")}
	}

	if isAnyOnlyStringList(expected.DestinationZones) && len(actual.DestinationZones) == 0 {
		actual.DestinationZones = []types.String{types.StringValue("Any")}
	}

	if isAnyOnlyStringList(expected.Services) && len(actual.Services) == 0 {
		actual.Services = []types.String{types.StringValue("Any")}
	}

	if sameStringSet(actual.SourceZones, expected.SourceZones) {
		actual.SourceZones = expected.SourceZones
	}

	if sameStringSet(actual.DestinationZones, expected.DestinationZones) {
		actual.DestinationZones = expected.DestinationZones
	}

	if sameStringSet(actual.SourceNetworks, expected.SourceNetworks) {
		actual.SourceNetworks = expected.SourceNetworks
	}

	if sameStringSet(actual.DestinationNetworks, expected.DestinationNetworks) {
		actual.DestinationNetworks = expected.DestinationNetworks
	}

	if sameStringSet(actual.Services, expected.Services) {
		actual.Services = expected.Services
	}

	return actual
}

func cloneFirewallRule(rule *firewallrule.FirewallRule) *firewallrule.FirewallRule {
	cloned := *rule
	return &cloned
}

func shouldRetryFirewallRuleMove(plan firewallRuleResourceModel, before, after []firewallrule.FirewallRule) bool {
	if plan.Position.IsNull() || plan.Position.IsUnknown() {
		return false
	}

	position := plan.Position.ValueString()
	if position != "After" && position != "Before" {
		return false
	}

	return !isFirewallRuleMoveSatisfied(plan, after) && isFirewallRuleMoveDirectionChanged(plan, before)
}

func isFirewallRuleMoveDirectionChanged(plan firewallRuleResourceModel, liveRules []firewallrule.FirewallRule) bool {
	if plan.Position.IsNull() || plan.Position.IsUnknown() {
		return false
	}

	switch plan.Position.ValueString() {
	case "After":
		if plan.AfterRule.IsNull() || plan.AfterRule.IsUnknown() || plan.AfterRule.ValueString() == "" {
			return false
		}
		ruleIndex, anchorIndex, ok := ruleAndAnchorIndexes(plan.Name.ValueString(), plan.AfterRule.ValueString(), liveRules)
		return ok && anchorIndex > ruleIndex
	case "Before":
		if plan.BeforeRule.IsNull() || plan.BeforeRule.IsUnknown() || plan.BeforeRule.ValueString() == "" {
			return false
		}
		ruleIndex, anchorIndex, ok := ruleAndAnchorIndexes(plan.Name.ValueString(), plan.BeforeRule.ValueString(), liveRules)
		return ok && anchorIndex < ruleIndex
	default:
		return false
	}
}

func stagingPositionForFirewallRuleMove(plan firewallRuleResourceModel, liveRules []firewallrule.FirewallRule) string {
	if plan.Position.IsNull() || plan.Position.IsUnknown() {
		return "Bottom"
	}

	switch plan.Position.ValueString() {
	case "After":
		if plan.AfterRule.IsNull() || plan.AfterRule.IsUnknown() || plan.AfterRule.ValueString() == "" {
			return "Bottom"
		}
		ruleIndex, anchorIndex, ok := ruleAndAnchorIndexes(plan.Name.ValueString(), plan.AfterRule.ValueString(), liveRules)
		if ok && anchorIndex > ruleIndex {
			return "Bottom"
		}
	case "Before":
		if plan.BeforeRule.IsNull() || plan.BeforeRule.IsUnknown() || plan.BeforeRule.ValueString() == "" {
			return "Top"
		}
		ruleIndex, anchorIndex, ok := ruleAndAnchorIndexes(plan.Name.ValueString(), plan.BeforeRule.ValueString(), liveRules)
		if ok && anchorIndex < ruleIndex {
			return "Top"
		}
	}

	return "Top"
}

func isFirewallRuleMoveSatisfied(plan firewallRuleResourceModel, liveRules []firewallrule.FirewallRule) bool {
	if plan.Position.IsNull() || plan.Position.IsUnknown() {
		return true
	}

	switch plan.Position.ValueString() {
	case "Top":
		ruleIndex, ok := ruleIndexByName(plan.Name.ValueString(), liveRules)
		return ok && ruleIndex == 0
	case "Bottom":
		ruleIndex, ok := ruleIndexByName(plan.Name.ValueString(), liveRules)
		return ok && ruleIndex == len(liveRules)-1
	case "After":
		return hasImmediateAfterAnchor(plan.Name.ValueString(), plan.AfterRule, liveRules)
	case "Before":
		return hasImmediateBeforeAnchor(plan.Name.ValueString(), plan.BeforeRule, liveRules)
	default:
		return true
	}
}

func firewallRuleMoveFailureMessage(plan firewallRuleResourceModel, liveRules []firewallrule.FirewallRule) string {
	actualAnchor := ""

	switch plan.Position.ValueString() {
	case "After":
		actualAnchor = immediatePredecessor(plan.Name.ValueString(), liveRules)
		if actualAnchor == "" {
			actualAnchor = "<none>"
		}
		return fmt.Sprintf(
			"Sophos did not apply the requested order change for rule %q. Expected it immediately after %q, but its actual predecessor is %q.",
			plan.Name.ValueString(),
			plan.AfterRule.ValueString(),
			actualAnchor,
		)
	case "Before":
		actualAnchor = immediateSuccessor(plan.Name.ValueString(), liveRules)
		if actualAnchor == "" {
			actualAnchor = "<none>"
		}
		return fmt.Sprintf(
			"Sophos did not apply the requested order change for rule %q. Expected it immediately before %q, but its actual successor is %q.",
			plan.Name.ValueString(),
			plan.BeforeRule.ValueString(),
			actualAnchor,
		)
	case "Top":
		return fmt.Sprintf("Sophos did not move rule %q to the top of the firewall rule list.", plan.Name.ValueString())
	case "Bottom":
		return fmt.Sprintf("Sophos did not move rule %q to the bottom of the firewall rule list.", plan.Name.ValueString())
	default:
		return fmt.Sprintf("Sophos did not apply the requested order change for rule %q.", plan.Name.ValueString())
	}
}

func shouldPreserveAfterAnchor(ruleName string, expectedAfter types.String, liveRules []firewallrule.FirewallRule) bool {
	if expectedAfter.IsNull() || expectedAfter.IsUnknown() || expectedAfter.ValueString() == "" {
		return false
	}

	ruleIndex, anchorIndex, ok := ruleAndAnchorIndexes(ruleName, expectedAfter.ValueString(), liveRules)
	return ok && anchorIndex < ruleIndex
}

func shouldPreserveBeforeAnchor(ruleName string, expectedBefore types.String, liveRules []firewallrule.FirewallRule) bool {
	if expectedBefore.IsNull() || expectedBefore.IsUnknown() || expectedBefore.ValueString() == "" {
		return false
	}

	ruleIndex, anchorIndex, ok := ruleAndAnchorIndexes(ruleName, expectedBefore.ValueString(), liveRules)
	return ok && ruleIndex < anchorIndex
}

func hasImmediateAfterAnchor(ruleName string, expectedAfter types.String, liveRules []firewallrule.FirewallRule) bool {
	if expectedAfter.IsNull() || expectedAfter.IsUnknown() || expectedAfter.ValueString() == "" {
		return false
	}

	ruleIndex, anchorIndex, ok := ruleAndAnchorIndexes(ruleName, expectedAfter.ValueString(), liveRules)
	return ok && ruleIndex == anchorIndex+1
}

func hasImmediateBeforeAnchor(ruleName string, expectedBefore types.String, liveRules []firewallrule.FirewallRule) bool {
	if expectedBefore.IsNull() || expectedBefore.IsUnknown() || expectedBefore.ValueString() == "" {
		return false
	}

	ruleIndex, anchorIndex, ok := ruleAndAnchorIndexes(ruleName, expectedBefore.ValueString(), liveRules)
	return ok && anchorIndex == ruleIndex+1
}

func ruleAndAnchorIndexes(ruleName, anchorName string, liveRules []firewallrule.FirewallRule) (int, int, bool) {
	ruleIndex := -1
	anchorIndex := -1

	for i := range liveRules {
		switch liveRules[i].Name {
		case ruleName:
			ruleIndex = i
		case anchorName:
			anchorIndex = i
		}
	}

	return ruleIndex, anchorIndex, ruleIndex >= 0 && anchorIndex >= 0
}

func ruleIndexByName(ruleName string, liveRules []firewallrule.FirewallRule) (int, bool) {
	for i := range liveRules {
		if liveRules[i].Name == ruleName {
			return i, true
		}
	}

	return -1, false
}

func immediatePredecessor(ruleName string, liveRules []firewallrule.FirewallRule) string {
	index, ok := ruleIndexByName(ruleName, liveRules)
	if !ok || index == 0 {
		return ""
	}

	return liveRules[index-1].Name
}

func immediateSuccessor(ruleName string, liveRules []firewallrule.FirewallRule) string {
	index, ok := ruleIndexByName(ruleName, liveRules)
	if !ok || index == len(liveRules)-1 {
		return ""
	}

	return liveRules[index+1].Name
}

func stringSliceValues(values []types.String) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value.IsNull() || value.IsUnknown() {
			continue
		}
		result = append(result, value.ValueString())
	}
	return result
}

func stringModelValues(values []string) []types.String {
	result := make([]types.String, 0, len(values))
	for _, value := range values {
		result = append(result, types.StringValue(value))
	}
	return result
}

func isAnyOnlyStringList(values []types.String) bool {
	if len(values) != 1 || values[0].IsNull() || values[0].IsUnknown() {
		return false
	}

	return strings.EqualFold(values[0].ValueString(), "Any")
}

func sameStringSet(a, b []types.String) bool {
	if len(a) != len(b) {
		return false
	}

	counts := make(map[string]int, len(a))
	for _, value := range a {
		if value.IsNull() || value.IsUnknown() {
			return false
		}
		counts[value.ValueString()]++
	}

	for _, value := range b {
		if value.IsNull() || value.IsUnknown() {
			return false
		}

		key := value.ValueString()
		if counts[key] == 0 {
			return false
		}
		counts[key]--
	}

	for _, remaining := range counts {
		if remaining != 0 {
			return false
		}
	}

	return true
}
