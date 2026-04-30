package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/firewallrulegroup"
)

var _ resource.Resource = &firewallRuleGroupResource{}
var _ resource.ResourceWithImportState = &firewallRuleGroupResource{}

type firewallRuleGroupResource struct {
	client *firewallrulegroup.Client
}

type firewallRuleGroupResourceModel struct {
	Name               types.String   `tfsdk:"name"`
	Description        types.String   `tfsdk:"description"`
	PolicyType         types.String   `tfsdk:"policy_type"`
	SourceZones        []types.String `tfsdk:"source_zones"`
	DestinationZones   []types.String `tfsdk:"destination_zones"`
	SecurityPolicyList types.List     `tfsdk:"security_policy_list"`
}

func NewFirewallRuleGroupResource() resource.Resource {
	return &firewallRuleGroupResource{}
}

func (r *firewallRuleGroupResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_firewallrule_group"
}

func (r *firewallRuleGroupResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Sophos Firewall rule group.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description: "Name of the firewall rule group",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"description": schema.StringAttribute{
				Description: "Description of the firewall rule group",
				Optional:    true,
			},
			"policy_type": schema.StringAttribute{
				Description: "Policy type of rules allowed in the group (Network, User, WAF, Any)",
				Required:    true,
			},
			"source_zones": schema.ListAttribute{
				Description: "Source zones associated with the group",
				Optional:    true,
				ElementType: types.StringType,
			},
			"destination_zones": schema.ListAttribute{
				Description: "Destination zones associated with the group",
				Optional:    true,
				ElementType: types.StringType,
			},
			"security_policy_list": schema.ListAttribute{
				Description: "Ordered firewall rules contained in this group",
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
			},
		},
	}
}

func (r *firewallRuleGroupResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

	r.client = firewallrulegroup.NewClient(client.BaseClient)
}

func (r *firewallRuleGroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan firewallRuleGroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if diags := validateFirewallRuleGroupPlan(plan); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	group := modelToAPIFirewallRuleGroup(plan)
	if err := r.client.CreateFirewallRuleGroup(group); err != nil {
		resp.Diagnostics.AddError("Error creating firewall rule group", err.Error())
		return
	}

	created, err := r.client.ReadFirewallRuleGroup(plan.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading created firewall rule group", err.Error())
		return
	}
	if created == nil {
		resp.Diagnostics.AddError("Error after creation", "Firewall rule group was not found after creation")
		return
	}

	state := apiToModelFirewallRuleGroup(*created)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *firewallRuleGroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state firewallRuleGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	group, err := r.client.ReadFirewallRuleGroup(state.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading firewall rule group", err.Error())
		return
	}
	if group == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	state = apiToModelFirewallRuleGroup(*group)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *firewallRuleGroupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan firewallRuleGroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if diags := validateFirewallRuleGroupPlan(plan); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	group := modelToAPIFirewallRuleGroup(plan)
	if err := r.client.UpdateFirewallRuleGroup(group); err != nil {
		resp.Diagnostics.AddError("Error updating firewall rule group", err.Error())
		return
	}

	updated, err := r.client.ReadFirewallRuleGroup(plan.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading updated firewall rule group", err.Error())
		return
	}
	if updated == nil {
		resp.Diagnostics.AddError("Error after update", "Firewall rule group was not found after update")
		return
	}

	state := apiToModelFirewallRuleGroup(*updated)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *firewallRuleGroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state firewallRuleGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.DeleteFirewallRuleGroup(state.Name.ValueString()); err != nil {
		resp.Diagnostics.AddError("Error deleting firewall rule group", err.Error())
	}
}

func (r *firewallRuleGroupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("name"), req, resp)
}

func modelToAPIFirewallRuleGroup(model firewallRuleGroupResourceModel) *firewallrulegroup.FirewallRuleGroup {
	group := &firewallrulegroup.FirewallRuleGroup{
		Name:          model.Name.ValueString(),
		Description:   model.Description.ValueString(),
		PolicyType:    model.PolicyType.ValueString(),
		TransactionID: "",
	}

	if len(model.SourceZones) > 0 && !isAnyOnlyStringList(model.SourceZones) {
		group.SourceZones = &firewallrulegroup.ZoneList{Zones: stringSliceValues(model.SourceZones)}
	}
	if len(model.DestinationZones) > 0 && !isAnyOnlyStringList(model.DestinationZones) {
		group.DestinationZones = &firewallrulegroup.ZoneList{Zones: stringSliceValues(model.DestinationZones)}
	}
	if !model.SecurityPolicyList.IsNull() && !model.SecurityPolicyList.IsUnknown() {
		policies := listStringValues(model.SecurityPolicyList)
		if len(policies) > 0 {
			group.SecurityPolicyList = &firewallrulegroup.SecurityPolicyList{SecurityPolicies: policies}
		}
	}

	return group
}

func apiToModelFirewallRuleGroup(group firewallrulegroup.FirewallRuleGroup) firewallRuleGroupResourceModel {
	model := firewallRuleGroupResourceModel{
		Name:        types.StringValue(group.Name),
		Description: stringValueOrNull(group.Description),
		PolicyType:  types.StringValue(group.PolicyType),
	}

	model.SourceZones = nil
	if group.SourceZones != nil && len(group.SourceZones.Zones) > 0 {
		model.SourceZones = stringModelValues(group.SourceZones.Zones)
	}

	model.DestinationZones = nil
	if group.DestinationZones != nil && len(group.DestinationZones.Zones) > 0 {
		model.DestinationZones = stringModelValues(group.DestinationZones.Zones)
	}

	model.SecurityPolicyList = types.ListValueMust(types.StringType, []attr.Value{})
	if group.SecurityPolicyList != nil {
		model.SecurityPolicyList = stringListValue(group.SecurityPolicyList.SecurityPolicies)
	}

	return model
}

func listStringValues(list types.List) []string {
	if list.IsNull() || list.IsUnknown() {
		return nil
	}

	values := make([]types.String, 0, len(list.Elements()))
	diags := list.ElementsAs(context.Background(), &values, false)
	if diags.HasError() {
		return nil
	}

	return stringSliceValues(values)
}

func stringListValue(values []string) types.List {
	attrValues := make([]attr.Value, 0, len(values))
	for _, value := range values {
		attrValues = append(attrValues, types.StringValue(value))
	}

	return types.ListValueMust(types.StringType, attrValues)
}

func validateFirewallRuleGroupPlan(plan firewallRuleGroupResourceModel) diag.Diagnostics {
	var diags diag.Diagnostics

	if plan.SecurityPolicyList.IsNull() || plan.SecurityPolicyList.IsUnknown() || len(listStringValues(plan.SecurityPolicyList)) == 0 {
		diags.AddError(
			"Invalid Firewall Rule Group Configuration",
			"`security_policy_list` must contain at least one firewall rule. Sophos does not support creating empty firewall rule groups.",
		)
	}

	return diags
}
