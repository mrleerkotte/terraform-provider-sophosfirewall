package firewallrulegroup

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/common"
)

type Client struct {
	*common.BaseClient
}

type setFirewallRuleGroupBlockXML struct {
	Operation          string               `xml:"operation,attr"`
	FirewallRuleGroups []*FirewallRuleGroup `xml:"FirewallRuleGroup"`
}

type firewallRuleGroupNameXML struct {
	Name string `xml:"Name"`
}

type getFirewallRuleGroupBlockXML struct {
	FirewallRuleGroup firewallRuleGroupNameXML `xml:"FirewallRuleGroup"`
}

type getFirewallRuleGroupsBlockXML struct {
	FirewallRuleGroup struct{} `xml:"FirewallRuleGroup"`
}

type removeFirewallRuleGroupBlockXML struct {
	FirewallRuleGroup firewallRuleGroupNameXML `xml:"FirewallRuleGroup"`
}

func NewClient(baseClient *common.BaseClient) *Client {
	return &Client{BaseClient: baseClient}
}

func (c *Client) CreateFirewallRuleGroup(group *FirewallRuleGroup) error {
	return c.setFirewallRuleGroup(group, "add")
}

func (c *Client) UpdateFirewallRuleGroup(group *FirewallRuleGroup) error {
	return c.setFirewallRuleGroup(group, "update")
}

func (c *Client) DeleteFirewallRuleGroup(name string) error {
	request := common.RequestXML{
		XMLName: xml.Name{Local: "Request"},
		Login: common.LoginXML{
			Username: c.BaseClient.Username,
			Password: c.BaseClient.Password,
		},
		Remove: removeFirewallRuleGroupBlockXML{
			FirewallRuleGroup: firewallRuleGroupNameXML{Name: name},
		},
	}

	responseData, err := c.doRequest(request)
	if err != nil {
		return err
	}

	var response struct {
		Login struct {
			Status string `xml:"status"`
		} `xml:"Login"`
		Status struct {
			Code    string `xml:"code,attr"`
			Message string `xml:",chardata"`
		} `xml:"Status"`
		Error struct {
			Code    string `xml:"code,attr"`
			Message string `xml:",chardata"`
		} `xml:"Error"`
	}

	if err := xml.Unmarshal(responseData, &response); err != nil {
		return fmt.Errorf("error unmarshaling firewall rule group delete response: %v", err)
	}

	if response.Login.Status != "Authentication Successful" {
		return fmt.Errorf("authentication failed: %s", response.Login.Status)
	}

	if response.Error.Code != "" {
		return fmt.Errorf("Sophos API error: %s - %s", response.Error.Code, response.Error.Message)
	}

	return nil
}

func (c *Client) ReadFirewallRuleGroup(name string) (*FirewallRuleGroup, error) {
	request := common.RequestXML{
		XMLName: xml.Name{Local: "Request"},
		Login: common.LoginXML{
			Username: c.BaseClient.Username,
			Password: c.BaseClient.Password,
		},
		Get: getFirewallRuleGroupBlockXML{
			FirewallRuleGroup: firewallRuleGroupNameXML{Name: name},
		},
	}

	groups, err := c.readFirewallRuleGroups(request)
	if err != nil {
		return nil, err
	}

	for i := range groups {
		if groups[i].Name == name {
			group := groups[i]
			normalizeFirewallRuleGroup(&group)
			return &group, nil
		}
	}

	return nil, nil
}

func (c *Client) ReadFirewallRuleGroups() ([]FirewallRuleGroup, error) {
	request := common.RequestXML{
		XMLName: xml.Name{Local: "Request"},
		Login: common.LoginXML{
			Username: c.BaseClient.Username,
			Password: c.BaseClient.Password,
		},
		Get: getFirewallRuleGroupsBlockXML{},
	}

	return c.readFirewallRuleGroups(request)
}

func (c *Client) setFirewallRuleGroup(group *FirewallRuleGroup, operation string) error {
	group.TransactionID = ""
	request := common.RequestXML{
		XMLName: xml.Name{Local: "Request"},
		Login: common.LoginXML{
			Username: c.BaseClient.Username,
			Password: c.BaseClient.Password,
		},
		Set: setFirewallRuleGroupBlockXML{
			Operation:          operation,
			FirewallRuleGroups: []*FirewallRuleGroup{group},
		},
	}

	responseData, err := c.doRequest(request)
	if err != nil {
		return err
	}

	var response struct {
		Login struct {
			Status string `xml:"status"`
		} `xml:"Login"`
		FirewallRuleGroup struct {
			Status struct {
				Code    string `xml:"code,attr"`
				Message string `xml:",chardata"`
			} `xml:"Status"`
		} `xml:"FirewallRuleGroup"`
		Error struct {
			Code    string `xml:"code,attr"`
			Message string `xml:",chardata"`
		} `xml:"Error"`
	}

	if err := xml.Unmarshal(responseData, &response); err != nil {
		return fmt.Errorf("error unmarshaling firewall rule group response: %v", err)
	}

	if response.Login.Status != "Authentication Successful" {
		return fmt.Errorf("authentication failed: %s", response.Login.Status)
	}

	if response.Error.Code != "" {
		return fmt.Errorf("Sophos API error: %s - %s", response.Error.Code, response.Error.Message)
	}

	if response.FirewallRuleGroup.Status.Code != "" && response.FirewallRuleGroup.Status.Code != "200" {
		return fmt.Errorf("operation failed: %s", response.FirewallRuleGroup.Status.Message)
	}

	return nil
}

func (c *Client) readFirewallRuleGroups(request common.RequestXML) ([]FirewallRuleGroup, error) {
	responseData, err := c.doRequest(request)
	if err != nil {
		return nil, err
	}

	var response struct {
		Login struct {
			Status string `xml:"status"`
		} `xml:"Login"`
		FirewallRuleGroups []FirewallRuleGroup `xml:"FirewallRuleGroup"`
		Error              struct {
			Code    string `xml:"code,attr"`
			Message string `xml:",chardata"`
		} `xml:"Error"`
	}

	if err := xml.Unmarshal(responseData, &response); err != nil {
		return nil, fmt.Errorf("error unmarshaling firewall rule group read response: %v", err)
	}

	if response.Login.Status != "Authentication Successful" {
		return nil, fmt.Errorf("authentication failed: %s", response.Login.Status)
	}

	if response.Error.Code != "" {
		return nil, fmt.Errorf("Sophos API error: %s - %s", response.Error.Code, response.Error.Message)
	}

	for i := range response.FirewallRuleGroups {
		normalizeFirewallRuleGroup(&response.FirewallRuleGroups[i])
	}

	return response.FirewallRuleGroups, nil
}

func (c *Client) doRequest(request common.RequestXML) ([]byte, error) {
	xmlData, err := xml.MarshalIndent(request, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("error marshaling firewall rule group request: %v", err)
	}

	tempFileName, err := common.CreateTempFile(xmlData)
	if err != nil {
		return nil, fmt.Errorf("error creating temporary file: %v", err)
	}
	defer os.Remove(tempFileName)

	responseTempFile, err := os.CreateTemp("", "sophos_response")
	if err != nil {
		return nil, fmt.Errorf("error creating response temporary file: %v", err)
	}
	responseTempFileName := responseTempFile.Name()
	responseTempFile.Close()
	defer os.Remove(responseTempFileName)

	url := fmt.Sprintf("%s/webconsole/APIController", c.BaseClient.Endpoint)
	cmd := exec.Command(
		"curl",
		"-k",
		url,
		"-F", fmt.Sprintf("reqxml=<%s", tempFileName),
		"-o", responseTempFileName,
	)

	var errb bytes.Buffer
	cmd.Stderr = &errb

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("error executing curl: %v, stderr: %s", err, errb.String())
	}

	responseData, err := os.ReadFile(responseTempFileName)
	if err != nil {
		return nil, fmt.Errorf("error reading response file: %v", err)
	}

	if len(responseData) == 0 {
		return nil, fmt.Errorf("received empty response from Sophos API")
	}

	return responseData, nil
}

func normalizeFirewallRuleGroup(group *FirewallRuleGroup) {
	if group.SecurityPolicyList == nil {
		group.SecurityPolicyList = &SecurityPolicyList{SecurityPolicies: []string{}}
	}
	if group.SourceZones == nil {
		group.SourceZones = &ZoneList{Zones: []string{}}
	}
	if group.DestinationZones == nil {
		group.DestinationZones = &ZoneList{Zones: []string{}}
	}
}
