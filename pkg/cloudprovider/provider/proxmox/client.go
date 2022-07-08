/*
Copyright 2022 The Machine Controller Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package proxmox

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/kubermatic/machine-controller/pkg/apis/cluster/common"
	cloudprovidererrors "github.com/kubermatic/machine-controller/pkg/cloudprovider/errors"
	proxmoxtypes "github.com/kubermatic/machine-controller/pkg/cloudprovider/provider/proxmox/types"
	corev1 "k8s.io/api/core/v1"

	"github.com/Telmate/proxmox-api-go/proxmox"
)

const (
	taskTimeout       = 300
	exitStatusSuccess = "OK"
)

type ClientSet struct {
	*proxmox.Client
}

func GetClientSet(config *Config) (*ClientSet, error) {
	if config == nil {
		return nil, errors.New("no configuration passed")
	}

	if config.UserID == "" {
		return nil, errors.New("no user_id specified")
	}

	if config.Token == "" {
		return nil, errors.New("no token specificed")
	}

	if config.Endpoint == "" {
		return nil, errors.New("no endpoint specified")
	}

	client, err := proxmox.NewClient(config.Endpoint, nil, &tls.Config{InsecureSkipVerify: config.TLSInsecure}, config.ProxyURL, taskTimeout)
	if err != nil {
		return nil, fmt.Errorf("could not initiate proxmox client: %w", err)
	}

	client.SetAPIToken(config.UserID, config.Token)

	return &ClientSet{client}, nil
}

func (c ClientSet) getVMRefByName(name string) (*proxmox.VmRef, error) {
	vmr, err := c.GetVmRefByName(name)
	if err != nil {
		if err.Error() == fmt.Sprintf("vm '%s' not found", name) {
			return nil, cloudprovidererrors.ErrInstanceNotFound
		}
		return nil, err
	}
	return vmr, nil
}

func (c ClientSet) checkNodeExists(name string) (bool, error) {
	nodeList, err := c.GetNodeList()
	if err != nil {
		return false, fmt.Errorf("cannot fetch nodes from cluster: %v", err)
	}

	var nodeExists bool
	var nl proxmoxtypes.NodeList

	nodeListJson, err := json.Marshal(nodeList)
	if err != nil {
		return false, fmt.Errorf("marshalling nodeList to JSON: %w", err)
	}
	err = json.Unmarshal(nodeListJson, &nl)
	if err != nil {
		return false, fmt.Errorf("unmarshalling JSON to NodeList: %w", err)
	}

	for _, n := range nl.Data {
		if n.Node == name {
			nodeExists = true
			break
		}
	}

	return nodeExists, nil
}

func (c ClientSet) checkTemplateExists(name string) (bool, error) {
	vmr, err := c.GetVmRefByName(name)
	if err != nil {
		return false, fmt.Errorf("could not retrieve VM template %q", name)
	}

	vmInfo, err := c.GetVmInfo(vmr)
	if err != nil {
		return false, fmt.Errorf("failed to retrieve info for VM template %q", name)
	}

	return vmInfo["template"] == 1, nil
}

func (c ClientSet) getIPsByVMRef(vmr *proxmox.VmRef) (map[string]corev1.NodeAddressType, error) {
	addresses := map[string]corev1.NodeAddressType{}
	netInterfaces, err := c.GetVmAgentNetworkInterfaces(vmr)
	if err != nil {
		return nil, cloudprovidererrors.TerminalError{
			Reason:  common.CreateMachineError,
			Message: fmt.Sprintf("failed to get network interfaces: %v", err),
		}
	}
	for _, netIf := range netInterfaces {
		for _, ipAddr := range netIf.IPAddresses {
			if len(ipAddr) > 0 {
				ip := ipAddr.String()
				addresses[ip] = corev1.NodeInternalIP
			}
		}
	}
	return addresses, nil
}
