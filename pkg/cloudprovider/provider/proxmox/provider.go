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
	"context"
	"errors"
	"fmt"

	"github.com/Telmate/proxmox-api-go/proxmox"
	"github.com/kubermatic/machine-controller/pkg/apis/cluster/common"
	clusterv1alpha1 "github.com/kubermatic/machine-controller/pkg/apis/cluster/v1alpha1"
	cloudprovidererrors "github.com/kubermatic/machine-controller/pkg/cloudprovider/errors"
	"github.com/kubermatic/machine-controller/pkg/cloudprovider/instance"
	proxmoxtypes "github.com/kubermatic/machine-controller/pkg/cloudprovider/provider/proxmox/types"
	cloudprovidertypes "github.com/kubermatic/machine-controller/pkg/cloudprovider/types"
	"github.com/kubermatic/machine-controller/pkg/providerconfig"
	providerconfigtypes "github.com/kubermatic/machine-controller/pkg/providerconfig/types"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	enabled = 1
)

type Config struct {
	Endpoint    string
	UserID      string
	Token       string
	TLSInsecure bool
	ProxyURL    string

	NodeName string

	CPUSockets   int64
	CPUCores     *int64
	MemoryMB     int64
	DiskSizeGB   int64
	BridgeDevice *string
}

type provider struct {
	configVarResolver *providerconfig.ConfigVarResolver
}

type Server struct {
	configQemu *proxmox.ConfigQemu
	vmRef      *proxmox.VmRef
	status     instance.Status
	addresses  map[string]corev1.NodeAddressType
}

// Ensures that Server implements Instance interface.
var _ instance.Instance = &Server{}

// Ensures that provider implements Provider interface.
var _ cloudprovidertypes.Provider = &provider{}

// Name returns the instance name.
func (server *Server) Name() string {
	return server.configQemu.Name
}

// ID returns the instance identifier.
func (server *Server) ID() string {
	return fmt.Sprintf("node-%s-vm-%d", server.vmRef.Node(), server.vmRef.VmId())
}

// Addresses returns a list of addresses associated with the instance.
func (server *Server) Addresses() map[string]corev1.NodeAddressType {
	return server.addresses
}

// Status returns the instance status.
func (server *Server) Status() instance.Status {
	return server.status
}

func New(configVarResolver *providerconfig.ConfigVarResolver) cloudprovidertypes.Provider {
	provider := &provider{configVarResolver: configVarResolver}
	return provider
}

func (p *provider) getConfig(provSpec clusterv1alpha1.ProviderSpec) (*Config, *providerconfigtypes.Config, *proxmoxtypes.RawConfig, error) {
	if provSpec.Value == nil {
		return nil, nil, nil, fmt.Errorf("machine.spec.providerconfig.value is nil")
	}

	pconfig, err := providerconfigtypes.GetConfig(provSpec)
	if err != nil {
		return nil, nil, nil, err
	}

	if pconfig.OperatingSystemSpec.Raw == nil {
		return nil, nil, nil, errors.New("operatingSystemSpec in the MachineDeployment cannot be empty")
	}

	rawConfig, err := proxmoxtypes.GetConfig(*pconfig)
	if err != nil {
		return nil, nil, nil, err
	}

	config := Config{}

	config.Endpoint, err = p.configVarResolver.GetConfigVarStringValueOrEnv(rawConfig.Endpoint, "PM_API_URL")
	if err != nil {
		return nil, nil, nil, err
	}

	config.UserID, err = p.configVarResolver.GetConfigVarStringValueOrEnv(rawConfig.UserID, "PM_API_USER_ID")
	if err != nil {
		return nil, nil, nil, err
	}

	config.Token, err = p.configVarResolver.GetConfigVarStringValueOrEnv(rawConfig.UserID, "PM_API_TOKEN")
	if err != nil {
		return nil, nil, nil, err
	}

	config.TLSInsecure, err = p.configVarResolver.GetConfigVarBoolValueOrEnv(rawConfig.AllowInsecure, "PM_TLS_INSECURE")
	if err != nil {
		return nil, nil, nil, err
	}

	config.ProxyURL, err = p.configVarResolver.GetConfigVarStringValueOrEnv(rawConfig.ProxyURL, "PM_PROXY_URL")
	if err != nil {
		return nil, nil, nil, err
	}

	config.NodeName, err = p.configVarResolver.GetConfigVarStringValueOrEnv(rawConfig.NodeName, "PM_NODE_NAME")

	config.CPUCores = rawConfig.CPUCores
	config.CPUSockets = rawConfig.CPUSockets
	config.MemoryMB = rawConfig.MemoryMB
	config.DiskSizeGB = rawConfig.DiskSizeGB
	config.BridgeDevice = rawConfig.BridgeDevice

	return &config, pconfig, rawConfig, nil
}

// AddDefaults will read the MachineSpec and apply defaults for provider specific fields
func (*provider) AddDefaults(spec clusterv1alpha1.MachineSpec) (clusterv1alpha1.MachineSpec, error) {
	return spec, nil
}

// Validate validates the given machine's specification.
//
// In case of any error a "terminal" error should be set,
// See v1alpha1.MachineStatus for more info
func (p *provider) Validate(ctx context.Context, spec clusterv1alpha1.MachineSpec) error {
	config, _, _, err := p.getConfig(spec.ProviderSpec)
	if err != nil {
		return cloudprovidererrors.TerminalError{
			Reason:  common.InvalidConfigurationMachineError,
			Message: fmt.Sprintf("failed to parse machineSpec: %v", err),
		}
	}

	c, err := GetClientSet(config)
	if err != nil {
		return cloudprovidererrors.TerminalError{
			Reason:  common.InvalidConfigurationMachineError,
			Message: fmt.Sprintf("failed to construct client: %v", err),
		}
	}

	// Verify client can connect to API
	_, err = c.GetVersion()
	if err != nil {
		return cloudprovidererrors.TerminalError{
			Reason:  common.InvalidConfigurationMachineError,
			Message: fmt.Sprintf("cannot connect to proxmox API: %v", err),
		}
	}

	nodes, err := c.GetNodeList()
	if err != nil {
		return cloudprovidererrors.TerminalError{
			Reason:  common.InvalidConfigurationMachineError,
			Message: fmt.Sprintf("cannot fetch nodes from cluster: %v", err),
		}
	}
	var nodeExists bool
	for _, n := range nodes["data"].([]map[string]interface{}) {
		if n["node"] == config.NodeName {
			nodeExists = nodeExists || true
		}
	}
	if !nodeExists {
		return cloudprovidererrors.TerminalError{
			Reason:  common.InvalidConfigurationMachineError,
			Message: fmt.Sprintf("node %q does not exist", config.NodeName),
		}
	}

	return nil
}

// Get gets a node that is associated with the given machine.
//
// Note that this method can return what we call a "terminal" error,
// which indicates that a manual interaction is required to recover from this state.
// See v1alpha1.MachineStatus for more info and TerminalError type
//
// In case the instance cannot be found, github.com/kubermatic/machine-controller/pkg/cloudprovider/errors/ErrInstanceNotFound will be returned
func (provider *provider) Get(ctx context.Context, machine *clusterv1alpha1.Machine, data *cloudprovidertypes.ProviderData) (instance.Instance, error) {
	panic("not implemented") // TODO: Implement
}

// GetCloudConfig will return the cloud provider specific cloud-config, which gets consumed by the kubelet
func (provider *provider) GetCloudConfig(spec clusterv1alpha1.MachineSpec) (config string, name string, err error) {
	panic("not implemented") // TODO: Implement
}

// Create creates a cloud instance according to the given machine
func (p *provider) Create(ctx context.Context, machine *clusterv1alpha1.Machine, data *cloudprovidertypes.ProviderData, userdata string) (instance.Instance, error) {
	config, _, _, err := p.getConfig(machine.Spec.ProviderSpec)
	if err != nil {
		return nil, cloudprovidererrors.TerminalError{
			Reason:  common.InvalidConfigurationMachineError,
			Message: fmt.Sprintf("failed to parse machineSpec: %v", err),
		}
	}

	c, err := GetClientSet(config)
	if err != nil {
		return nil, cloudprovidererrors.TerminalError{
			Reason:  common.InvalidConfigurationMachineError,
			Message: fmt.Sprintf("failed to construct client: %v", err),
		}
	}

	vmID, err := c.GetNextID(0)
	if err != nil {
		return nil, cloudprovidererrors.TerminalError{
			Reason:  common.InvalidConfigurationMachineError,
			Message: fmt.Sprintf("failed to get next available VM ID: %v", err),
		}
	}

	configQemu := &proxmox.ConfigQemu{
		Name:  machine.Name,
		Agent: enabled,
		VmID:  vmID,

		// TODO: config.Image
		QemuIso: "local:iso/ubuntu-22.04-live-server-amd64.iso",
		// For now only Linux 2.6 is supported
		QemuOs: "l26",

		// TODO: config.Memory
		Memory: 2048,

		QemuCpu: "host",
		// TODO: confog.CPUSockets
		QemuSockets: 1,
		// TODO: config.CPUCores
		QemuCores: 1,

		QemuDisks: proxmox.QemuDevices{
			0: {
				"type":    "scsi",
				"storage": "local-lvm",
				// TODO: Config.DiskSizeGB
				"size":   "30G",
				"backup": false,
			},
		},

		// TODO: Figure out correct network settings
		QemuNetworks: proxmox.QemuDevices{
			0: {
				"model":  "e1000",
				"bridge": "vmbr0",
			},
		},

		QemuKVM:     true,
		QemuVlanTag: -1,

		// TODO: userdata -> cloud-init
	}

	vmr := proxmox.NewVmRef(vmID)
	vmr.SetNode(config.NodeName)

	// CreateVm polls the creation task until it has completed.
	// It also cleans up created disks on failed VM creation.
	err = configQemu.CreateVm(vmr, c.Client)
	if err != nil {
		return nil, cloudprovidererrors.TerminalError{
			Reason:  common.CreateMachineError,
			Message: fmt.Sprintf("failed to create VM: %v", err),
		}
	}

	// TODO: extract to func getIPs()
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

	return &Server{
		vmRef:      vmr,
		configQemu: configQemu,
		addresses:  addresses,
		status:     instance.StatusRunning,
	}, nil
}

// Cleanup will delete the instance associated with the machine and all associated resources.
// If all resources have been cleaned up, true will be returned.
// In case the cleanup involves asynchronous deletion of resources & those resources are not gone yet,
// false should be returned. This is to indicate that the cleanup is not done, but needs to be called again at a later point
func (p *provider) Cleanup(ctx context.Context, machine *clusterv1alpha1.Machine, data *cloudprovidertypes.ProviderData) (bool, error) {
	config, _, _, err := p.getConfig(machine.Spec.ProviderSpec)
	if err != nil {
		return false, cloudprovidererrors.TerminalError{
			Reason:  common.InvalidConfigurationMachineError,
			Message: fmt.Sprintf("failed to parse machineSpec: %v", err),
		}
	}

	c, err := GetClientSet(config)
	if err != nil {
		return false, cloudprovidererrors.TerminalError{
			Reason:  common.InvalidConfigurationMachineError,
			Message: fmt.Sprintf("failed to construct client: %v", err),
		}
	}

	vmr, err := c.GetVmRefByName(machine.Name)
	if err != nil {
		if cloudprovidererrors.IsNotFound(err) {
			// VM is already gone
			return true, nil
		}
		return false, err
	}

	params := map[string]interface{}{
		// Clean all disks matching this VM ID even not referenced in the current VM config.
		"destroy-unreferenced-disks": true,
		// Remove all traces of this VM ID (backup, replication, HA)
		"purge": true,
	}
	exitStatus, err := c.DeleteVmParams(vmr, params)

	return exitStatus == exitStatusSuccess, err
}

// MachineMetricsLabels returns labels used for the Prometheus metrics
// about created machines, e.g. instance type, instance size, region
// or whatever the provider deems interesting. Should always return
// a "size" label.
// This should not do any api calls to the cloud provider
func (provider *provider) MachineMetricsLabels(machine *clusterv1alpha1.Machine) (map[string]string, error) {
	panic("not implemented") // TODO: Implement
}

// MigrateUID is called when the controller migrates types and the UID of the machine object changes
// All cloud providers that use Machine.UID to uniquely identify resources must implement this
func (provider *provider) MigrateUID(ctx context.Context, machine *clusterv1alpha1.Machine, newUID types.UID) error {
	panic("not implemented") // TODO: Implement
}

// SetMetricsForMachines allows providers to provide provider-specific metrics. This may be implemented
// as no-op
func (provider *provider) SetMetricsForMachines(machines clusterv1alpha1.MachineList) error {
	panic("not implemented") // TODO: Implement
}
