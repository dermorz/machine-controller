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

	VMTemplateName string
	CPUSockets     *int
	CPUCores       *int
	MemoryMB       int
	DiskName       string
	DiskSizeGB     int
}

type provider struct {
	configVarResolver *providerconfig.ConfigVarResolver
}

// Server holds the proxmox VM information.
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

func (p *provider) getConfig(provSpec clusterv1alpha1.ProviderSpec) (*Config, error) {
	if provSpec.Value == nil {
		return nil, fmt.Errorf("machine.spec.providerconfig.value is nil")
	}

	pconfig, err := providerconfigtypes.GetConfig(provSpec)
	if err != nil {
		return nil, err
	}

	if pconfig.OperatingSystemSpec.Raw == nil {
		return nil, errors.New("operatingSystemSpec in the MachineDeployment cannot be empty")
	}

	rawConfig, err := proxmoxtypes.GetConfig(*pconfig)
	if err != nil {
		return nil, err
	}

	config := Config{}

	config.Endpoint, err = p.configVarResolver.GetConfigVarStringValueOrEnv(rawConfig.Endpoint, "PM_API_URL")
	if err != nil {
		return nil, err
	}

	config.UserID, err = p.configVarResolver.GetConfigVarStringValueOrEnv(rawConfig.UserID, "PM_API_USER_ID")
	if err != nil {
		return nil, err
	}

	config.Token, err = p.configVarResolver.GetConfigVarStringValueOrEnv(rawConfig.UserID, "PM_API_TOKEN")
	if err != nil {
		return nil, err
	}

	config.TLSInsecure, err = p.configVarResolver.GetConfigVarBoolValueOrEnv(rawConfig.AllowInsecure, "PM_TLS_INSECURE")
	if err != nil {
		return nil, err
	}

	config.ProxyURL, err = p.configVarResolver.GetConfigVarStringValueOrEnv(rawConfig.ProxyURL, "PM_PROXY_URL")
	if err != nil {
		return nil, err
	}

	config.NodeName, err = p.configVarResolver.GetConfigVarStringValueOrEnv(rawConfig.NodeName, "PM_NODE_NAME")

	config.VMTemplateName = rawConfig.VMTemplateName
	config.CPUCores = rawConfig.CPUCores
	config.CPUSockets = rawConfig.CPUSockets
	config.MemoryMB = rawConfig.MemoryMB
	config.DiskSizeGB = rawConfig.DiskSizeGB

	return &config, nil
}

// AddDefaults will read the MachineSpec and apply defaults for provider specific fields
func (*provider) AddDefaults(spec clusterv1alpha1.MachineSpec) (clusterv1alpha1.MachineSpec, error) {
	// TODO: Check if there are default values that make sense.
	return spec, nil
}

func (p *provider) Validate(ctx context.Context, spec clusterv1alpha1.MachineSpec) error {
	config, err := p.getConfig(spec.ProviderSpec)
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

	if nodeExists, err := c.checkNodeExists(config.NodeName); err != nil {
		return err
	} else {
		if !nodeExists {
			return cloudprovidererrors.TerminalError{
				Reason:  common.InvalidConfigurationMachineError,
				Message: fmt.Sprintf("node %q does not exist", config.NodeName),
			}
		}
	}

	if templateExists, err := c.checkTemplateExists(config.VMTemplateName); err != nil {
		return err
	} else {
		if !templateExists {
			return cloudprovidererrors.TerminalError{
				Reason:  common.InvalidConfigurationMachineError,
				Message: fmt.Sprintf("%q is not a VM template", config.VMTemplateName),
			}
		}
	}

	return nil
}

func (p *provider) Get(ctx context.Context, machine *clusterv1alpha1.Machine, data *cloudprovidertypes.ProviderData) (instance.Instance, error) {
	config, err := p.getConfig(machine.Spec.ProviderSpec)
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

	vmr, err := c.getVMRefByName(machine.Name)
	if err != nil {
		return nil, err
	}

	configQemu, err := proxmox.NewConfigQemuFromApi(vmr, c.Client)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch config of VM: %w", err)
	}

	addresses, err := c.getIPsByVMRef(vmr)
	if err != nil {
		return nil, fmt.Errorf("failed to get IP addresses of VM: %w", err)
	}

	var status instance.Status
	vmState, err := c.GetVmState(vmr)
	if err != nil {
		return nil, fmt.Errorf("failed to get state of VM: %w", err)
	}
	switch vmState["status"] {
	case "running":
		status = instance.StatusRunning
	case "stopped":
		status = instance.StatusCreating
	default:
		status = instance.StatusUnknown
	}

	return &Server{
		vmRef:      vmr,
		configQemu: configQemu,
		addresses:  addresses,
		status:     status,
	}, nil

}

// GetCloudConfig will return the cloud provider specific cloud-config, which gets consumed by the kubelet
func (provider *provider) GetCloudConfig(spec clusterv1alpha1.MachineSpec) (config string, name string, err error) {
	panic("not implemented") // TODO: Implement
}

func (p *provider) Create(ctx context.Context, machine *clusterv1alpha1.Machine, data *cloudprovidertypes.ProviderData, userdata string) (instance.Instance, error) {
	config, err := p.getConfig(machine.Spec.ProviderSpec)
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

	sourceVmr, err := c.GetVmRefByName(config.VMTemplateName)
	if err != nil {
		return nil, cloudprovidererrors.TerminalError{
			Reason:  common.InvalidConfigurationMachineError,
			Message: fmt.Sprintf("failed to retrieve VM template %q", config.VMTemplateName),
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
		Name:      machine.Name,
		VmID:      vmID,
		FullClone: proxmox.PointerInt(0),
	}

	vmr := proxmox.NewVmRef(vmID)
	vmr.SetNode(config.NodeName)

	err = configQemu.CloneVm(sourceVmr, vmr, c.Client)
	if err != nil {
		return nil, cloudprovidererrors.TerminalError{
			Reason:  common.CreateMachineError,
			Message: fmt.Sprintf("failed to create VM: %v", err),
		}
	}

	configClone, err := proxmox.NewConfigQemuFromApi(vmr, c.Client)
	if err != nil {
		p.Cleanup(ctx, machine, data)
		return nil, cloudprovidererrors.TerminalError{
			Reason:  common.CreateMachineError,
			Message: fmt.Sprintf("failed to fetch config of newly created VM: %v", err),
		}
	}

	configClone.QemuSockets = *config.CPUSockets
	configClone.QemuCores = *config.CPUCores
	configClone.Memory = config.MemoryMB

	err = configClone.UpdateConfig(vmr, c.Client)
	if err != nil {
		p.Cleanup(ctx, machine, data)
		return nil, cloudprovidererrors.TerminalError{
			Reason:  common.CreateMachineError,
			Message: fmt.Sprintf("failed to update VM size: %v", err),
		}
	}

	_, err = c.ResizeQemuDiskRaw(vmr, config.DiskName, fmt.Sprintf("%dG", config.DiskSizeGB))
	if err != nil {
		p.Cleanup(ctx, machine, data)
		return nil, cloudprovidererrors.TerminalError{
			Reason:  common.CreateMachineError,
			Message: fmt.Sprintf("failed to update disk size: %v", err),
		}
	}

	addresses, err := c.getIPsByVMRef(vmr)
	if err != nil {
		p.Cleanup(ctx, machine, data)
		return nil, cloudprovidererrors.TerminalError{
			Reason:  common.CreateMachineError,
			Message: fmt.Sprintf("failed to get IP addresses of VM: %v", err),
		}
	}

	return &Server{
		vmRef:      vmr,
		configQemu: configClone,
		addresses:  addresses,
		status:     instance.StatusRunning,
	}, nil
}

func (p *provider) Cleanup(ctx context.Context, machine *clusterv1alpha1.Machine, data *cloudprovidertypes.ProviderData) (bool, error) {
	config, err := p.getConfig(machine.Spec.ProviderSpec)
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

	vmr, err := c.getVMRefByName(machine.Name)
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

func (p *provider) MachineMetricsLabels(machine *clusterv1alpha1.Machine) (map[string]string, error) {
	labels := make(map[string]string)

	config, err := p.getConfig(machine.Spec.ProviderSpec)
	if err != nil {
		return labels, fmt.Errorf("failed to parse config: %w", err)
	}

	labels["size"] = fmt.Sprintf("%d-cpus-%d-mb", config.CPUSockets, config.MemoryMB)
	labels["node"] = config.NodeName
	labels["template"] = config.VMTemplateName

	return labels, nil
}

func (*provider) MigrateUID(ctx context.Context, machine *clusterv1alpha1.Machine, newUID types.UID) error {
	return nil
}

func (*provider) SetMetricsForMachines(machines clusterv1alpha1.MachineList) error {
	return nil
}
