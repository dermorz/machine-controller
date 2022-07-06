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

package types

import (
	"github.com/kubermatic/machine-controller/pkg/jsonutil"
	providerconfigtypes "github.com/kubermatic/machine-controller/pkg/providerconfig/types"
)

type RawConfig struct {
	Endpoint      providerconfigtypes.ConfigVarString `json:"endpoint"`
	UserID        providerconfigtypes.ConfigVarString `json:"user_id"`
	Token         providerconfigtypes.ConfigVarString `json:"token"`
	AllowInsecure providerconfigtypes.ConfigVarBool   `json:"allowInsecure"`
	ProxyURL      providerconfigtypes.ConfigVarString `json:"proxyURL,omitempty"`

	NodeName providerconfigtypes.ConfigVarString `json:"nodeName"`

	VMTemplateName string `json:"vmTemplate"`
	CPUSockets     *int   `json:"cpuSockets"`
	CPUCores       *int   `json:"cpuCores,omitempty"`
	MemoryMB       int    `json:"memoryMB"`
	DiskName       string `json:"diskName"`
	DiskSizeGB     int    `json:"diskSizeGB"`
}

func GetConfig(pconfig providerconfigtypes.Config) (*RawConfig, error) {
	rawConfig := &RawConfig{}

	return rawConfig, jsonutil.StrictUnmarshal(pconfig.CloudProviderSpec.Raw, rawConfig)
}

// NodeList represents the response body of GET /api2/json/nodes.
type NodeList struct {
	Data []struct {
		ID             string  `json:"id"`
		Uptime         int     `json:"uptime"`
		Maxdisk        int64   `json:"maxdisk"`
		Status         string  `json:"status"`
		CPU            float64 `json:"cpu"`
		Maxmem         int     `json:"maxmem"`
		Type           string  `json:"type"`
		Disk           int64   `json:"disk"`
		Mem            int     `json:"mem"`
		Maxcpu         int     `json:"maxcpu"`
		SslFingerprint string  `json:"ssl_fingerprint"`
		Node           string  `json:"node"`
		Level          string  `json:"level"`
	} `json:"data"`
}
