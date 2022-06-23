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
	"errors"

	"github.com/Telmate/proxmox-api-go/proxmox"
)

const (
	taskTimeout = 300
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
		return nil, err
	}

	client.SetAPIToken(config.UserID, config.Token)

	return &ClientSet{client}, nil
}
