/*
Copyright 2020 The Kubermatic Kubernetes Platform contributors.

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

package v1_test

import (
	"encoding/json"
	"strings"
	"testing"

	kubevirtv1 "kubevirt.io/api/core/v1"

	apiv1 "k8c.io/dashboard/v2/pkg/api/v1"
	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	"k8c.io/kubermatic/sdk/v2/semver"
)

func TestNewClusterSpec_MarshalJSON(t *testing.T) {
	t.Parallel()

	const valueToBeFiltered = "_______VALUE_TO_BE_FILTERED_______"

	cases := []struct {
		name    string
		cluster apiv1.ClusterSpec
	}{
		{
			"case 1: filter username and password from OpenStack",
			apiv1.ClusterSpec{
				Version: *semver.NewSemverOrDie("1.2.3"),
				Cloud: kubermaticv1.CloudSpec{
					DatacenterName: "OpenstackDatacenter",
					Openstack: &kubermaticv1.OpenstackCloudSpec{
						Username:       valueToBeFiltered,
						Password:       valueToBeFiltered,
						SubnetID:       "subnetID",
						Domain:         "domain",
						FloatingIPPool: "floatingIPPool",
						Network:        "network",
						RouterID:       "routerID",
						SecurityGroups: "securityGroups",
						Project:        "project",
					},
				},
			},
		},
		{
			"case 2: client ID and client secret from Azure",
			apiv1.ClusterSpec{
				Version: *semver.NewSemverOrDie("1.2.3"),
				Cloud: kubermaticv1.CloudSpec{
					Azure: &kubermaticv1.AzureCloudSpec{
						ClientID:        valueToBeFiltered,
						ClientSecret:    valueToBeFiltered,
						TenantID:        "tenantID",
						AvailabilitySet: "availabilitySet",
						ResourceGroup:   "resourceGroup",
						RouteTableName:  "routeTableName",
						SecurityGroup:   "securityGroup",
						SubnetName:      "subnetName",
						SubscriptionID:  "subsciprionID",
						VNetName:        "vnetname",
					},
				},
			},
		},
		{
			"case 3: filter token from Hetzner",
			apiv1.ClusterSpec{
				Version: *semver.NewSemverOrDie("1.2.3"),
				Cloud: kubermaticv1.CloudSpec{
					Hetzner: &kubermaticv1.HetznerCloudSpec{
						Token: valueToBeFiltered,
					},
				},
			},
		},
		{
			"case 4: filter token from DigitalOcean",
			apiv1.ClusterSpec{
				Version: *semver.NewSemverOrDie("1.2.3"),
				Cloud: kubermaticv1.CloudSpec{
					Digitalocean: &kubermaticv1.DigitaloceanCloudSpec{
						Token: valueToBeFiltered,
					},
				},
			},
		},
		{
			"case 5: filter usernames and passwords from VSphere",
			apiv1.ClusterSpec{
				Version: *semver.NewSemverOrDie("1.2.3"),
				Cloud: kubermaticv1.CloudSpec{
					VSphere: &kubermaticv1.VSphereCloudSpec{
						Password: valueToBeFiltered,
						Username: valueToBeFiltered,
						InfraManagementUser: kubermaticv1.VSphereCredentials{
							Username: valueToBeFiltered,
							Password: valueToBeFiltered,
						},
						VMNetName: "vmNetName",
						Datastore: "testDataStore",
					},
				},
			},
		},
		{
			"case 6: filter access key ID and secret access key from AWS",
			apiv1.ClusterSpec{
				Version: *semver.NewSemverOrDie("1.2.3"),
				Cloud: kubermaticv1.CloudSpec{
					AWS: &kubermaticv1.AWSCloudSpec{
						AccessKeyID:         valueToBeFiltered,
						SecretAccessKey:     valueToBeFiltered,
						SecurityGroupID:     "securityGroupID",
						InstanceProfileName: "instanceProfileName",
						RouteTableID:        "routeTableID",
						VPCID:               "vpcID",
					},
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			jsonByteArray, err := c.cluster.MarshalJSON()
			if err != nil {
				t.Errorf("failed to marshal: %v", err)
			}

			if jsonString := string(jsonByteArray); strings.Contains(jsonString, valueToBeFiltered) {
				t.Errorf("output JSON: %s should not contain: %s", jsonString, valueToBeFiltered)
			}

			var jsonObject apiv1.ClusterSpec
			if err := json.Unmarshal(jsonByteArray, &jsonObject); err != nil {
				t.Errorf("failed to unmarshal: %v", err)
			}
		})
	}
}

func TestDigitalOceanNodeSpec_MarshalJSON(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		spec     *apiv1.DigitaloceanNodeSpec
		expected string
	}{
		{
			"case 1: should fail when size is not provided",
			&apiv1.DigitaloceanNodeSpec{},
			"missing or invalid required parameter(s): size",
		},
		{
			"case 2: should marshal when size is provided",
			&apiv1.DigitaloceanNodeSpec{
				Size: "test-size",
			},
			"{\"size\":\"test-size\",\"backups\":false,\"ipv6\":false,\"monitoring\":false,\"tags\":null}",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			marshalledBytes, err := json.Marshal(c.spec)
			if err != nil && !strings.Contains(err.Error(), c.expected) {
				t.Errorf("expected: %v,\nbut got: %v", c.expected, err.Error())
			}

			if len(marshalledBytes) > 0 && string(marshalledBytes) != c.expected {
				t.Errorf("expected: %v,\nbut got: %v", c.expected, string(marshalledBytes))
			}
		})
	}
}

func TestHetznerNodeSpec_MarshalJSON(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		spec     *apiv1.HetznerNodeSpec
		expected string
	}{
		{
			"case 1: should fail when type is not provided",
			&apiv1.HetznerNodeSpec{},
			"missing or invalid required parameter(s): type",
		},
		{
			"case 2: should marshal when type is provided",
			&apiv1.HetznerNodeSpec{
				Type:    "test-type",
				Network: "test",
			},
			"{\"network\":\"test\",\"type\":\"test-type\"}",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			marshalledBytes, err := json.Marshal(c.spec)
			if err != nil && !strings.Contains(err.Error(), c.expected) {
				t.Errorf("expected: %v,\nbut got: %v", c.expected, err.Error())
			}

			if len(marshalledBytes) > 0 && string(marshalledBytes) != c.expected {
				t.Errorf("expected: %v,\nbut got: %v", c.expected, string(marshalledBytes))
			}
		})
	}
}

func TestAzureNodeSpec_MarshalJSON(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		spec     *apiv1.AzureNodeSpec
		expected string
	}{
		{
			"case 1: should fail when size is not provided",
			&apiv1.AzureNodeSpec{},
			"missing or invalid required parameter(s): size",
		},
		{
			"case 2: should marshal when size is provided",
			&apiv1.AzureNodeSpec{
				Size: "test-size",
			},
			"{\"size\":\"test-size\",\"assignPublicIP\":false,\"osDiskSize\":0,\"dataDiskSize\":0,\"zones\":null,\"imageID\":\"\",\"assignAvailabilitySet\":false,\"enableAcceleratedNetworking\":null}",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			marshalledBytes, err := json.Marshal(c.spec)
			if err != nil && !strings.Contains(err.Error(), c.expected) {
				t.Errorf("expected: %v,\nbut got: %v", c.expected, err.Error())
			}

			if len(marshalledBytes) > 0 && string(marshalledBytes) != c.expected {
				t.Errorf("expected: %v,\nbut got: %v", c.expected, string(marshalledBytes))
			}
		})
	}
}

func TestVSphereNodeSpec_MarshalJSON(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		spec     *apiv1.VSphereNodeSpec
		expected string
	}{
		{
			"case 1: should fail when required parameters are not provided",
			&apiv1.VSphereNodeSpec{},
			"missing or invalid required parameter(s): cpus, memory, diskSizeGB, template",
		},
		{
			"case 2: should fail when only cpus are provided",
			&apiv1.VSphereNodeSpec{
				CPUs: 1,
			},
			"missing or invalid required parameter(s): memory, diskSizeGB, template",
		},
		{
			"case 3: should fail when cpus and memory are provided",
			&apiv1.VSphereNodeSpec{
				CPUs:   1,
				Memory: 1,
			},
			"missing or invalid required parameter(s): diskSizeGB, template",
		},
		{
			"case 4: should fail when cpus, memory and disk size are provided",
			&apiv1.VSphereNodeSpec{
				CPUs:       1,
				Memory:     1,
				DiskSizeGB: &[]int64{1}[0],
			},
			"missing or invalid required parameter(s): template",
		},
		{
			"case 5: should fail when cpus count is wrong",
			&apiv1.VSphereNodeSpec{
				CPUs:       0,
				Memory:     1,
				DiskSizeGB: &[]int64{1}[0],
				Template:   "test-template",
			},
			"missing or invalid required parameter(s): cpus",
		},
		{
			"case 6: should fail when memory count is wrong",
			&apiv1.VSphereNodeSpec{
				CPUs:       1,
				Memory:     0,
				DiskSizeGB: &[]int64{1}[0],
				Template:   "test-template",
			},
			"missing or invalid required parameter(s): memory",
		},
		{
			"case 7: should fail when disk size is wrong",
			&apiv1.VSphereNodeSpec{
				CPUs:       1,
				Memory:     1,
				DiskSizeGB: &[]int64{0}[0],
				Template:   "test-template",
			},
			"missing or invalid required parameter(s): diskSizeGB",
		},
		{
			"case 8: should marshal when all required parameters are provided",
			&apiv1.VSphereNodeSpec{
				CPUs:       1,
				Memory:     1,
				DiskSizeGB: &[]int64{1}[0],
				Template:   "test-template",
			},
			"{\"cpus\":1,\"memory\":1,\"diskSizeGB\":1,\"template\":\"test-template\",\"vmAntiAffinity\":null}",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			marshalledBytes, err := json.Marshal(c.spec)
			if err != nil && !strings.Contains(err.Error(), c.expected) {
				t.Errorf("expected: %v,\nbut got: %v", c.expected, err.Error())
			}

			if len(marshalledBytes) > 0 && string(marshalledBytes) != c.expected {
				t.Errorf("expected: %v,\nbut got: %v", c.expected, string(marshalledBytes))
			}
		})
	}
}

func TestOpenstackNodeSpec_MarshalJSON(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		spec     *apiv1.OpenstackNodeSpec
		expected string
	}{
		{
			"case 1: should fail when required parameters are not provided",
			&apiv1.OpenstackNodeSpec{},
			"missing or invalid required parameter(s): flavor, image",
		},
		{
			"case 2: should fail when only flavor is provided",
			&apiv1.OpenstackNodeSpec{
				Flavor: "test-flavor",
			},
			"missing or invalid required parameter(s): image",
		},
		{
			"case 3: should fail when only image is provided",
			&apiv1.OpenstackNodeSpec{
				Image: "test-image",
			},
			"missing or invalid required parameter(s): flavor",
		},
		{
			"case 4: should marshal when all required parameters are provided",
			&apiv1.OpenstackNodeSpec{
				Flavor: "test-flavor",
				Image:  "test-image",
			},
			"{\"flavor\":\"test-flavor\",\"image\":\"test-image\",\"diskSize\":null,\"availabilityZone\":\"\",\"instanceReadyCheckPeriod\":\"\",\"instanceReadyCheckTimeout\":\"\",\"serverGroup\":\"\",\"configDrive\":false}",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			marshalledBytes, err := json.Marshal(c.spec)
			if err != nil && !strings.Contains(err.Error(), c.expected) {
				t.Errorf("expected: %v,\nbut got: %v", c.expected, err.Error())
			}

			if len(marshalledBytes) > 0 && string(marshalledBytes) != c.expected {
				t.Errorf("expected: %v,\nbut got: %v", c.expected, string(marshalledBytes))
			}
		})
	}
}

func TestAWSNodeSpec_MarshalJSON(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		spec     *apiv1.AWSNodeSpec
		expected string
	}{
		{
			"case 1: should fail when required parameters are not provided",
			&apiv1.AWSNodeSpec{},
			"missing or invalid required parameter(s): instanceType, diskSize, volumeType",
		},
		{
			"case 2: should fail when only instance type is provided",
			&apiv1.AWSNodeSpec{
				InstanceType: "test-instance",
			},
			"missing or invalid required parameter(s): diskSize, volumeType",
		},
		{
			"case 3: should fail when only volume type is provided",
			&apiv1.AWSNodeSpec{
				VolumeType: "test-volume",
			},
			"missing or invalid required parameter(s): instanceType, diskSize",
		},
		{
			"case 4: should fail when only volume size is provided",
			&apiv1.AWSNodeSpec{
				VolumeSize: 1,
			},
			"missing or invalid required parameter(s): instanceType, volumeType",
		},
		{
			"case 3: should fail when volume size is wrong",
			&apiv1.AWSNodeSpec{
				VolumeSize:   0,
				InstanceType: "test-instance",
				VolumeType:   "test-volume",
			},
			"missing or invalid required parameter(s): diskSize",
		},
		{
			"case 4: should marshal when all required parameters are provided",
			&apiv1.AWSNodeSpec{
				InstanceType: "test-instance",
				VolumeSize:   1,
				VolumeType:   "test-volume",
			},
			"{\"instanceType\":\"test-instance\",\"diskSize\":1,\"volumeType\":\"test-volume\",\"ami\":\"\",\"tags\":null,\"availabilityZone\":\"\",\"subnetID\":\"\",\"assignPublicIP\":null,\"isSpotInstance\":null,\"ebsVolumeEncrypted\":null}",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			marshalledBytes, err := json.Marshal(c.spec)
			if err != nil && !strings.Contains(err.Error(), c.expected) {
				t.Errorf("expected: %v,\nbut got: %v", c.expected, err.Error())
			}

			if len(marshalledBytes) > 0 && string(marshalledBytes) != c.expected {
				t.Errorf("expected: %v,\nbut got: %v", c.expected, string(marshalledBytes))
			}
		})
	}
}

func TestPacketNodeSpec_MarshalJSON(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		spec     *apiv1.PacketNodeSpec
		expected string
	}{
		{
			"case 1: should fail when instance type is not provided",
			&apiv1.PacketNodeSpec{},
			"missing or invalid required parameter(s): instanceType",
		},
		{
			"case 2: should marshal when instance type is provided",
			&apiv1.PacketNodeSpec{
				InstanceType: "test-instance",
			},
			"{\"instanceType\":\"test-instance\",\"tags\":null}",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			marshalledBytes, err := json.Marshal(c.spec)
			if err != nil && !strings.Contains(err.Error(), c.expected) {
				t.Errorf("expected: %v,\nbut got: %v", c.expected, err.Error())
			}

			if len(marshalledBytes) > 0 && string(marshalledBytes) != c.expected {
				t.Errorf("expected: %v,\nbut got: %v", c.expected, string(marshalledBytes))
			}
		})
	}
}

func TestGCPNodeSpec_MarshalJSON(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		spec     *apiv1.GCPNodeSpec
		expected string
	}{
		{
			"case 1: should fail when required parameters are not provided",
			&apiv1.GCPNodeSpec{},
			"missing or invalid required parameter(s): zone, diskSize, machineType, diskType",
		},
		{
			"case 2: should fail when only zone is provided",
			&apiv1.GCPNodeSpec{
				Zone: "test-zone",
			},
			"missing or invalid required parameter(s): diskSize, machineType, diskType",
		},
		{
			"case 3: should fail when only diskSize is provided",
			&apiv1.GCPNodeSpec{
				DiskSize: 1,
			},
			"missing or invalid required parameter(s): zone, machineType, diskType",
		},
		{
			"case 4: should fail when only machineType is provided",
			&apiv1.GCPNodeSpec{
				MachineType: "test-machine",
			},
			"missing or invalid required parameter(s): zone, diskSize, diskType",
		},
		{
			"case 5: should fail when only diskType is provided",
			&apiv1.GCPNodeSpec{
				DiskType: "test-disk",
			},
			"missing or invalid required parameter(s): zone, diskSize, machineType",
		},
		{
			"case 6: should fail when diskSize is invalid",
			&apiv1.GCPNodeSpec{
				DiskSize: 0,
			},
			"missing or invalid required parameter(s): zone, diskSize, machineType, diskType",
		},
		{
			"case 7: should marshal when instance type is provided",
			&apiv1.GCPNodeSpec{
				Zone:        "test-zone",
				MachineType: "test-machine",
				DiskSize:    1,
				DiskType:    "test-disk",
			},
			"{\"zone\":\"test-zone\",\"machineType\":\"test-machine\",\"diskSize\":1,\"diskType\":\"test-disk\",\"preemptible\":false,\"labels\":null,\"tags\":null,\"customImage\":\"\"}",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			marshalledBytes, err := json.Marshal(c.spec)
			if err != nil && !strings.Contains(err.Error(), c.expected) {
				t.Errorf("expected: %v,\nbut got: %v", c.expected, err.Error())
			}

			if len(marshalledBytes) > 0 && string(marshalledBytes) != c.expected {
				t.Errorf("expected: %v,\nbut got: %v", c.expected, string(marshalledBytes))
			}
		})
	}
}

func TestKubevirtNodeSpec_MarshalJSON(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		spec     *apiv1.KubevirtNodeSpec
		expected string
	}{
		{
			"case 1: should fail when required parameters are not provided",
			&apiv1.KubevirtNodeSpec{},
			"missing or invalid required parameter(s): cpus, memory, primaryDiskOSImage, primaryDiskStorageClassName, primaryDiskSize",
		},

		{
			"case 2: should fail when only cpus is provided",
			&apiv1.KubevirtNodeSpec{
				CPUs: "2",
			},
			"missing or invalid required parameter(s): memory, primaryDiskOSImage, primaryDiskStorageClassName, primaryDiskSize",
		},
		{
			"case 3: should fail when only memory is provided",
			&apiv1.KubevirtNodeSpec{
				Memory: "1",
			},
			"missing or invalid required parameter(s): cpus, primaryDiskOSImage, primaryDiskStorageClassName, primaryDiskSize",
		},
		{
			"case 4: should fail when only primaryDiskOSImageURL is provided",
			&apiv1.KubevirtNodeSpec{
				PrimaryDiskOSImage: "test-url",
			},
			"missing or invalid required parameter(s): cpus, memory, primaryDiskStorageClassName, primaryDiskSize",
		},
		{
			"case 5: should fail when only primaryDiskStorageClassName is provided",
			&apiv1.KubevirtNodeSpec{
				PrimaryDiskStorageClassName: "test-sc",
			},
			"missing or invalid required parameter(s): cpus, memory, primaryDiskOSImage, primaryDiskSize",
		},
		{
			"case 6: should fail when only primaryDiskSize is provided",
			&apiv1.KubevirtNodeSpec{
				PrimaryDiskSize: "1",
			},
			"missing or invalid required parameter(s): cpus, memory, primaryDiskOSImage, primaryDiskStorageClassName",
		},
		{
			"case 7: should marshal when instance type is not provided",
			&apiv1.KubevirtNodeSpec{
				CPUs:                        "1",
				Memory:                      "1",
				PrimaryDiskOSImage:          "test-url",
				PrimaryDiskStorageClassName: "test-sc",
				PrimaryDiskSize:             "1",
			},
			"{\"flavorName\":\"\",\"flavorProfile\":\"\",\"instancetype\":null,\"preference\":null,\"cpus\":\"1\",\"memory\":\"1\",\"primaryDiskOSImage\":\"test-url\",\"primaryDiskStorageClassName\":\"test-sc\",\"primaryDiskSize\":\"1\",\"secondaryDisks\":null,\"podAffinityPreset\":\"\",\"podAntiAffinityPreset\":\"\",\"nodeAffinityPreset\":{\"Type\":\"\",\"Key\":\"\",\"Values\":null},\"topologySpreadConstraints\":null}",
		},
		{
			"case 8-1: should fail when cpu/memory is provided with vm-flavor and NodeSpec",
			&apiv1.KubevirtNodeSpec{
				CPUs:                        "1",
				Memory:                      "1",
				FlavorName:                  "test-flavor",
				PrimaryDiskOSImage:          "test-url",
				PrimaryDiskStorageClassName: "test-sc",
				PrimaryDiskSize:             "1",
			},
			"cpus, memory can not be set at the same time in template (instancetype/flavor) and node spec",
		},
		{
			"case 8-2: should fail when cpu is provided with vm-flavor and NodeSpec",
			&apiv1.KubevirtNodeSpec{
				CPUs:                        "1",
				FlavorName:                  "test-flavor",
				PrimaryDiskOSImage:          "test-url",
				PrimaryDiskStorageClassName: "test-sc",
				PrimaryDiskSize:             "1",
			},
			"cpus can not be set at the same time in template (instancetype/flavor) and node spec",
		},
		{
			"case 8-3: should fail when memory is provided with vm-flavor and NodeSpec",
			&apiv1.KubevirtNodeSpec{
				Memory:                      "1",
				FlavorName:                  "test-flavor",
				PrimaryDiskOSImage:          "test-url",
				PrimaryDiskStorageClassName: "test-sc",
				PrimaryDiskSize:             "1",
			},
			"memory can not be set at the same time in template (instancetype/flavor) and node spec",
		},
		{
			"case 8-4: should fail when memory is provided with vm-flavor and NodeSpec",
			&apiv1.KubevirtNodeSpec{
				CPUs:   "1",
				Memory: "1",
				Instancetype: &kubevirtv1.InstancetypeMatcher{
					Name: "standard-2",
					Kind: "VirtualMachineInstancetype",
				}, PrimaryDiskOSImage: "test-url",
				PrimaryDiskStorageClassName: "test-sc",
				PrimaryDiskSize:             "1",
			},
			"cpus, memory can not be set at the same time in template (instancetype/flavor) and node spec",
		},
		{
			"case 8-5: should fail when memory is provided with vm-flavor and NodeSpec",
			&apiv1.KubevirtNodeSpec{
				CPUs: "1",
				Instancetype: &kubevirtv1.InstancetypeMatcher{
					Name: "standard-2",
					Kind: "VirtualMachineInstancetype",
				}, PrimaryDiskOSImage: "test-url",
				PrimaryDiskStorageClassName: "test-sc",
				PrimaryDiskSize:             "1",
			},
			"cpus can not be set at the same time in template (instancetype/flavor) and node spec",
		},
		{
			"case 8-6: should fail when memory is provided with vm-flavor and NodeSpec",
			&apiv1.KubevirtNodeSpec{
				Memory: "1",
				Instancetype: &kubevirtv1.InstancetypeMatcher{
					Name: "standard-2",
					Kind: "VirtualMachineInstancetype",
				}, PrimaryDiskOSImage: "test-url",
				PrimaryDiskStorageClassName: "test-sc",
				PrimaryDiskSize:             "1",
			},
			"memory can not be set at the same time in template (instancetype/flavor) and node spec",
		},
		{
			"case 8-7: should marshal when cpu/memory is provided with vm-flavor",
			&apiv1.KubevirtNodeSpec{
				FlavorName:                  "test-flavor",
				PrimaryDiskOSImage:          "test-url",
				PrimaryDiskStorageClassName: "test-sc",
				PrimaryDiskSize:             "1",
			},
			"{\"flavorName\":\"test-flavor\",\"flavorProfile\":\"\",\"instancetype\":null,\"preference\":null,\"cpus\":\"\",\"memory\":\"\",\"primaryDiskOSImage\":\"test-url\",\"primaryDiskStorageClassName\":\"test-sc\",\"primaryDiskSize\":\"1\",\"secondaryDisks\":null,\"podAffinityPreset\":\"\",\"podAntiAffinityPreset\":\"\",\"nodeAffinityPreset\":{\"Type\":\"\",\"Key\":\"\",\"Values\":null},\"topologySpreadConstraints\":null}",
		},
		{
			"case 9: should marshal when flavor is provided with affinity",
			&apiv1.KubevirtNodeSpec{
				CPUs:                        "1",
				Memory:                      "1",
				PrimaryDiskOSImage:          "test-url",
				PrimaryDiskStorageClassName: "test-sc",
				PrimaryDiskSize:             "1",
				NodeAffinityPreset: apiv1.NodeAffinityPreset{
					Type:   "soft",
					Key:    "foo",
					Values: []string{"bar"},
				},
			},
			"{\"flavorName\":\"\",\"flavorProfile\":\"\",\"instancetype\":null,\"preference\":null,\"cpus\":\"1\",\"memory\":\"1\",\"primaryDiskOSImage\":\"test-url\",\"primaryDiskStorageClassName\":\"test-sc\",\"primaryDiskSize\":\"1\",\"secondaryDisks\":null,\"podAffinityPreset\":\"\",\"podAntiAffinityPreset\":\"\",\"nodeAffinityPreset\":{\"Type\":\"soft\",\"Key\":\"foo\",\"Values\":[\"bar\"]},\"topologySpreadConstraints\":null}",
		},
		{
			"case 10: should marshal when instance type is provided with topology constraint",
			&apiv1.KubevirtNodeSpec{
				Instancetype: &kubevirtv1.InstancetypeMatcher{
					Name: "standard-2",
					Kind: "VirtualMachineInstancetype",
				},
				PrimaryDiskOSImage:          "test-url",
				PrimaryDiskStorageClassName: "test-sc",
				PrimaryDiskSize:             "1",
				NodeAffinityPreset: apiv1.NodeAffinityPreset{
					Type:   "soft",
					Key:    "foo",
					Values: []string{"bar"},
				},
				TopologySpreadConstraints: []apiv1.TopologySpreadConstraint{{MaxSkew: 1, TopologyKey: "zone", WhenUnsatisfiable: "ScheduleAnyway"}},
			},
			"{\"flavorName\":\"\",\"flavorProfile\":\"\",\"instancetype\":{\"name\":\"standard-2\",\"kind\":\"VirtualMachineInstancetype\"},\"preference\":null,\"cpus\":\"\",\"memory\":\"\",\"primaryDiskOSImage\":\"test-url\",\"primaryDiskStorageClassName\":\"test-sc\",\"primaryDiskSize\":\"1\",\"secondaryDisks\":null,\"podAffinityPreset\":\"\",\"podAntiAffinityPreset\":\"\",\"nodeAffinityPreset\":{\"Type\":\"soft\",\"Key\":\"foo\",\"Values\":[\"bar\"]},\"topologySpreadConstraints\":[{\"maxSkew\":1,\"topologyKey\":\"zone\",\"whenUnsatisfiable\":\"ScheduleAnyway\"}]}",
		},
		{
			"case 11: should fail when no cpu is provided (neither directly nor instancetype)",
			&apiv1.KubevirtNodeSpec{
				Memory:                      "1",
				PrimaryDiskOSImage:          "test-url",
				PrimaryDiskStorageClassName: "test-sc",
				PrimaryDiskSize:             "1"},
			"missing or invalid required parameter(s): cpus",
		},
		{
			"case 12: should fail when no memory is provided (neither directly nor instancetype)",
			&apiv1.KubevirtNodeSpec{
				CPUs:                        "1",
				PrimaryDiskOSImage:          "test-url",
				PrimaryDiskStorageClassName: "test-sc",
				PrimaryDiskSize:             "1"},
			"missing or invalid required parameter(s): memory",
		},
		{
			"case 13: should marshal when cpu/memory are provided with instancetype",
			&apiv1.KubevirtNodeSpec{
				Instancetype: &kubevirtv1.InstancetypeMatcher{
					Name: "standard-2",
					Kind: "VirtualMachineInstancetype",
				},
				PrimaryDiskOSImage:          "test-url",
				PrimaryDiskStorageClassName: "test-sc",
				PrimaryDiskSize:             "1",
			},
			"{\"flavorName\":\"\",\"flavorProfile\":\"\",\"instancetype\":{\"name\":\"standard-2\",\"kind\":\"VirtualMachineInstancetype\"},\"preference\":null,\"cpus\":\"\",\"memory\":\"\",\"primaryDiskOSImage\":\"test-url\",\"primaryDiskStorageClassName\":\"test-sc\",\"primaryDiskSize\":\"1\",\"secondaryDisks\":null,\"podAffinityPreset\":\"\",\"podAntiAffinityPreset\":\"\",\"nodeAffinityPreset\":{\"Type\":\"\",\"Key\":\"\",\"Values\":null},\"topologySpreadConstraints\":null}",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			marshalledBytes, err := json.Marshal(c.spec)
			if err != nil && !strings.Contains(err.Error(), c.expected) {
				t.Errorf("expected: %v,\nbut got: %v", c.expected, err.Error())
			}

			if len(marshalledBytes) > 0 && string(marshalledBytes) != c.expected {
				t.Errorf("expected: %v,\nbut got: %v", c.expected, string(marshalledBytes))
			}
		})
	}
}

func TestAlibabaNodeSpec_MarshalJSON(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		spec     *apiv1.AlibabaNodeSpec
		expected string
	}{
		{
			"case 1: should fail when required parameters are not provided",
			&apiv1.AlibabaNodeSpec{},
			"missing or invalid required parameter(s): instanceType, diskSize, diskType, vSwitchID, internetMaxBandwidthOut, zoneID",
		},
		{
			"case 2: should fail when only instanceType is provided",
			&apiv1.AlibabaNodeSpec{
				InstanceType: "test-instance",
			},
			"missing or invalid required parameter(s): diskSize, diskType, vSwitchID, internetMaxBandwidthOut, zoneID",
		},
		{
			"case 3: should fail when only diskSize is provided",
			&apiv1.AlibabaNodeSpec{
				DiskSize: "1",
			},
			"missing or invalid required parameter(s): instanceType, diskType, vSwitchID, internetMaxBandwidthOut, zoneID",
		},
		{
			"case 4: should fail when only diskType is provided",
			&apiv1.AlibabaNodeSpec{
				DiskType: "test-disk",
			},
			"missing or invalid required parameter(s): instanceType, diskSize, vSwitchID, internetMaxBandwidthOut, zoneID",
		},
		{
			"case 5: should fail when only vSwitchID is provided",
			&apiv1.AlibabaNodeSpec{
				VSwitchID: "test-vswitch",
			},
			"missing or invalid required parameter(s): instanceType, diskSize, diskType, internetMaxBandwidthOut, zoneID",
		},
		{
			"case 6: should fail when only internetMaxBandwidthOut is provided",
			&apiv1.AlibabaNodeSpec{
				InternetMaxBandwidthOut: "1",
			},
			"missing or invalid required parameter(s): instanceType, diskSize, diskType, vSwitchID, zoneID",
		},
		{
			"case 7: should fail when only zoneID is provided",
			&apiv1.AlibabaNodeSpec{
				ZoneID: "test-zone",
			},
			"missing or invalid required parameter(s): instanceType, diskSize, diskType, vSwitchID, internetMaxBandwidthOut",
		},
		{
			"case 8: should marshal when instance type is provided",
			&apiv1.AlibabaNodeSpec{
				InstanceType:            "test-instance",
				DiskSize:                "1",
				DiskType:                "test-disk",
				VSwitchID:               "test-vswitch",
				InternetMaxBandwidthOut: "1",
				ZoneID:                  "test-zone",
			},
			"{\"instanceType\":\"test-instance\",\"diskSize\":\"1\",\"diskType\":\"test-disk\",\"vSwitchID\":\"test-vswitch\",\"internetMaxBandwidthOut\":\"1\",\"labels\":null,\"zoneID\":\"test-zone\"}",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			marshalledBytes, err := json.Marshal(c.spec)
			if err != nil && !strings.Contains(err.Error(), c.expected) {
				t.Errorf("expected: %v,\nbut got: %v", c.expected, err.Error())
			}

			if len(marshalledBytes) > 0 && string(marshalledBytes) != c.expected {
				t.Errorf("expected: %v,\nbut got: %v", c.expected, string(marshalledBytes))
			}
		})
	}
}

func TestAnexiaNodeSpec_MarshalJSON(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		spec     *apiv1.AnexiaNodeSpec
		expected string
	}{
		{
			"case 1: should fail when required parameters are not provided",
			&apiv1.AnexiaNodeSpec{},
			"missing or invalid required parameter(s): vlanID missing, cpus missing, memory missing, neither templateID nor template is set, disks missing",
		},
		{
			"case 2: should fail when only vlanID is provided",
			&apiv1.AnexiaNodeSpec{
				VlanID: "test-vlan",
			},
			"missing or invalid required parameter(s): cpus missing, memory missing, neither templateID nor template is set, disks missing",
		},
		{
			"case 3.1: should fail when only templateID is provided",
			&apiv1.AnexiaNodeSpec{
				TemplateID: "test-template-id",
			},
			"missing or invalid required parameter(s): vlanID missing, cpus missing, memory missing, disks missing",
		},
		{
			"case 3.2: should fail when only template is provided",
			&apiv1.AnexiaNodeSpec{
				Template: "test-template-name",
			},
			"missing or invalid required parameter(s): vlanID missing, cpus missing, memory missing, disks missing",
		},
		{
			"case 4: should fail when only cpus is provided",
			&apiv1.AnexiaNodeSpec{
				CPUs: 1,
			},
			"missing or invalid required parameter(s): vlanID missing, memory missing, neither templateID nor template is set, disks missing",
		},
		{
			"case 5: should fail when only memory is provided",
			&apiv1.AnexiaNodeSpec{
				Memory: 1,
			},
			"missing or invalid required parameter(s): vlanID missing, cpus missing, neither templateID nor template is set, disks missing",
		},
		{
			"case 6: should fail when only diskSize is provided",
			&apiv1.AnexiaNodeSpec{
				DiskSize: &[]int64{1}[0],
			},
			"missing or invalid required parameter(s): vlanID missing, cpus missing, memory missing, neither templateID nor template is set",
		},
		{
			"case 7: should fail with diskSize and disks provided",
			&apiv1.AnexiaNodeSpec{
				VlanID:     "test-vlan",
				TemplateID: "test-template",
				CPUs:       1,
				Memory:     1,
				DiskSize:   &[]int64{1}[0],
				Disks: []apiv1.AnexiaDiskConfig{
					{
						Size: 1,
					},
				},
			},
			"missing or invalid required parameter(s): both disks and diskSize configured but only one of those allowed",
		},
		{
			"case 8: should marshal when everything is provided, using the old diskSize attribute",
			&apiv1.AnexiaNodeSpec{
				VlanID:     "test-vlan",
				TemplateID: "test-template",
				CPUs:       1,
				Memory:     1,
				DiskSize:   &[]int64{1}[0],
			},
			"{\"vlanID\":\"test-vlan\",\"templateID\":\"test-template\",\"cpus\":1,\"memory\":1,\"diskSize\":1}",
		},
		{
			"case 9: should marshal when everything is provided, using the new disks attribute",
			&apiv1.AnexiaNodeSpec{
				VlanID:     "test-vlan",
				TemplateID: "test-template",
				CPUs:       1,
				Memory:     1,
				Disks: []apiv1.AnexiaDiskConfig{
					{
						Size:            1,
						PerformanceType: &[]string{"ENT6"}[0],
					},
				},
			},
			`{"vlanID":"test-vlan","templateID":"test-template","cpus":1,"memory":1,"disks":[{"size":1,"performanceType":"ENT6"}]}`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			marshalledBytes, err := json.Marshal(c.spec)
			if err != nil && !strings.Contains(err.Error(), c.expected) {
				t.Errorf("expected: %v,\nbut got: %v", c.expected, err.Error())
			}

			if len(marshalledBytes) > 0 && string(marshalledBytes) != c.expected {
				t.Errorf("expected: %v,\nbut got: %v", c.expected, string(marshalledBytes))
			}
		})
	}
}
