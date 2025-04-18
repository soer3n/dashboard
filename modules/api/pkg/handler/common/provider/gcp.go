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

package provider

import (
	"context"
	"net/http"
	"strings"

	"google.golang.org/api/compute/v1"

	apiv1 "k8c.io/dashboard/v2/pkg/api/v1"
	handlercommon "k8c.io/dashboard/v2/pkg/handler/common"
	"k8c.io/dashboard/v2/pkg/handler/middleware"
	"k8c.io/dashboard/v2/pkg/handler/v1/common"
	"k8c.io/dashboard/v2/pkg/handler/v1/dc"
	"k8c.io/dashboard/v2/pkg/provider"
	"k8c.io/dashboard/v2/pkg/provider/cloud/gcp"
	kubernetesprovider "k8c.io/dashboard/v2/pkg/provider/kubernetes"
	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	utilerrors "k8c.io/kubermatic/v2/pkg/util/errors"

	"k8s.io/apimachinery/pkg/util/sets"
)

func GCPSizeWithClusterCredentialsEndpoint(ctx context.Context, userInfoGetter provider.UserInfoGetter, projectProvider provider.ProjectProvider, privilegedProjectProvider provider.PrivilegedProjectProvider, seedsGetter provider.SeedsGetter, settingsProvider provider.SettingsProvider, projectID, clusterID, zone string) (interface{}, error) {
	clusterProvider := ctx.Value(middleware.ClusterProviderContextKey).(provider.ClusterProvider)
	cluster, err := handlercommon.GetCluster(ctx, projectProvider, privilegedProjectProvider, userInfoGetter, projectID, clusterID, &provider.ClusterGetOptions{CheckInitStatus: true})
	if err != nil {
		return nil, err
	}
	if cluster.Spec.Cloud.GCP == nil {
		return nil, utilerrors.NewNotFound("cloud spec for ", clusterID)
	}

	assertedClusterProvider, ok := clusterProvider.(*kubernetesprovider.ClusterProvider)
	if !ok {
		return nil, utilerrors.New(http.StatusInternalServerError, "failed to assert clusterProvider")
	}

	secretKeySelector := provider.SecretKeySelectorValueFuncFactory(ctx, assertedClusterProvider.GetSeedClusterAdminRuntimeClient())
	sa, err := gcp.GetCredentialsForCluster(cluster.Spec.Cloud, secretKeySelector)
	if err != nil {
		return nil, err
	}

	settings, err := settingsProvider.GetGlobalSettings(ctx)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	userInfo, err := userInfoGetter(ctx, "")
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}
	datacenter, err := dc.GetDatacenter(userInfo, seedsGetter, cluster.Spec.Cloud.DatacenterName)
	if err != nil {
		return nil, utilerrors.New(http.StatusInternalServerError, err.Error())
	}

	if datacenter.Spec.GCP == nil {
		return nil, utilerrors.NewNotFound("cloud spec (dc) for ", clusterID)
	}

	filter := handlercommon.DetermineMachineFlavorFilter(datacenter.Spec.MachineFlavorFilter, settings.Spec.MachineDeploymentVMResourceQuota)
	return ListGCPSizes(ctx, filter, sa, zone)
}

func GCPZoneWithClusterCredentialsEndpoint(ctx context.Context, userInfoGetter provider.UserInfoGetter, projectProvider provider.ProjectProvider, privilegedProjectProvider provider.PrivilegedProjectProvider, seedsGetter provider.SeedsGetter, projectID, clusterID string) (interface{}, error) {
	clusterProvider := ctx.Value(middleware.ClusterProviderContextKey).(provider.ClusterProvider)
	cluster, err := handlercommon.GetCluster(ctx, projectProvider, privilegedProjectProvider, userInfoGetter, projectID, clusterID, &provider.ClusterGetOptions{CheckInitStatus: true})
	if err != nil {
		return nil, err
	}
	if cluster.Spec.Cloud.GCP == nil {
		return nil, utilerrors.NewNotFound("cloud spec for ", clusterID)
	}

	assertedClusterProvider, ok := clusterProvider.(*kubernetesprovider.ClusterProvider)
	if !ok {
		return nil, utilerrors.New(http.StatusInternalServerError, "failed to assert clusterProvider")
	}

	secretKeySelector := provider.SecretKeySelectorValueFuncFactory(ctx, assertedClusterProvider.GetSeedClusterAdminRuntimeClient())
	sa, err := gcp.GetCredentialsForCluster(cluster.Spec.Cloud, secretKeySelector)
	if err != nil {
		return nil, err
	}
	userInfo, err := userInfoGetter(ctx, "")
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}
	return ListGCPZones(ctx, userInfo, sa, cluster.Spec.Cloud.DatacenterName, seedsGetter)
}

func GCPNetworkWithClusterCredentialsEndpoint(ctx context.Context, userInfoGetter provider.UserInfoGetter, projectProvider provider.ProjectProvider, privilegedProjectProvider provider.PrivilegedProjectProvider, projectID, clusterID string) (interface{}, error) {
	clusterProvider := ctx.Value(middleware.ClusterProviderContextKey).(provider.ClusterProvider)
	cluster, err := handlercommon.GetCluster(ctx, projectProvider, privilegedProjectProvider, userInfoGetter, projectID, clusterID, &provider.ClusterGetOptions{CheckInitStatus: true})
	if err != nil {
		return nil, err
	}
	if cluster.Spec.Cloud.GCP == nil {
		return nil, utilerrors.NewNotFound("cloud spec for ", clusterID)
	}

	assertedClusterProvider, ok := clusterProvider.(*kubernetesprovider.ClusterProvider)
	if !ok {
		return nil, utilerrors.New(http.StatusInternalServerError, "failed to assert clusterProvider")
	}

	secretKeySelector := provider.SecretKeySelectorValueFuncFactory(ctx, assertedClusterProvider.GetSeedClusterAdminRuntimeClient())
	sa, err := gcp.GetCredentialsForCluster(cluster.Spec.Cloud, secretKeySelector)
	if err != nil {
		return nil, err
	}
	return ListGCPNetworks(ctx, sa)
}

func GCPSubnetworkWithClusterCredentialsEndpoint(ctx context.Context, userInfoGetter provider.UserInfoGetter, projectProvider provider.ProjectProvider, privilegedProjectProvider provider.PrivilegedProjectProvider, seedsGetter provider.SeedsGetter, projectID, clusterID, network string) (interface{}, error) {
	clusterProvider := ctx.Value(middleware.ClusterProviderContextKey).(provider.ClusterProvider)
	cluster, err := handlercommon.GetCluster(ctx, projectProvider, privilegedProjectProvider, userInfoGetter, projectID, clusterID, &provider.ClusterGetOptions{CheckInitStatus: true})
	if err != nil {
		return nil, err
	}
	if cluster.Spec.Cloud.GCP == nil {
		return nil, utilerrors.NewNotFound("cloud spec for ", clusterID)
	}

	assertedClusterProvider, ok := clusterProvider.(*kubernetesprovider.ClusterProvider)
	if !ok {
		return nil, utilerrors.New(http.StatusInternalServerError, "failed to assert clusterProvider")
	}

	secretKeySelector := provider.SecretKeySelectorValueFuncFactory(ctx, assertedClusterProvider.GetSeedClusterAdminRuntimeClient())
	sa, err := gcp.GetCredentialsForCluster(cluster.Spec.Cloud, secretKeySelector)
	if err != nil {
		return nil, err
	}
	userInfo, err := userInfoGetter(ctx, "")
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}
	return ListGCPSubnetworks(ctx, userInfo, cluster.Spec.Cloud.DatacenterName, sa, network, seedsGetter)
}

func GCPDiskTypesWithClusterCredentialsEndpoint(ctx context.Context, userInfoGetter provider.UserInfoGetter, projectProvider provider.ProjectProvider, privilegedProjectProvider provider.PrivilegedProjectProvider, projectID, clusterID, zone string) (interface{}, error) {
	clusterProvider := ctx.Value(middleware.ClusterProviderContextKey).(provider.ClusterProvider)

	cluster, err := handlercommon.GetCluster(ctx, projectProvider, privilegedProjectProvider, userInfoGetter, projectID, clusterID, &provider.ClusterGetOptions{CheckInitStatus: true})
	if err != nil {
		return nil, err
	}
	if cluster.Spec.Cloud.GCP == nil {
		return nil, utilerrors.NewNotFound("cloud spec for ", clusterID)
	}

	assertedClusterProvider, ok := clusterProvider.(*kubernetesprovider.ClusterProvider)
	if !ok {
		return nil, utilerrors.New(http.StatusInternalServerError, "failed to assert clusterProvider")
	}

	secretKeySelector := provider.SecretKeySelectorValueFuncFactory(ctx, assertedClusterProvider.GetSeedClusterAdminRuntimeClient())
	sa, err := gcp.GetCredentialsForCluster(cluster.Spec.Cloud, secretKeySelector)
	if err != nil {
		return nil, err
	}

	return ListGCPDiskTypes(ctx, sa, zone)
}

func ListGCPDiskTypes(ctx context.Context, sa string, zone string) (apiv1.GCPDiskTypeList, error) {
	diskTypes := apiv1.GCPDiskTypeList{}
	// Currently accepted values: 'pd-standard', 'pd-ssd' or 'pd-balanced'
	// Reference: https://pkg.go.dev/google.golang.org/api/container/v1#NodeConfig

	excludedDiskTypes := sets.New("local-ssd", "pd-balanced")
	computeService, project, err := gcp.ConnectToComputeService(ctx, sa)
	if err != nil {
		return diskTypes, err
	}

	req := computeService.DiskTypes.List(project, zone)
	err = req.Pages(ctx, func(page *compute.DiskTypeList) error {
		for _, diskType := range page.Items {
			if !excludedDiskTypes.Has(diskType.Name) {
				dt := apiv1.GCPDiskType{
					Name:        diskType.Name,
					Description: diskType.Description,
				}
				diskTypes = append(diskTypes, dt)
			}
		}
		return nil
	})

	return diskTypes, err
}

func ListGCPSubnetworks(ctx context.Context, userInfo *provider.UserInfo, datacenterName string, sa string, networkName string, seedsGetter provider.SeedsGetter) (apiv1.GCPSubnetworkList, error) {
	datacenter, err := dc.GetDatacenter(userInfo, seedsGetter, datacenterName)
	if err != nil {
		return nil, utilerrors.NewBadRequest("%v", err)
	}

	if datacenter.Spec.GCP == nil {
		return nil, utilerrors.NewBadRequest("%s is not a GCP datacenter", datacenterName)
	}

	subnetworks := apiv1.GCPSubnetworkList{}

	computeService, project, err := gcp.ConnectToComputeService(ctx, sa)
	if err != nil {
		return subnetworks, err
	}

	req := computeService.Subnetworks.List(project, datacenter.Spec.GCP.Region)
	err = req.Pages(ctx, func(page *compute.SubnetworkList) error {
		for _, subnetwork := range page.Items {
			// subnetworks.Network are a url e.g. https://www.googleapis.com/compute/v1/[...]/networks/default"
			// we just get the path of the network, instead of the url
			// therefore we can't use regular Filter function and need to check on our own
			if strings.Contains(subnetwork.Network, networkName) {
				subnetworks = append(subnetworks, gcp.ToGCPSubnetworkAPIModel(subnetwork))
			}
		}
		return nil
	})

	return subnetworks, err
}

func ListGCPNetworks(ctx context.Context, sa string) (apiv1.GCPNetworkList, error) {
	networks := apiv1.GCPNetworkList{}

	computeService, project, err := gcp.ConnectToComputeService(ctx, sa)
	if err != nil {
		return networks, err
	}

	req := computeService.Networks.List(project)
	err = req.Pages(ctx, func(page *compute.NetworkList) error {
		for _, network := range page.Items {
			networks = append(networks, gcp.ToGCPNetworkAPIModel(network))
		}
		return nil
	})

	return networks, err
}

func ListGCPZones(ctx context.Context, userInfo *provider.UserInfo, sa, datacenterName string, seedsGetter provider.SeedsGetter) (apiv1.GCPZoneList, error) {
	datacenter, err := dc.GetDatacenter(userInfo, seedsGetter, datacenterName)
	if err != nil {
		return nil, utilerrors.NewBadRequest("%v", err)
	}

	if datacenter.Spec.GCP == nil {
		return nil, utilerrors.NewBadRequest("the %s is not GCP datacenter", datacenterName)
	}

	computeService, project, err := gcp.ConnectToComputeService(ctx, sa)
	if err != nil {
		return nil, err
	}

	zones := apiv1.GCPZoneList{}
	req := computeService.Zones.List(project)
	err = req.Pages(ctx, func(page *compute.ZoneList) error {
		for _, zone := range page.Items {
			if strings.HasPrefix(zone.Name, datacenter.Spec.GCP.Region) {
				apiZone := apiv1.GCPZone{Name: zone.Name}
				zones = append(zones, apiZone)
			}
		}
		return nil
	})

	return zones, err
}

func ListGCPSizes(ctx context.Context, machineFilter kubermaticv1.MachineFlavorFilter, sa, zone string) (apiv1.GCPMachineSizeList, error) {
	sizes := apiv1.GCPMachineSizeList{}

	computeService, project, err := gcp.ConnectToComputeService(ctx, sa)
	if err != nil {
		return sizes, err
	}

	req := computeService.MachineTypes.List(project, zone)
	err = req.Pages(ctx, func(page *compute.MachineTypeList) error {
		for _, machineType := range page.Items {
			mt := apiv1.GCPMachineSize{
				Name:        machineType.Name,
				Description: machineType.Description,
				Memory:      machineType.MemoryMb,
				VCPUs:       machineType.GuestCpus,
			}
			sizes = append(sizes, mt)
		}
		return nil
	})

	return filterGCPByQuota(sizes, machineFilter), err
}

func filterGCPByQuota(instances apiv1.GCPMachineSizeList, machineFilter kubermaticv1.MachineFlavorFilter) apiv1.GCPMachineSizeList {
	filteredRecords := apiv1.GCPMachineSizeList{}

	// Range over the records and apply all the filters to each record.
	// If the record passes all the filters, add it to the final slice.
	for _, r := range instances {
		keep := true

		if !handlercommon.FilterCPU(int(r.VCPUs), machineFilter.MinCPU, machineFilter.MaxCPU) {
			keep = false
		}
		if !handlercommon.FilterMemory(int(r.Memory/1024), machineFilter.MinRAM, machineFilter.MaxRAM) {
			keep = false
		}

		if keep {
			filteredRecords = append(filteredRecords, r)
		}
	}

	return filteredRecords
}
