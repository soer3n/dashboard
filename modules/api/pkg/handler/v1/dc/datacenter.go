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

package dc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/go-kit/kit/endpoint"
	"github.com/gorilla/mux"

	apiv1 "k8c.io/dashboard/v2/pkg/api/v1"
	"k8c.io/dashboard/v2/pkg/handler/v1/common"
	"k8c.io/dashboard/v2/pkg/provider"
	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	kubermaticv1helper "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1/helper"
	"k8c.io/kubermatic/v2/pkg/log"
	"k8c.io/kubermatic/v2/pkg/util/email"
	utilerrors "k8c.io/kubermatic/v2/pkg/util/errors"

	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// ListEndpoint an HTTP endpoint that returns a list of apiv1.Datacenter.
func ListEndpoint(seedsGetter provider.SeedsGetter, userInfoGetter provider.UserInfoGetter) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		seeds, err := seedsGetter()
		if err != nil {
			return nil, utilerrors.New(http.StatusInternalServerError, fmt.Sprintf("failed to list seeds: %v", err))
		}

		userInfo, err := userInfoGetter(ctx, "")
		if err != nil {
			return nil, common.KubernetesErrorToHTTPError(err)
		}

		// Get the DCs and immediately filter out the ones restricted by e-mail domain if user is not admin
		dcs := getAPIDCsFromSeedMap(seeds)
		if !userInfo.IsAdmin {
			dcs, err = filterDCsByEmail(userInfo, dcs)
			if err != nil {
				return apiv1.Datacenter{}, utilerrors.New(http.StatusInternalServerError,
					fmt.Sprintf("failed to filter datacenters by email: %v", err))
			}
		}

		// Maintain a stable order. We do not check for duplicate names here
		sort.SliceStable(dcs, func(i, j int) bool {
			return dcs[i].Metadata.Name < dcs[j].Metadata.Name
		})

		return dcs, nil
	}
}

// ListEndpoint an HTTP endpoint that returns a list of apiv1.Datacenter for a specified provider.
func ListEndpointForProvider(seedsGetter provider.SeedsGetter, userInfoGetter provider.UserInfoGetter) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(forProviderDCListReq)
		if !ok {
			return nil, utilerrors.NewBadRequest("invalid request")
		}

		seeds, err := seedsGetter()
		if err != nil {
			return nil, utilerrors.New(http.StatusInternalServerError, fmt.Sprintf("failed to list seeds: %v", err))
		}

		userInfo, err := userInfoGetter(ctx, "")
		if err != nil {
			return nil, common.KubernetesErrorToHTTPError(err)
		}

		// Get the DCs and immediately filter them out for the provider.
		dcs := filterDCsByProvider(req.Provider, getAPIDCsFromSeedMap(seeds))

		// Filter out dc restricted by email if user is not admin
		if !userInfo.IsAdmin {
			dcs, err = filterDCsByEmail(userInfo, dcs)
			if err != nil {
				return apiv1.Datacenter{}, utilerrors.New(http.StatusInternalServerError,
					fmt.Sprintf("failed to filter datacenters by email: %v", err))
			}
		}

		// Maintain a stable order. We do not check for duplicate names here
		sort.SliceStable(dcs, func(i, j int) bool {
			return dcs[i].Metadata.Name < dcs[j].Metadata.Name
		})

		return dcs, nil
	}
}

func filterDCsByProvider(providerName string, list []apiv1.Datacenter) []apiv1.Datacenter {
	var dcList []apiv1.Datacenter

	for _, dc := range list {
		if dc.Spec.Provider == providerName {
			dcList = append(dcList, dc)
		}
	}
	return dcList
}

// GetEndpoint an HTTP endpoint that returns a single apiv1.Datacenter object.
func GetEndpoint(seedsGetter provider.SeedsGetter, userInfoGetter provider.UserInfoGetter) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(LegacyDCReq)

		userInfo, err := userInfoGetter(ctx, "")
		if err != nil {
			return nil, common.KubernetesErrorToHTTPError(err)
		}

		return GetDatacenter(userInfo, seedsGetter, req.DC)
	}
}

// GetDatacenter a function that gives you a single apiv1.Datacenter object.
func GetDatacenter(userInfo *provider.UserInfo, seedsGetter provider.SeedsGetter, datacenterToGet string) (apiv1.Datacenter, error) {
	seeds, err := seedsGetter()
	if err != nil {
		return apiv1.Datacenter{}, utilerrors.New(http.StatusInternalServerError, fmt.Sprintf("failed to list seeds: %v", err))
	}

	// Get the DCs and immediately filter out the ones restricted by e-mail domain if user is not admin
	dcs := getAPIDCsFromSeedMap(seeds)
	if !userInfo.IsAdmin {
		dcs, err = filterDCsByEmail(userInfo, dcs)
		if err != nil {
			return apiv1.Datacenter{}, utilerrors.New(http.StatusInternalServerError,
				fmt.Sprintf("failed to filter datacenters by email: %v", err))
		}
	}

	return filterDCsByName(dcs, datacenterToGet)
}

// GetEndpointForProvider an HTTP endpoint that returns a specified apiv1.Datacenter for a specified provider.
func GetEndpointForProvider(seedsGetter provider.SeedsGetter, userInfoGetter provider.UserInfoGetter) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(forProviderDCGetReq)
		if !ok {
			return nil, utilerrors.NewBadRequest("invalid request")
		}

		seeds, err := seedsGetter()
		if err != nil {
			return nil, utilerrors.New(http.StatusInternalServerError, fmt.Sprintf("failed to list seeds: %v", err))
		}

		userInfo, err := userInfoGetter(ctx, "")
		if err != nil {
			return nil, common.KubernetesErrorToHTTPError(err)
		}

		// Get the DCs and immediately filter them out for the provider.
		dcs := filterDCsByProvider(req.Provider, getAPIDCsFromSeedMap(seeds))

		// Filter out dc restricted by email if user is not admin
		if !userInfo.IsAdmin {
			dcs, err = filterDCsByEmail(userInfo, dcs)
			if err != nil {
				return apiv1.Datacenter{}, utilerrors.New(http.StatusInternalServerError,
					fmt.Sprintf("failed to filter datacenters by email: %v", err))
			}
		}

		return filterDCsByName(dcs, req.Datacenter)
	}
}

func filterDCsByName(dcs []apiv1.Datacenter, dcName string) (apiv1.Datacenter, error) {
	var foundDCs []apiv1.Datacenter
	for _, unfilteredDC := range dcs {
		if unfilteredDC.Metadata.Name == dcName {
			foundDCs = append(foundDCs, unfilteredDC)
		}
	}

	if n := len(foundDCs); n > 1 {
		return apiv1.Datacenter{}, fmt.Errorf("did not find one but %d datacenters for name %q", n, dcName)
	}
	if len(foundDCs) == 0 {
		return apiv1.Datacenter{}, utilerrors.NewNotFound("datacenter", dcName)
	}

	return foundDCs[0], nil
}

func filterDCsByEmail(userInfo *provider.UserInfo, list []apiv1.Datacenter) ([]apiv1.Datacenter, error) {
	var result []apiv1.Datacenter

	for _, dc := range list {
		matches, err := email.MatchesRequirements(userInfo.Email, dc.Spec.RequiredEmails)
		if err != nil {
			return nil, err
		}

		if matches {
			result = append(result, dc)
		}
	}

	return result, nil
}

func getAPIDCsFromSeedMap(seeds map[string]*kubermaticv1.Seed) []apiv1.Datacenter {
	var foundDCs []apiv1.Datacenter
	for _, seed := range seeds {
		foundDCs = append(foundDCs, getAPIDCsFromSeed(seed)...)
	}
	return foundDCs
}

// TODO(lsviben) - check if a "seed" dc is needed + if whole metadata is needed for DC, maybe we only need the name.
func getAPIDCsFromSeed(seed *kubermaticv1.Seed) []apiv1.Datacenter {
	var foundDCs []apiv1.Datacenter
	for datacenterName, datacenter := range seed.Spec.Datacenters {
		spec, err := ConvertInternalDCToExternalSpec(datacenter.DeepCopy(), seed.Name)
		if err != nil {
			log.Logger.Errorf("api spec error in dc %q: %v", datacenterName, err)
			continue
		}
		foundDCs = append(foundDCs, apiv1.Datacenter{
			Metadata: apiv1.DatacenterMeta{
				Name: datacenterName,
			},
			Spec: *spec,
		})
	}
	return foundDCs
}

// CreateEndpoint an HTTP endpoint that creates the specified apiv1.Datacenter.
func CreateEndpoint(seedsGetter provider.SeedsGetter, userInfoGetter provider.UserInfoGetter, masterClient ctrlruntimeclient.Client) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(createDCReq)
		if !ok {
			return nil, utilerrors.NewBadRequest("invalid request")
		}

		err := req.validate()
		if err != nil {
			return nil, utilerrors.New(http.StatusBadRequest, fmt.Sprintf("Validation error: %v", err))
		}

		if err := validateUser(ctx, userInfoGetter); err != nil {
			return nil, err
		}

		// Get the seed in which the dc should be created
		seeds, err := seedsGetter()
		if err != nil {
			return nil, utilerrors.New(http.StatusInternalServerError, fmt.Sprintf("failed to list seeds: %v", err))
		}
		seed, ok := seeds[req.Body.Spec.Seed]
		if !ok {
			return nil, utilerrors.New(http.StatusBadRequest,
				fmt.Sprintf("Bad request: seed %q does not exist", req.Body.Spec.Seed))
		}

		// Check if dc already exists
		if _, ok = seed.Spec.Datacenters[req.Body.Name]; ok {
			return nil, utilerrors.New(http.StatusBadRequest,
				fmt.Sprintf("Bad request: datacenter %q already exists", req.Body.Name))
		}

		// Add DC, update seed
		if seed.Spec.Datacenters == nil {
			seed.Spec.Datacenters = map[string]kubermaticv1.Datacenter{}
		}
		seed.Spec.Datacenters[req.Body.Name] = convertExternalDCToInternal(&req.Body.Spec)

		if err = masterClient.Update(ctx, seed); err != nil {
			return nil, utilerrors.New(http.StatusInternalServerError,
				fmt.Sprintf("failed to update seed %q datacenter %q: %v", seed.Name, req.Body.Name, err))
		}

		return &apiv1.Datacenter{
			Metadata: apiv1.DatacenterMeta{
				Name: req.Body.Name,
			},
			Spec: req.Body.Spec,
		}, nil
	}
}

// UpdateEndpoint an HTTP endpoint that updates the specified apiv1.Datacenter.
func UpdateEndpoint(seedsGetter provider.SeedsGetter, userInfoGetter provider.UserInfoGetter,
	masterClient ctrlruntimeclient.Client) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(updateDCReq)
		if !ok {
			return nil, utilerrors.NewBadRequest("invalid request")
		}

		err := req.validate()
		if err != nil {
			return nil, utilerrors.New(http.StatusBadRequest, fmt.Sprintf("Validation error: %v", err))
		}

		if err := validateUser(ctx, userInfoGetter); err != nil {
			return nil, err
		}

		// Get the seed in which the dc should be updated
		seeds, err := seedsGetter()
		if err != nil {
			return nil, utilerrors.New(http.StatusInternalServerError, fmt.Sprintf("failed to list seeds: %v", err))
		}
		seed, ok := seeds[req.Body.Spec.Seed]
		if !ok {
			return nil, utilerrors.New(http.StatusBadRequest,
				fmt.Sprintf("Bad request: seed %q does not exist", req.Body.Spec.Seed))
		}

		// get the dc to update
		if _, ok := seed.Spec.Datacenters[req.DCToUpdate]; !ok {
			return nil, utilerrors.New(http.StatusBadRequest,
				fmt.Sprintf("Bad request: datacenter %q does not exists", req.DCToUpdate))
		}

		// Do an extra check if name changed and remove old dc
		if !strings.EqualFold(req.DCToUpdate, req.Body.Name) {
			if _, ok := seed.Spec.Datacenters[req.Body.Name]; ok {
				return nil, utilerrors.New(http.StatusBadRequest,
					fmt.Sprintf("Bad request: cannot change %q datacenter name to %q as it already exists",
						req.DCToUpdate, req.Body.Name))
			}
			delete(seed.Spec.Datacenters, req.DCToUpdate)
		}
		seed.Spec.Datacenters[req.Body.Name] = convertExternalDCToInternal(&req.Body.Spec)

		if err = masterClient.Update(ctx, seed); err != nil {
			return nil, utilerrors.New(http.StatusInternalServerError,
				fmt.Sprintf("failed to update seed %q datacenter %q: %v", seed.Name, req.DCToUpdate, err))
		}

		return &apiv1.Datacenter{
			Metadata: apiv1.DatacenterMeta{
				Name: req.Body.Name,
			},
			Spec: req.Body.Spec,
		}, nil
	}
}

// PatchEndpoint an HTTP endpoint that patches the specified apiv1.Datacenter.
func PatchEndpoint(seedsGetter provider.SeedsGetter, userInfoGetter provider.UserInfoGetter,
	masterClient ctrlruntimeclient.Client) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(patchDCReq)
		if !ok {
			return nil, utilerrors.NewBadRequest("invalid request")
		}

		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := validateUser(ctx, userInfoGetter); err != nil {
			return nil, err
		}

		// Get the seed in which the dc should be updated
		seeds, err := seedsGetter()
		if err != nil {
			return nil, utilerrors.New(http.StatusInternalServerError, fmt.Sprintf("failed to list seeds: %v", err))
		}
		seed, ok := seeds[req.Seed]
		if !ok {
			return nil, utilerrors.New(http.StatusBadRequest,
				fmt.Sprintf("Bad request: seed %q does not exist", req.Seed))
		}

		// get the dc to update
		currentDC, ok := seed.Spec.Datacenters[req.DCToPatch]
		if !ok {
			return nil, utilerrors.New(http.StatusBadRequest,
				fmt.Sprintf("Bad request: datacenter %q does not exists", req.DCToPatch))
		}

		// patch
		currentAPIDC, err := convertInternalDCToExternal(&currentDC, req.DCToPatch, req.Seed)
		if err != nil {
			return nil, utilerrors.New(http.StatusInternalServerError, fmt.Sprintf("failed to convert current dc: %v", err))
		}

		currentDCJSON, err := json.Marshal(currentAPIDC)
		if err != nil {
			return nil, utilerrors.New(http.StatusInternalServerError, fmt.Sprintf("failed to marshal current dc: %v", err))
		}

		patchedJSON, err := jsonpatch.MergePatch(currentDCJSON, req.Patch)
		if err != nil {
			return nil, utilerrors.New(http.StatusInternalServerError, fmt.Sprintf("failed to merge patch dc: %v", err))
		}

		var patched apiv1.Datacenter
		err = json.Unmarshal(patchedJSON, &patched)
		if err != nil {
			return nil, utilerrors.New(http.StatusInternalServerError, fmt.Sprintf("failed to unmarshal patched dc: %v", err))
		}

		// validate patched spec
		if err := validateProvider(&patched.Spec); err != nil {
			return nil, utilerrors.New(http.StatusBadRequest, fmt.Sprintf("patched dc validation failed: %v", err))
		}
		kubermaticPatched := convertExternalDCToInternal(&patched.Spec)

		// As provider field is extracted from providers, we need to make sure its set properly
		providerName, err := kubermaticv1helper.DatacenterCloudProviderName(kubermaticPatched.Spec.DeepCopy())
		if err != nil {
			return nil, utilerrors.New(http.StatusInternalServerError, fmt.Sprintf("failed extracting provider name from dc: %v", err))
		}
		patched.Spec.Provider = providerName

		dcName := req.DCToPatch
		// Do an extra check if name changed and remove old dc
		if !strings.EqualFold(req.DCToPatch, patched.Metadata.Name) {
			if _, ok := seed.Spec.Datacenters[patched.Metadata.Name]; ok {
				return nil, utilerrors.New(http.StatusBadRequest,
					fmt.Sprintf("Bad request: cannot change %q datacenter name to %q as it already exists",
						req.DCToPatch, patched.Metadata.Name))
			}
			delete(seed.Spec.Datacenters, req.DCToPatch)
			dcName = patched.Metadata.Name
		}

		seed.Spec.Datacenters[dcName] = kubermaticPatched

		if err = masterClient.Update(ctx, seed); err != nil {
			return nil, utilerrors.New(http.StatusInternalServerError,
				fmt.Sprintf("failed to update seed %q datacenter %q: %v", seed.Name, req.DCToPatch, err))
		}

		return &patched, nil
	}
}

// DeleteEndpoint an HTTP endpoint that deletes the specified apiv1.Datacenter.
func DeleteEndpoint(seedsGetter provider.SeedsGetter, userInfoGetter provider.UserInfoGetter,
	masterClient ctrlruntimeclient.Client) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(deleteDCReq)
		if !ok {
			return nil, utilerrors.NewBadRequest("invalid request")
		}

		if err := validateUser(ctx, userInfoGetter); err != nil {
			return nil, err
		}

		// Get the seed in which the dc should be deleted
		seeds, err := seedsGetter()
		if err != nil {
			return nil, utilerrors.New(http.StatusInternalServerError, fmt.Sprintf("failed to list seeds: %v", err))
		}
		seed, ok := seeds[req.Seed]
		if !ok {
			return nil, utilerrors.New(http.StatusBadRequest,
				fmt.Sprintf("Bad request: seed %q does not exist", req.Seed))
		}

		// get the dc to delete
		if _, ok := seed.Spec.Datacenters[req.DC]; !ok {
			return nil, utilerrors.New(http.StatusBadRequest,
				fmt.Sprintf("Bad request: datacenter %q does not exists", req.DC))
		}
		delete(seed.Spec.Datacenters, req.DC)

		if err = masterClient.Update(ctx, seed); err != nil {
			return nil, utilerrors.New(http.StatusInternalServerError,
				fmt.Sprintf("failed to delete seed %q datacenter %q: %v", seed.Name, req.DC, err))
		}

		return nil, nil
	}
}

// ListEndpointForSeed an HTTP endpoint that returns a list of apiv1.Datacenter for the specified seed.
func ListEndpointForSeed(seedsGetter provider.SeedsGetter, userInfoGetter provider.UserInfoGetter) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(listDCForSeedReq)
		if !ok {
			return nil, utilerrors.NewBadRequest("invalid request")
		}

		seeds, err := seedsGetter()
		if err != nil {
			return nil, utilerrors.New(http.StatusInternalServerError, fmt.Sprintf("failed to list seeds: %v", err))
		}

		userInfo, err := userInfoGetter(ctx, "")
		if err != nil {
			return nil, common.KubernetesErrorToHTTPError(err)
		}

		seed, ok := seeds[req.Seed]
		if !ok {
			return nil, utilerrors.NewNotFound("seed", req.Seed)
		}

		// Get the DCs and immediately filter out the ones restricted by e-mail domain if user is not admin
		dcs := getAPIDCsFromSeed(seed)
		if !userInfo.IsAdmin {
			dcs, err = filterDCsByEmail(userInfo, dcs)
			if err != nil {
				return apiv1.Datacenter{}, utilerrors.New(http.StatusInternalServerError,
					fmt.Sprintf("failed to filter datacenters by email: %v", err))
			}
		}

		// Maintain a stable order. We do not check for duplicate names here
		sort.SliceStable(dcs, func(i, j int) bool {
			return dcs[i].Metadata.Name < dcs[j].Metadata.Name
		})

		return dcs, nil
	}
}

// GetEndpointForSeed an HTTP endpoint that returns a specified apiv1.Datacenter in the specified seed.
func GetEndpointForSeed(seedsGetter provider.SeedsGetter, userInfoGetter provider.UserInfoGetter) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(getDCForSeedReq)
		if !ok {
			return nil, utilerrors.NewBadRequest("invalid request")
		}

		seeds, err := seedsGetter()
		if err != nil {
			return nil, utilerrors.New(http.StatusInternalServerError, fmt.Sprintf("failed to list seeds: %v", err))
		}

		userInfo, err := userInfoGetter(ctx, "")
		if err != nil {
			return nil, common.KubernetesErrorToHTTPError(err)
		}

		seed, ok := seeds[req.Seed]
		if !ok {
			return nil, utilerrors.NewNotFound("seed", req.Seed)
		}

		// Get the DCs and immediately filter out the ones restricted by e-mail domain if user is not admin
		dcs := getAPIDCsFromSeed(seed)
		if !userInfo.IsAdmin {
			dcs, err = filterDCsByEmail(userInfo, dcs)
			if err != nil {
				return apiv1.Datacenter{}, utilerrors.New(http.StatusInternalServerError,
					fmt.Sprintf("failed to filter datacenters by email: %v", err))
			}
		}

		return filterDCsByName(dcs, req.DC)
	}
}

func validateUser(ctx context.Context, userInfoGetter provider.UserInfoGetter) error {
	userInfo, err := userInfoGetter(ctx, "")
	if err != nil {
		return common.KubernetesErrorToHTTPError(err)
	}

	if !userInfo.IsAdmin {
		return utilerrors.New(http.StatusForbidden,
			fmt.Sprintf("forbidden: \"%s\" doesn't have admin rights", userInfo.Email))
	}
	return nil
}

func convertInternalDCToExternal(dc *kubermaticv1.Datacenter, dcName, seedName string) (*apiv1.Datacenter, error) {
	dcSpec, err := ConvertInternalDCToExternalSpec(dc, seedName)
	if err != nil {
		return nil, err
	}

	return &apiv1.Datacenter{
		Metadata: apiv1.DatacenterMeta{
			Name: dcName,
		},
		Spec: *dcSpec,
	}, nil
}

func ConvertInternalDCToExternalSpec(dc *kubermaticv1.Datacenter, seedName string) (*apiv1.DatacenterSpec, error) {
	p, err := kubermaticv1helper.DatacenterCloudProviderName(dc.Spec.DeepCopy())
	if err != nil {
		return nil, err
	}

	nodeSettings := kubermaticv1.NodeSettings{}
	if dc.Node != nil {
		nodeSettings = *dc.Node
	}

	return &apiv1.DatacenterSpec{
		Seed:                           seedName,
		Location:                       dc.Location,
		Country:                        dc.Country,
		Provider:                       p,
		Node:                           nodeSettings,
		Digitalocean:                   dc.Spec.Digitalocean,
		AWS:                            dc.Spec.AWS,
		BringYourOwn:                   dc.Spec.BringYourOwn,
		Openstack:                      dc.Spec.Openstack,
		Hetzner:                        dc.Spec.Hetzner,
		VSphere:                        dc.Spec.VSphere,
		Baremetal:                      dc.Spec.Baremetal,
		Azure:                          dc.Spec.Azure,
		Edge:                           dc.Spec.Edge,
		Packet:                         dc.Spec.Packet,
		GCP:                            dc.Spec.GCP,
		Kubevirt:                       dc.Spec.Kubevirt,
		Alibaba:                        dc.Spec.Alibaba,
		Anexia:                         dc.Spec.Anexia,
		Nutanix:                        dc.Spec.Nutanix,
		VMwareCloudDirector:            dc.Spec.VMwareCloudDirector,
		Fake:                           dc.Spec.Fake,
		RequiredEmails:                 dc.Spec.RequiredEmails,
		EnforceAuditLogging:            dc.Spec.EnforceAuditLogging,
		EnforcedAuditWebhookSettings:   dc.Spec.EnforcedAuditWebhookSettings,
		EnforcePodSecurityPolicy:       dc.Spec.EnforcePodSecurityPolicy,
		DefaultOperatingSystemProfiles: dc.Spec.DefaultOperatingSystemProfiles,
		KubeLB:                         dc.Spec.KubeLB,
		IPv6Enabled:                    dc.IsIPv6Enabled(kubermaticv1.ProviderType(p)),
		MachineFlavorFilter:            dc.Spec.MachineFlavorFilter,
		DisableCSIDriver:               dc.Spec.DisableCSIDriver,
	}, nil
}

func convertExternalDCToInternal(datacenter *apiv1.DatacenterSpec) kubermaticv1.Datacenter {
	return kubermaticv1.Datacenter{
		Country:  datacenter.Country,
		Location: datacenter.Location,
		Node:     &datacenter.Node,
		Spec: kubermaticv1.DatacenterSpec{
			Digitalocean:                 datacenter.Digitalocean,
			BringYourOwn:                 datacenter.BringYourOwn,
			AWS:                          datacenter.AWS,
			Azure:                        datacenter.Azure,
			Edge:                         datacenter.Edge,
			Openstack:                    datacenter.Openstack,
			Packet:                       datacenter.Packet,
			Hetzner:                      datacenter.Hetzner,
			VSphere:                      datacenter.VSphere,
			GCP:                          datacenter.GCP,
			Kubevirt:                     datacenter.Kubevirt,
			Alibaba:                      datacenter.Alibaba,
			Anexia:                       datacenter.Anexia,
			Nutanix:                      datacenter.Nutanix,
			VMwareCloudDirector:          datacenter.VMwareCloudDirector,
			Fake:                         datacenter.Fake,
			RequiredEmails:               datacenter.RequiredEmails,
			EnforceAuditLogging:          datacenter.EnforceAuditLogging,
			EnforcedAuditWebhookSettings: datacenter.EnforcedAuditWebhookSettings,
			EnforcePodSecurityPolicy:     datacenter.EnforcePodSecurityPolicy,
			MachineFlavorFilter:          datacenter.MachineFlavorFilter,
		},
	}
}

// LegacyDCReq represent a request for datacenter specific data
// swagger:parameters getDatacenter
type LegacyDCReq struct {
	// in: path
	// required: true
	DC string `json:"dc"`
}

// GetDC returns the name of the datacenter in the request.
func (req LegacyDCReq) GetDC() string {
	return req.DC
}

// DecodeLegacyDcReq decodes http request into LegacyDCReq.
func DecodeLegacyDcReq(c context.Context, r *http.Request) (interface{}, error) {
	var req LegacyDCReq

	req.DC = mux.Vars(r)["dc"]
	return req, nil
}

// listDCForSeedReq represents a request for datacenters list in the specified seed
// swagger:parameters listDCForSeed
type listDCForSeedReq struct {
	// in: path
	// required: true
	Seed string `json:"seed_name"`
}

// DecodeListDCForSeedReq decodes http request into listDCForSeedReq.
func DecodeListDCForSeedReq(c context.Context, r *http.Request) (interface{}, error) {
	var req listDCForSeedReq

	req.Seed = mux.Vars(r)["seed_name"]
	if req.Seed == "" {
		return nil, fmt.Errorf("'seed_name' parameter is required but was not provided")
	}
	return req, nil
}

// getDCForSeedReq represents a request for a datacenter in the specified seed
// swagger:parameters getDCForSeed
type getDCForSeedReq struct {
	// in: path
	// required: true
	Seed string `json:"seed_name"`
	// in: path
	// required: true
	DC string `json:"dc"`
}

// DecodeGetDCForSeedReq decodes http request into getDCForSeedReq.
func DecodeGetDCForSeedReq(c context.Context, r *http.Request) (interface{}, error) {
	var req getDCForSeedReq

	req.Seed = mux.Vars(r)["seed_name"]
	if req.Seed == "" {
		return nil, fmt.Errorf("'seed_name' parameter is required but was not provided")
	}
	req.DC = mux.Vars(r)["dc"]
	if req.DC == "" {
		return nil, fmt.Errorf("'dc' parameter is required but was not provided")
	}

	return req, nil
}

// forProviderDCListReq defines HTTP request for ListDCForProvider
// swagger:parameters listDCForProvider
type forProviderDCListReq struct {
	// in: path
	// required: true
	Provider string `json:"provider_name"`
}

// DecodeForProviderDCListReq decodes http request into forProviderDCListReq.
func DecodeForProviderDCListReq(c context.Context, r *http.Request) (interface{}, error) {
	var req forProviderDCListReq

	req.Provider = mux.Vars(r)["provider_name"]
	if req.Provider == "" {
		return nil, fmt.Errorf("'provider_name' parameter is required but was not provided")
	}
	return req, nil
}

// forProviderDCGetReq defines HTTP request for GetDCForProvider
// swagger:parameters getDCForProvider
type forProviderDCGetReq struct {
	// in: path
	// required: true
	Provider string `json:"provider_name"`
	// in: path
	// required: true
	Datacenter string `json:"dc"`
}

// DecodeForProviderDCGetReq decodes http request into forProviderDCGetReq.
func DecodeForProviderDCGetReq(c context.Context, r *http.Request) (interface{}, error) {
	var req forProviderDCGetReq

	req.Provider = mux.Vars(r)["provider_name"]
	if req.Provider == "" {
		return nil, fmt.Errorf("'provider_name' parameter is required but was not provided")
	}

	req.Datacenter = mux.Vars(r)["dc"]
	if req.Datacenter == "" {
		return nil, fmt.Errorf("'dc' parameter is required but was not provided")
	}
	return req, nil
}

// createDCReq defines HTTP request for CreateDC
// swagger:parameters createDC
type createDCReq struct {
	// in: path
	// required: true
	Seed string `json:"seed_name"`
	// in: body
	Body struct {
		Name string               `json:"name"`
		Spec apiv1.DatacenterSpec `json:"spec"`
	}
}

func (req createDCReq) validate() error {
	if err := validateProvider(&req.Body.Spec); err != nil {
		return err
	}

	if !strings.EqualFold(req.Seed, req.Body.Spec.Seed) {
		return fmt.Errorf("path seed %q and request seed %q not equal", req.Seed, req.Body.Spec.Seed)
	}

	return nil
}

// DecodeCreateDCReq decodes http request into createDCReq.
func DecodeCreateDCReq(c context.Context, r *http.Request) (interface{}, error) {
	var req createDCReq

	req.Seed = mux.Vars(r)["seed_name"]
	if req.Seed == "" {
		return nil, fmt.Errorf("'seed_name' parameter is required but was not provided")
	}

	if err := json.NewDecoder(r.Body).Decode(&req.Body); err != nil {
		return nil, err
	}
	return req, nil
}

// updateDCReq defines HTTP request for UpdateDC
// swagger:parameters updateDC
type updateDCReq struct {
	createDCReq
	// in: path
	// required: true
	DCToUpdate string `json:"dc"`
}

// DecodeUpdateDCReq decodes http request into updateDCReq.
func DecodeUpdateDCReq(c context.Context, r *http.Request) (interface{}, error) {
	var req updateDCReq

	createReq, err := DecodeCreateDCReq(c, r)
	if err != nil {
		return nil, err
	}
	req.createDCReq = createReq.(createDCReq)

	req.DCToUpdate = mux.Vars(r)["dc"]
	if req.DCToUpdate == "" {
		return nil, fmt.Errorf("'dc' parameter is required but was not provided")
	}

	return req, nil
}

// patchDCReq defines HTTP request for PatchDC
// swagger:parameters patchDC
type patchDCReq struct {
	// in: body
	Patch json.RawMessage
	// in: path
	// required: true
	DCToPatch string `json:"dc"`
	// in: path
	// required: true
	Seed string `json:"seed_name"`
}

func (req patchDCReq) validate() error {
	var seedValidator struct {
		Spec struct {
			Seed string `json:"seed"`
		} `json:"spec"`
	}

	err := json.Unmarshal(req.Patch, &seedValidator)
	if err != nil {
		return utilerrors.New(http.StatusBadRequest, fmt.Sprintf("failed to validate patch body seed: %v", err))
	}

	if seedValidator.Spec.Seed != "" && !strings.EqualFold(seedValidator.Spec.Seed, req.Seed) {
		return utilerrors.New(http.StatusBadRequest,
			fmt.Sprintf("patched dc validation failed: path seed name %q has to be equal to patch seed name %q",
				req.Seed, seedValidator.Spec.Seed))
	}
	return nil
}

// DecodePatchDCReq decodes http request into patchDCReq.
func DecodePatchDCReq(c context.Context, r *http.Request) (interface{}, error) {
	var req patchDCReq

	var err error
	if req.Patch, err = io.ReadAll(r.Body); err != nil {
		return nil, err
	}

	req.DCToPatch = mux.Vars(r)["dc"]
	if req.DCToPatch == "" {
		return nil, fmt.Errorf("'dc' parameter is required but was not provided")
	}

	req.Seed = mux.Vars(r)["seed_name"]
	if req.Seed == "" {
		return nil, fmt.Errorf("'seed_name' parameter is required but was not provided")
	}

	return req, nil
}

func GetProviderName(dcSpec *apiv1.DatacenterSpec) (kubermaticv1.ProviderType, error) {
	var providerNames []kubermaticv1.ProviderType

	if dcSpec.Alibaba != nil {
		providerNames = append(providerNames, kubermaticv1.AlibabaCloudProvider)
	}
	if dcSpec.BringYourOwn != nil {
		providerNames = append(providerNames, kubermaticv1.BringYourOwnCloudProvider)
	}
	if dcSpec.Digitalocean != nil {
		providerNames = append(providerNames, kubermaticv1.DigitaloceanCloudProvider)
	}
	if dcSpec.AWS != nil {
		providerNames = append(providerNames, kubermaticv1.AWSCloudProvider)
	}
	if dcSpec.Openstack != nil {
		providerNames = append(providerNames, kubermaticv1.OpenstackCloudProvider)
	}
	if dcSpec.Packet != nil {
		providerNames = append(providerNames, kubermaticv1.PacketCloudProvider)
	}
	if dcSpec.Hetzner != nil {
		providerNames = append(providerNames, kubermaticv1.HetznerCloudProvider)
	}
	if dcSpec.VSphere != nil {
		providerNames = append(providerNames, kubermaticv1.VSphereCloudProvider)
	}
	if dcSpec.Baremetal != nil {
		providerNames = append(providerNames, kubermaticv1.BaremetalCloudProvider)
	}
	if dcSpec.Azure != nil {
		providerNames = append(providerNames, kubermaticv1.AzureCloudProvider)
	}
	if dcSpec.Edge != nil {
		providerNames = append(providerNames, kubermaticv1.EdgeCloudProvider)
	}
	if dcSpec.GCP != nil {
		providerNames = append(providerNames, kubermaticv1.GCPCloudProvider)
	}
	if dcSpec.Kubevirt != nil {
		providerNames = append(providerNames, kubermaticv1.KubevirtCloudProvider)
	}
	if dcSpec.Anexia != nil {
		providerNames = append(providerNames, kubermaticv1.AnexiaCloudProvider)
	}
	if dcSpec.Nutanix != nil {
		providerNames = append(providerNames, kubermaticv1.NutanixCloudProvider)
	}
	if dcSpec.VMwareCloudDirector != nil {
		providerNames = append(providerNames, kubermaticv1.VMwareCloudDirectorCloudProvider)
	}
	if dcSpec.Fake != nil {
		providerNames = append(providerNames, kubermaticv1.FakeCloudProvider)
	}
	if len(providerNames) != 1 {
		return "", fmt.Errorf("only one DC provider should be specified, got: %v", providerNames)
	}
	return providerNames[0], nil
}

func validateProvider(dcSpec *apiv1.DatacenterSpec) error {
	_, err := GetProviderName(dcSpec)
	return err
}

// deleteDCReq defines HTTP request for DeleteDC
// swagger:parameters deleteDC
type deleteDCReq struct {
	// in: path
	// required: true
	Seed string `json:"seed_name"`
	// in: path
	// required: true
	DC string `json:"dc"`
}

// DecodeDeleteDCReq decodes http request into deleteDCReq.
func DecodeDeleteDCReq(c context.Context, r *http.Request) (interface{}, error) {
	var req deleteDCReq

	req.Seed = mux.Vars(r)["seed_name"]
	if req.Seed == "" {
		return nil, fmt.Errorf("'seed_name' parameter is required but was not provided")
	}

	req.DC = mux.Vars(r)["dc"]
	if req.DC == "" {
		return nil, fmt.Errorf("'dc' parameter is required but was not provided")
	}

	return req, nil
}
