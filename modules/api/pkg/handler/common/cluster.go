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

package common

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	jsonpatch "github.com/evanphx/json-patch"
	"go.uber.org/zap"

	apiv1 "k8c.io/dashboard/v2/pkg/api/v1"
	"k8c.io/dashboard/v2/pkg/handler/middleware"
	"k8c.io/dashboard/v2/pkg/handler/v1/common"
	"k8c.io/dashboard/v2/pkg/handler/v1/label"
	"k8c.io/dashboard/v2/pkg/provider"
	kubernetesprovider "k8c.io/dashboard/v2/pkg/provider/kubernetes"
	"k8c.io/dashboard/v2/pkg/resources/cluster"
	"k8c.io/dashboard/v2/pkg/resources/machine"
	appskubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/apps.kubermatic/v1"
	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	kubermaticv1helper "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1/helper"
	"k8c.io/kubermatic/v2/pkg/defaulting"
	"k8c.io/kubermatic/v2/pkg/features"
	kuberneteshelper "k8c.io/kubermatic/v2/pkg/kubernetes"
	kubermaticlog "k8c.io/kubermatic/v2/pkg/log"
	clustermutation "k8c.io/kubermatic/v2/pkg/mutation/cluster"
	kubermaticprovider "k8c.io/kubermatic/v2/pkg/provider"
	"k8c.io/kubermatic/v2/pkg/resources"
	utilcluster "k8c.io/kubermatic/v2/pkg/util/cluster"
	utilerrors "k8c.io/kubermatic/v2/pkg/util/errors"
	"k8c.io/kubermatic/v2/pkg/validation"
	"k8c.io/kubermatic/v2/pkg/version"
	clusterv1alpha1 "k8c.io/machine-controller/sdk/apis/cluster/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/metrics/pkg/apis/metrics/v1beta1"
	"k8s.io/utils/ptr"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// ClusterTypes holds a list of supported cluster types.
var ClusterTypes = sets.New(apiv1.KubernetesClusterType)

// patchClusterSpec is equivalent of ClusterSpec but it uses default JSON marshalling method instead of custom
// MarshalJSON defined for ClusterSpec type. This means it should be only used internally as it may contain
// sensitive cloud provider authentication data.
type patchClusterSpec apiv1.ClusterSpec

// patchCluster is equivalent of Cluster but it uses patchClusterSpec instead of original ClusterSpec.
// This means it should be only used internally as it may contain sensitive cloud provider authentication data.
type patchCluster struct {
	apiv1.Cluster `json:",inline"`
	Spec          patchClusterSpec `json:"spec"`
}

func CreateEndpoint(
	ctx context.Context,
	projectID string,
	body apiv1.CreateClusterSpec,
	projectProvider provider.ProjectProvider,
	privilegedProjectProvider provider.PrivilegedProjectProvider,
	seedsGetter provider.SeedsGetter,
	credentialManager provider.PresetProvider,
	exposeStrategy kubermaticv1.ExposeStrategy,
	userInfoGetter provider.UserInfoGetter,
	caBundle *x509.CertPool,
	configGetter provider.KubermaticConfigurationGetter,
	features features.FeatureGate,
	settingsProvider provider.SettingsProvider,
) (interface{}, error) {
	clusterProvider := ctx.Value(middleware.ClusterProviderContextKey).(provider.ClusterProvider)
	privilegedClusterProvider := ctx.Value(middleware.PrivilegedClusterProviderContextKey).(provider.PrivilegedClusterProvider)

	adminUserInfo, err := userInfoGetter(ctx, "")
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	_, dc, err := provider.DatacenterFromSeedMap(adminUserInfo, seedsGetter, body.Cluster.Spec.Cloud.DatacenterName)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	partialCluster, err := GenerateCluster(ctx, projectID, body, seedsGetter, credentialManager, exposeStrategy, userInfoGetter, caBundle, configGetter, features, settingsProvider)
	if err != nil {
		return nil, err
	}

	project, err := common.GetProject(ctx, userInfoGetter, projectProvider, privilegedProjectProvider, projectID, &provider.ProjectGetOptions{IncludeUninitialized: false})
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}
	existingClusters, err := clusterProvider.List(ctx, project, &provider.ClusterListOptions{ClusterSpecName: partialCluster.Spec.HumanReadableName})
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	if len(existingClusters.Items) > 0 {
		return nil, utilerrors.NewAlreadyExists("cluster", partialCluster.Spec.HumanReadableName)
	}

	newCluster, err := createNewCluster(ctx, userInfoGetter, clusterProvider, privilegedClusterProvider, project, partialCluster)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	log := kubermaticlog.Logger.With("cluster", newCluster.Name)

	config, err := configGetter(ctx)
	if err != nil {
		return nil, err
	}

	supportManager := version.NewFromConfiguration(config)

	// Block for up to 10 seconds to give the rbac controller time to create the bindings.
	// During that time we swallow all errors
	if err := wait.PollUntilContextTimeout(ctx, time.Second, 10*time.Second, true, func(ctx context.Context) (bool, error) {
		_, err := GetInternalCluster(ctx, userInfoGetter, clusterProvider, privilegedClusterProvider, project, projectID, newCluster.Name, &provider.ClusterGetOptions{})
		if err != nil {
			log.Debugw("Error when waiting for cluster to become ready after creation", zap.Error(err))
			return false, nil
		}
		return true, nil
	}); err != nil {
		log.Error("Timed out waiting for cluster to become ready")
		return ConvertInternalClusterToExternal(newCluster, dc, true, supportManager.GetIncompatibilities()...), utilerrors.New(http.StatusInternalServerError, "timed out waiting for cluster to become ready")
	}

	return ConvertInternalClusterToExternal(newCluster, dc, true, supportManager.GetIncompatibilities()...), nil
}

func GenerateCluster(
	ctx context.Context,
	projectID string,
	body apiv1.CreateClusterSpec,
	seedsGetter provider.SeedsGetter,
	credentialManager provider.PresetProvider,
	exposeStrategy kubermaticv1.ExposeStrategy,
	userInfoGetter provider.UserInfoGetter,
	caBundle *x509.CertPool,
	configGetter provider.KubermaticConfigurationGetter,
	features features.FeatureGate,
	settingsProvider provider.SettingsProvider,
) (*kubermaticv1.Cluster, error) {
	privilegedClusterProvider := ctx.Value(middleware.PrivilegedClusterProviderContextKey).(provider.PrivilegedClusterProvider)
	adminUserInfo, err := userInfoGetter(ctx, "")
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}
	seed, dc, err := provider.DatacenterFromSeedMap(adminUserInfo, seedsGetter, body.Cluster.Spec.Cloud.DatacenterName)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	config, err := configGetter(ctx)
	if err != nil {
		return nil, err
	}

	// Start filling cluster object.
	partialCluster := &kubermaticv1.Cluster{}
	partialCluster.Labels = body.Cluster.Labels
	if partialCluster.Labels == nil {
		partialCluster.Labels = make(map[string]string)
	}
	partialCluster.Annotations = make(map[string]string)
	if body.Cluster.Annotations != nil {
		partialCluster.Annotations = body.Cluster.Annotations
	}

	credentialName := body.Cluster.Credential
	if len(credentialName) > 0 {
		cloudSpec, err := credentialManager.SetCloudCredentials(ctx, adminUserInfo, projectID, credentialName, body.Cluster.Spec.Cloud, dc)
		if err != nil {
			return nil, utilerrors.NewBadRequest("invalid credentials: %v", err)
		}

		if checkIfPresetCustomized(ctx, projectID, *adminUserInfo, body.Cluster.Spec.Cloud, credentialManager, credentialName) {
			body.Cluster.Credential = ""
		} else {
			partialCluster.Labels[kubermaticv1.IsCredentialPresetLabelKey] = "true"
			partialCluster.Annotations[kubermaticv1.PresetNameAnnotation] = credentialName
		}
		body.Cluster.Spec.Cloud = *cloudSpec
	}

	// Fetch the defaulting ClusterTemplate.
	seedClient := privilegedClusterProvider.GetSeedClusterAdminRuntimeClient()
	defaultingTemplate, err := defaulting.GetDefaultingClusterTemplate(ctx, seedClient, seed)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	// Create the Cluster object.
	secretKeyGetter := kubermaticprovider.SecretKeySelectorValueFuncFactory(ctx, seedClient)
	spec, cloudProvider, err := cluster.Spec(ctx, body.Cluster, defaultingTemplate, seed, dc, config, secretKeyGetter, caBundle, features)
	if err != nil {
		return nil, utilerrors.NewBadRequest("invalid cluster: %v", err)
	}

	partialCluster.Spec = *spec

	if err := clustermutation.MutateCreate(partialCluster, config, seed, cloudProvider); err != nil {
		return nil, utilerrors.NewBadRequest("invalid cluster: %v", err)
	}

	versionManager := version.NewFromConfiguration(config)

	if errs := validation.ValidateNewClusterSpec(ctx, &partialCluster.Spec, dc, seed, cloudProvider, versionManager, features, nil).ToAggregate(); errs != nil {
		return nil, utilerrors.NewBadRequest("cluster validation failed: %v", errs)
	}

	if err = validation.ValidateUpdateWindow(partialCluster.Spec.UpdateWindow); err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	// Generate the name here so that it can be used below.
	partialCluster.Name = utilcluster.MakeClusterName()

	// Serialize initial machine deployment request into annotation if it is in the body and provider different than
	// BringYourOwn was selected. The request will be transformed into machine deployment by the controller once cluster
	// will be ready. To make it easier to determine if a machine deployment annotation has already been applied to
	// the user cluster (in case errors happen and the controller needs to re-reconcile), we ensure that the MD
	// has a proper name instead of relying on the GenerateName.
	if body.NodeDeployment != nil {
		isBYO, err := common.IsBringYourOwnProvider(spec.Cloud)
		if err != nil {
			return nil, utilerrors.NewBadRequest("cannot verify the provider due to an invalid spec: %v", err)
		}
		if !isBYO {
			if body.NodeDeployment.Name == "" {
				body.NodeDeployment.Name = fmt.Sprintf("%s-worker-%s", partialCluster.Name, rand.String(6))
			}

			// Convert NodeDeployment into a standard MachineDeployment; leave out the SSH keys as the
			// controller in KKP will apply the currently assigned keys automatically when processing
			// this annotation.
			partialCluster.Spec = *spec
			md, err := machine.Deployment(ctx, partialCluster, body.NodeDeployment, dc, nil, settingsProvider)
			if err != nil {
				return nil, fmt.Errorf("cannot create machine deployment data: %w", err)
			}

			data, err := json.Marshal(md)
			if err != nil {
				return nil, fmt.Errorf("cannot marshal initial machine deployment: %w", err)
			}
			partialCluster.Annotations[kubermaticv1.InitialMachineDeploymentRequestAnnotation] = string(data)
		}
	}

	// Serialize initial applications request into an annotation.
	// "initial-application-installation-controller" running in seed will transform this annotation, create the resultant
	// ApplicationInstallation, and then delete this annotation from the Cluster Object.

	// Ensure that application has a proper name instead of relying on the Generated Name. This makes it easier to
	// determine if an application annotation has already been processed by the corresponding controller and all the
	// resources(applications) created.
	for i, app := range body.Applications {
		if app.Name == "" {
			body.Applications[i].Name = fmt.Sprintf("%s-instance", app.Spec.ApplicationRef.Name)
		}
	}

	if len(body.Applications) > 0 {
		// Remove enforced applications since they are automatically installed by the controllers.
		apps := []apiv1.Application{}
		for _, app := range body.Applications {
			if value, ok := app.Annotations[appskubermaticv1.ApplicationEnforcedAnnotation]; !ok || value != "true" {
				apps = append(apps, app)
			}
		}
		data, err := json.Marshal(apps)
		if err != nil {
			return nil, fmt.Errorf("cannot marshal initial applications: %w", err)
		}
		partialCluster.Annotations[kubermaticv1.InitialApplicationInstallationsRequestAnnotation] = string(data)
	} else {
		// This is a workaround to ensure that if the request to create a cluster is originating from our UI, it's known that the user explicitly disabled
		// the default applications.
		partialCluster.Annotations[kubermaticv1.InitialApplicationInstallationsRequestAnnotation] = "[]"
	}

	// Propagate initial CNI values request annotation
	if value, ok := body.Cluster.Annotations[kubermaticv1.InitialCNIValuesRequestAnnotation]; ok {
		partialCluster.Annotations[kubermaticv1.InitialCNIValuesRequestAnnotation] = value
	}

	// Owning project ID must be set early, because it will be inherited by some child objects,
	// for example the credentials secret.
	partialCluster.Labels[kubermaticv1.ProjectIDLabelKey] = projectID

	if body.Cluster.Spec.EnableUserSSHKeyAgent == nil {
		partialCluster.Spec.EnableUserSSHKeyAgent = ptr.To(true)
	} else {
		partialCluster.Spec.EnableUserSSHKeyAgent = body.Cluster.Spec.EnableUserSSHKeyAgent
	}

	// add the cluster backup storage location if exist
	if body.Cluster.Spec.BackupConfig != nil {
		partialCluster.Spec.BackupConfig = body.Cluster.Spec.BackupConfig
	}
	return partialCluster, nil
}

func GetClusters(ctx context.Context, userInfoGetter provider.UserInfoGetter, clusterProvider provider.ClusterProvider, projectProvider provider.ProjectProvider, privilegedProjectProvider provider.PrivilegedProjectProvider, seedsGetter provider.SeedsGetter, projectID string, configGetter provider.KubermaticConfigurationGetter, includeMachineDeploymentCount bool) ([]*apiv1.Cluster, error) {
	project, err := common.GetProject(ctx, userInfoGetter, projectProvider, privilegedProjectProvider, projectID, nil)
	if err != nil {
		return nil, err
	}

	adminUserInfo, err := userInfoGetter(ctx, "")
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}
	clusters, err := clusterProvider.List(ctx, project, nil)
	if err != nil {
		return nil, err
	}
	config, err := configGetter(ctx)
	if err != nil {
		return nil, err
	}

	apiClusters := make([]*apiv1.Cluster, 0, len(clusters.Items))
	for _, internalCluster := range clusters.Items {
		_, dc, err := provider.DatacenterFromSeedMap(adminUserInfo, seedsGetter, internalCluster.Spec.Cloud.DatacenterName)
		if err != nil {
			// Ignore 403 errors and omit clusters with not accessible datacenters in the result.
			var errHttp *utilerrors.HTTPError
			if errors.As(err, &errHttp) && errHttp.StatusCode() == http.StatusForbidden {
				continue
			}
			return nil, common.KubernetesErrorToHTTPError(err)
		}

		apiClusters = append(apiClusters, ConvertInternalClusterToExternal(internalCluster.DeepCopy(), dc, true, version.NewFromConfiguration(config).GetIncompatibilities()...))
	}

	if includeMachineDeploymentCount {
		var wg sync.WaitGroup

		listErrs := make([]error, len(clusters.Items))

		for i, internalCluster := range clusters.Items {
			wg.Add(1)

			go func(pos int, cl kubermaticv1.Cluster) {
				defer wg.Done()

				machineDeployment, er := listClusterMachineDeployments(ctx, userInfoGetter, clusterProvider, &cl, projectID)
				if er != nil {
					listErrs[pos] = er
					return
				}

				apiClusters[pos].MachineDeploymentCount = ptr.To[int](len(machineDeployment.Items))
			}(i, internalCluster)
		}

		wg.Wait()

		for _, er := range listErrs {
			if er != nil {
				return nil, er
			}
		}
	}

	return apiClusters, nil
}

func listClusterMachineDeployments(ctx context.Context, userInfoGetter func(ctx context.Context, projectID string) (*provider.UserInfo, error), clusterProvider provider.ClusterProvider, cluster *kubermaticv1.Cluster, projectID string) (*clusterv1alpha1.MachineDeploymentList, error) {
	client, err := common.GetClusterClient(ctx, userInfoGetter, clusterProvider, cluster, projectID)
	if err != nil {
		return nil, err
	}

	machineDeployments := &clusterv1alpha1.MachineDeploymentList{}
	if err := client.List(ctx, machineDeployments, ctrlruntimeclient.InNamespace(metav1.NamespaceSystem)); err != nil {
		return nil, err
	}

	return machineDeployments, nil
}

// GetCluster returns the cluster for a given request.
func GetCluster(ctx context.Context, projectProvider provider.ProjectProvider, privilegedProjectProvider provider.PrivilegedProjectProvider, userInfoGetter provider.UserInfoGetter, projectID, clusterID string, options *provider.ClusterGetOptions) (*kubermaticv1.Cluster, error) {
	clusterProvider, ok := ctx.Value(middleware.ClusterProviderContextKey).(provider.ClusterProvider)
	if !ok {
		return nil, utilerrors.New(http.StatusInternalServerError, "no cluster in request")
	}
	privilegedClusterProvider := ctx.Value(middleware.PrivilegedClusterProviderContextKey).(provider.PrivilegedClusterProvider)
	project, err := common.GetProject(ctx, userInfoGetter, projectProvider, privilegedProjectProvider, projectID, nil)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	return GetInternalCluster(ctx, userInfoGetter, clusterProvider, privilegedClusterProvider, project, projectID, clusterID, options)
}

func GetEndpoint(ctx context.Context, projectProvider provider.ProjectProvider, privilegedProjectProvider provider.PrivilegedProjectProvider, seedsGetter provider.SeedsGetter, userInfoGetter provider.UserInfoGetter, projectID, clusterID string, configGetter provider.KubermaticConfigurationGetter) (interface{}, error) {
	cluster, err := GetCluster(ctx, projectProvider, privilegedProjectProvider, userInfoGetter, projectID, clusterID, nil)
	if err != nil {
		return nil, err
	}
	adminUserInfo, err := userInfoGetter(ctx, "")
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}
	_, dc, err := provider.DatacenterFromSeedMap(adminUserInfo, seedsGetter, cluster.Spec.Cloud.DatacenterName)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}
	config, err := configGetter(ctx)
	if err != nil {
		return nil, err
	}

	return ConvertInternalClusterToExternal(cluster, dc, true, version.NewFromConfiguration(config).GetIncompatibilities()...), nil
}

func DeleteEndpoint(ctx context.Context, userInfoGetter provider.UserInfoGetter, projectID, clusterID string, deleteVolumes, deleteLoadBalancers bool, sshKeyProvider provider.SSHKeyProvider, privilegedSSHKeyProvider provider.PrivilegedSSHKeyProvider, projectProvider provider.ProjectProvider, privilegedProjectProvider provider.PrivilegedProjectProvider) (interface{}, error) {
	clusterProvider := ctx.Value(middleware.ClusterProviderContextKey).(provider.ClusterProvider)
	privilegedClusterProvider := ctx.Value(middleware.PrivilegedClusterProviderContextKey).(provider.PrivilegedClusterProvider)

	project, err := common.GetProject(ctx, userInfoGetter, projectProvider, privilegedProjectProvider, projectID, nil)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	existingCluster, err := GetInternalCluster(ctx, userInfoGetter, clusterProvider, privilegedClusterProvider, project, projectID, clusterID, &provider.ClusterGetOptions{})
	if err != nil {
		return nil, err
	}

	// Use the NodeDeletionFinalizer to determine if the cluster was ever up, the LB and PV finalizers
	// will prevent cluster deletion if the APIserver was never created
	wasUpOnce := kuberneteshelper.HasFinalizer(existingCluster, kubermaticv1.NodeDeletionFinalizer)
	if wasUpOnce && (deleteVolumes || deleteLoadBalancers) {
		if deleteLoadBalancers {
			kuberneteshelper.AddFinalizer(existingCluster, kubermaticv1.InClusterLBCleanupFinalizer)
		}
		if deleteVolumes {
			kuberneteshelper.AddFinalizer(existingCluster, kubermaticv1.InClusterPVCleanupFinalizer)
		}
	}

	return nil, updateAndDeleteCluster(ctx, userInfoGetter, clusterProvider, privilegedClusterProvider, project, existingCluster)
}

func PatchEndpoint(
	ctx context.Context,
	userInfoGetter provider.UserInfoGetter,
	projectID string,
	clusterID string,
	patch json.RawMessage,
	seedsGetter provider.SeedsGetter,
	projectProvider provider.ProjectProvider,
	privilegedProjectProvider provider.PrivilegedProjectProvider,
	caBundle *x509.CertPool,
	configGetter provider.KubermaticConfigurationGetter,
	features features.FeatureGate,
	skipKubeletVersionValidation bool,
) (interface{}, error) {
	clusterProvider := ctx.Value(middleware.ClusterProviderContextKey).(provider.ClusterProvider)
	privilegedClusterProvider := ctx.Value(middleware.PrivilegedClusterProviderContextKey).(provider.PrivilegedClusterProvider)

	project, err := common.GetProject(ctx, userInfoGetter, projectProvider, privilegedProjectProvider, projectID, nil)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	oldInternalCluster, err := GetInternalCluster(ctx, userInfoGetter, clusterProvider, privilegedClusterProvider, project, projectID, clusterID, &provider.ClusterGetOptions{})
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	userInfo, err := userInfoGetter(ctx, "")
	if err != nil {
		return nil, utilerrors.New(http.StatusInternalServerError, err.Error())
	}
	seed, dc, err := provider.DatacenterFromSeedMap(userInfo, seedsGetter, oldInternalCluster.Spec.Cloud.DatacenterName)
	if err != nil {
		return nil, fmt.Errorf("error getting dc: %w", err)
	}
	config, err := configGetter(ctx)
	if err != nil {
		return nil, err
	}

	versionManager := version.NewFromConfiguration(config)

	// Converting to API type as it is the type exposed externally.
	externalCluster := ConvertInternalClusterToExternal(oldInternalCluster, dc, false, versionManager.GetIncompatibilities()...)

	// Changing the type to patchCluster as during marshalling it doesn't remove the cloud provider authentication
	// data that is required here for validation.
	externalClusterSpec := (patchClusterSpec)(externalCluster.Spec)
	clusterToPatch := patchCluster{
		Cluster: *externalCluster,
		Spec:    externalClusterSpec,
	}

	existingClusterJSON, err := json.Marshal(clusterToPatch)
	if err != nil {
		return nil, utilerrors.NewBadRequest("cannot decode existing cluster: %v", err)
	}

	patchedClusterJSON, err := jsonpatch.MergePatch(existingClusterJSON, patch)
	if err != nil {
		return nil, utilerrors.NewBadRequest("cannot patch cluster: %v", err)
	}

	var patchedCluster *apiv1.Cluster
	err = json.Unmarshal(patchedClusterJSON, &patchedCluster)
	if err != nil {
		return nil, utilerrors.NewBadRequest("cannot decode patched cluster: %v", err)
	}

	// Only specific fields from old internal cluster will be updated by a patch.
	// It prevents user from changing other fields like resource ID or version that should not be modified.
	newInternalCluster := oldInternalCluster.DeepCopy()
	newInternalCluster.Spec.HumanReadableName = patchedCluster.Name
	newInternalCluster.Labels = patchedCluster.Labels
	newInternalCluster.Annotations = patchedCluster.Annotations
	newInternalCluster.Spec.Cloud = patchedCluster.Spec.Cloud
	newInternalCluster.Spec.MachineNetworks = patchedCluster.Spec.MachineNetworks
	newInternalCluster.Spec.Version = patchedCluster.Spec.Version
	newInternalCluster.Spec.OIDC = patchedCluster.Spec.OIDC
	newInternalCluster.Spec.UsePodSecurityPolicyAdmissionPlugin = patchedCluster.Spec.UsePodSecurityPolicyAdmissionPlugin
	newInternalCluster.Spec.UsePodNodeSelectorAdmissionPlugin = patchedCluster.Spec.UsePodNodeSelectorAdmissionPlugin
	newInternalCluster.Spec.UseEventRateLimitAdmissionPlugin = patchedCluster.Spec.UseEventRateLimitAdmissionPlugin
	newInternalCluster.Spec.AdmissionPlugins = patchedCluster.Spec.AdmissionPlugins
	newInternalCluster.Spec.AuditLogging = patchedCluster.Spec.AuditLogging
	newInternalCluster.Spec.UpdateWindow = patchedCluster.Spec.UpdateWindow
	newInternalCluster.Spec.OPAIntegration = patchedCluster.Spec.OPAIntegration
	newInternalCluster.Spec.PodNodeSelectorAdmissionPluginConfig = patchedCluster.Spec.PodNodeSelectorAdmissionPluginConfig
	newInternalCluster.Spec.EventRateLimitConfig = patchedCluster.Spec.EventRateLimitConfig
	newInternalCluster.Spec.ServiceAccount = patchedCluster.Spec.ServiceAccount
	newInternalCluster.Spec.MLA = patchedCluster.Spec.MLA
	newInternalCluster.Spec.ContainerRuntime = patchedCluster.Spec.ContainerRuntime
	newInternalCluster.Spec.ClusterNetwork.KonnectivityEnabled = patchedCluster.Spec.ClusterNetwork.KonnectivityEnabled //nolint:staticcheck
	newInternalCluster.Spec.ClusterNetwork.ProxyMode = patchedCluster.Spec.ClusterNetwork.ProxyMode
	newInternalCluster.Spec.CNIPlugin = patchedCluster.Spec.CNIPlugin
	newInternalCluster.Spec.ExposeStrategy = patchedCluster.Spec.ExposeStrategy
	newInternalCluster.Spec.BackupConfig = patchedCluster.Spec.BackupConfig
	newInternalCluster.Spec.KubernetesDashboard = patchedCluster.Spec.KubernetesDashboard
	newInternalCluster.Spec.APIServerAllowedIPRanges = patchedCluster.Spec.APIServerAllowedIPRanges
	newInternalCluster.Spec.KubeLB = patchedCluster.Spec.KubeLB
	newInternalCluster.Spec.DisableCSIDriver = patchedCluster.Spec.DisableCSIDriver
	newInternalCluster.Spec.Kyverno = patchedCluster.Spec.Kyverno

	// Checking kubelet versions on user cluster machines requires network connection between kubermatic-api and user cluster api-server.
	// In case where the connection is blocked, we still want to be able to send a patch request. This can be achieved with an additional
	// query param attached to the patch request: "skip_kubelet_version_validation=true"
	if !skipKubeletVersionValidation {
		incompatibleKubelets, err := common.CheckClusterVersionSkew(ctx, userInfoGetter, clusterProvider, newInternalCluster, projectID)
		if err != nil {
			return nil, fmt.Errorf("failed to check existing nodes' version skew: %w", err)
		}
		if len(incompatibleKubelets) > 0 {
			return nil, utilerrors.NewBadRequest("Cluster contains nodes running the following incompatible kubelet versions: %v. Upgrade your nodes before you upgrade the cluster.", incompatibleKubelets)
		}
	}

	// find the defaulting template
	seedClient := privilegedClusterProvider.GetSeedClusterAdminRuntimeClient()

	defaultingTemplate, err := defaulting.GetDefaultingClusterTemplate(ctx, seedClient, seed)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	// determine cloud provider for defaulting
	secretKeyGetter := kubermaticprovider.SecretKeySelectorValueFuncFactory(ctx, seedClient)
	cloudProvider, err := cluster.CloudProviderForCluster(&newInternalCluster.Spec, dc, secretKeyGetter, caBundle)
	if err != nil {
		return nil, err
	}

	// apply default values to the new cluster
	if err := defaulting.DefaultClusterSpec(ctx, &newInternalCluster.Spec, defaultingTemplate, seed, config, cloudProvider); err != nil {
		return nil, err
	}

	validate := &kubernetesprovider.ValidateCredentials{
		Datacenter: dc,
		CABundle:   caBundle,
	}

	changed, err := kubernetesprovider.CreateOrUpdateCredentialSecretForClusterWithValidation(ctx, seedClient, newInternalCluster, validate)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}
	// the credentials were changed during the update. Remove link to credential preset if exists.
	if changed {
		if newInternalCluster.Labels != nil {
			delete(newInternalCluster.Labels, kubermaticv1.IsCredentialPresetLabelKey)
		}
		if newInternalCluster.Annotations != nil {
			delete(newInternalCluster.Annotations, kubermaticv1.PresetNameAnnotation)
			delete(newInternalCluster.Annotations, kubermaticv1.PresetInvalidatedAnnotation)
		}
	}

	if err := clustermutation.MutateUpdate(oldInternalCluster, newInternalCluster, config, seed, cloudProvider); err != nil {
		return nil, utilerrors.NewBadRequest("failed to mutate cluster: %v", err)
	}

	// validate the new cluster
	if errs := validation.ValidateClusterUpdate(ctx, newInternalCluster, oldInternalCluster, dc, seed, cloudProvider, versionManager, features).ToAggregate(); errs != nil {
		return nil, utilerrors.NewBadRequest("invalid cluster: %v", errs)
	}
	if err = validation.ValidateUpdateWindow(newInternalCluster.Spec.UpdateWindow); err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	// update the Cluster resource
	updatedCluster, err := updateCluster(ctx, userInfoGetter, clusterProvider, privilegedClusterProvider, project, newInternalCluster)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	return ConvertInternalClusterToExternal(updatedCluster, dc, true, versionManager.GetIncompatibilities()...), nil
}

func GetClusterEventsEndpoint(ctx context.Context, userInfoGetter provider.UserInfoGetter, projectID, clusterID, eventType string, projectProvider provider.ProjectProvider, privilegedProjectProvider provider.PrivilegedProjectProvider) (interface{}, error) {
	clusterProvider := ctx.Value(middleware.ClusterProviderContextKey).(provider.ClusterProvider)
	privilegedClusterProvider := ctx.Value(middleware.PrivilegedClusterProviderContextKey).(provider.PrivilegedClusterProvider)
	client := privilegedClusterProvider.GetSeedClusterAdminRuntimeClient()

	project, err := common.GetProject(ctx, userInfoGetter, projectProvider, privilegedProjectProvider, projectID, nil)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	cluster, err := GetInternalCluster(ctx, userInfoGetter, clusterProvider, privilegedClusterProvider, project, projectID, clusterID, &provider.ClusterGetOptions{})
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	eventTypeAPI := ""
	switch eventType {
	case "warning":
		eventTypeAPI = corev1.EventTypeWarning
	case "normal":
		eventTypeAPI = corev1.EventTypeNormal
	}

	events, err := common.GetEvents(ctx, client, cluster, metav1.NamespaceAll)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	if len(eventTypeAPI) > 0 {
		events = common.FilterEventsByType(events, eventTypeAPI)
	}

	return events, nil
}

func HealthEndpoint(ctx context.Context, userInfoGetter provider.UserInfoGetter, projectID, clusterID string, projectProvider provider.ProjectProvider, privilegedProjectProvider provider.PrivilegedProjectProvider) (interface{}, error) {
	clusterProvider := ctx.Value(middleware.ClusterProviderContextKey).(provider.ClusterProvider)
	privilegedClusterProvider := ctx.Value(middleware.PrivilegedClusterProviderContextKey).(provider.PrivilegedClusterProvider)
	project, err := common.GetProject(ctx, userInfoGetter, projectProvider, privilegedProjectProvider, projectID, nil)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	existingCluster, err := GetInternalCluster(ctx, userInfoGetter, clusterProvider, privilegedClusterProvider, project, projectID, clusterID, &provider.ClusterGetOptions{})
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	return apiv1.ClusterHealth{
		Apiserver:                    existingCluster.Status.ExtendedHealth.Apiserver,
		ApplicationController:        existingCluster.Status.ExtendedHealth.ApplicationController,
		Scheduler:                    existingCluster.Status.ExtendedHealth.Scheduler,
		Controller:                   existingCluster.Status.ExtendedHealth.Controller,
		MachineController:            existingCluster.Status.ExtendedHealth.MachineController,
		Etcd:                         existingCluster.Status.ExtendedHealth.Etcd,
		CloudProviderInfrastructure:  existingCluster.Status.ExtendedHealth.CloudProviderInfrastructure,
		UserClusterControllerManager: existingCluster.Status.ExtendedHealth.UserClusterControllerManager,
		GatekeeperController:         existingCluster.Status.ExtendedHealth.GatekeeperController,
		GatekeeperAudit:              existingCluster.Status.ExtendedHealth.GatekeeperAudit,
		Monitoring:                   existingCluster.Status.ExtendedHealth.Monitoring,
		Logging:                      existingCluster.Status.ExtendedHealth.Logging,
		AlertmanagerConfig:           existingCluster.Status.ExtendedHealth.AlertmanagerConfig,
		MLAGateway:                   existingCluster.Status.ExtendedHealth.MLAGateway,
		OperatingSystemManager:       existingCluster.Status.ExtendedHealth.OperatingSystemManager,
		KubernetesDashboard:          existingCluster.Status.ExtendedHealth.KubernetesDashboard,
		KubeLB:                       existingCluster.Status.ExtendedHealth.KubeLB,
	}, nil
}

func GetMetricsEndpoint(ctx context.Context, userInfoGetter provider.UserInfoGetter, projectID, clusterID string, projectProvider provider.ProjectProvider, privilegedProjectProvider provider.PrivilegedProjectProvider) (interface{}, error) {
	privilegedClusterProvider := ctx.Value(middleware.PrivilegedClusterProviderContextKey).(provider.PrivilegedClusterProvider)
	clusterProvider := ctx.Value(middleware.ClusterProviderContextKey).(provider.ClusterProvider)

	cluster, err := GetCluster(ctx, projectProvider, privilegedProjectProvider, userInfoGetter, projectID, clusterID, nil)
	if err != nil {
		return nil, err
	}

	client, err := common.GetClusterClient(ctx, userInfoGetter, clusterProvider, cluster, projectID)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	nodeList := &corev1.NodeList{}
	if err := client.List(ctx, nodeList); err != nil {
		return nil, err
	}

	if len(nodeList.Items) == 0 {
		return nil, utilerrors.New(http.StatusNotFound, "no nodes found")
	}

	availableResources := make(map[string]corev1.ResourceList)
	for _, n := range nodeList.Items {
		availableResources[n.Name] = n.Status.Allocatable
	}

	dynamicClient, err := clusterProvider.GetAdminClientForUserCluster(ctx, cluster)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	allNodeMetricsList := &v1beta1.NodeMetricsList{}
	if err := dynamicClient.List(ctx, allNodeMetricsList); err != nil {
		// Happens during cluster creation when the CRD is not setup yet
		if !meta.IsNoMatchError(err) {
			return nil, common.KubernetesErrorToHTTPError(err)
		}
	}

	seedAdminClient := privilegedClusterProvider.GetSeedClusterAdminRuntimeClient()
	podMetricsList := &v1beta1.PodMetricsList{}
	if err := seedAdminClient.List(ctx, podMetricsList, &ctrlruntimeclient.ListOptions{Namespace: fmt.Sprintf("cluster-%s", cluster.Name)}); err != nil {
		// Happens during cluster creation when the CRD is not setup yet
		if !meta.IsNoMatchError(err) {
			return nil, common.KubernetesErrorToHTTPError(err)
		}
	}
	return ConvertClusterMetrics(podMetricsList, allNodeMetricsList.Items, availableResources, cluster.Name)
}

func MigrateEndpointToExternalCCM(ctx context.Context, userInfoGetter provider.UserInfoGetter, projectID,
	clusterID string, projectProvider provider.ProjectProvider, seedsGetter provider.SeedsGetter,
	privilegedProjectProvider provider.PrivilegedProjectProvider, configGetter provider.KubermaticConfigurationGetter,
) (interface{}, error) {
	privilegedClusterProvider := ctx.Value(middleware.PrivilegedClusterProviderContextKey).(provider.PrivilegedClusterProvider)

	adminUserInfo, err := userInfoGetter(ctx, "")
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	oldCluster, err := GetCluster(ctx, projectProvider, privilegedProjectProvider, userInfoGetter, projectID, clusterID, nil)
	if err != nil {
		return nil, err
	}

	config, err := configGetter(ctx)
	if err != nil {
		return nil, err
	}

	_, dc, err := provider.DatacenterFromSeedMap(adminUserInfo, seedsGetter, oldCluster.Spec.Cloud.DatacenterName)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	if !resources.MigrationToExternalCloudControllerSupported(dc, oldCluster, version.NewFromConfiguration(config).GetIncompatibilities()...) {
		return nil, utilerrors.NewBadRequest("external CCM not supported by the given provider")
	}

	if ok := oldCluster.Spec.Features[kubermaticv1.ClusterFeatureExternalCloudProvider]; ok {
		return nil, utilerrors.NewBadRequest("external CCM already enabled, cannot be disabled")
	}

	newCluster := oldCluster.DeepCopy()
	if newCluster.Spec.Features == nil {
		newCluster.Spec.Features = make(map[string]bool)
	}
	newCluster.Spec.Features[kubermaticv1.ClusterFeatureExternalCloudProvider] = true
	if oldCluster.Spec.Cloud.VSphere != nil {
		newCluster.Spec.Features[kubermaticv1.ClusterFeatureVsphereCSIClusterID] = true
	}

	seedAdminClient := privilegedClusterProvider.GetSeedClusterAdminRuntimeClient()
	if err := seedAdminClient.Patch(ctx, newCluster, ctrlruntimeclient.MergeFrom(oldCluster)); err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	return nil, nil
}

func ListNamespaceEndpoint(ctx context.Context, userInfoGetter provider.UserInfoGetter, projectID, clusterID string, projectProvider provider.ProjectProvider, privilegedProjectProvider provider.PrivilegedProjectProvider) (interface{}, error) {
	clusterProvider := ctx.Value(middleware.ClusterProviderContextKey).(provider.ClusterProvider)

	cluster, err := GetCluster(ctx, projectProvider, privilegedProjectProvider, userInfoGetter, projectID, clusterID, nil)
	if err != nil {
		return nil, err
	}

	client, err := common.GetClusterClient(ctx, userInfoGetter, clusterProvider, cluster, projectID)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	namespaceList := &corev1.NamespaceList{}
	if err := client.List(ctx, namespaceList); err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	var apiNamespaces []apiv1.Namespace

	for _, namespace := range namespaceList.Items {
		apiNamespace := apiv1.Namespace{Name: namespace.Name}
		apiNamespaces = append(apiNamespaces, apiNamespace)
	}

	return apiNamespaces, nil
}

func AssignSSHKeyEndpoint(ctx context.Context, userInfoGetter provider.UserInfoGetter, projectID, clusterID, keyID string, projectProvider provider.ProjectProvider, privilegedProjectProvider provider.PrivilegedProjectProvider, sshKeyProvider provider.SSHKeyProvider, privilegedSSHKeyProvider provider.PrivilegedSSHKeyProvider) (interface{}, error) {
	clusterProvider := ctx.Value(middleware.ClusterProviderContextKey).(provider.ClusterProvider)
	privilegedClusterProvider := ctx.Value(middleware.PrivilegedClusterProviderContextKey).(provider.PrivilegedClusterProvider)
	if len(keyID) == 0 {
		return nil, utilerrors.NewBadRequest("please provide an SSH key")
	}

	project, err := common.GetProject(ctx, userInfoGetter, projectProvider, privilegedProjectProvider, projectID, nil)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}
	_, err = GetInternalCluster(ctx, userInfoGetter, clusterProvider, privilegedClusterProvider, project, projectID, clusterID, &provider.ClusterGetOptions{})
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	// sanity check, make sure that the key belongs to the project
	// alternatively we could examine the owner references
	{
		projectSSHKeys, err := sshKeyProvider.List(ctx, project, nil)
		if err != nil {
			return nil, common.KubernetesErrorToHTTPError(err)
		}
		found := false
		for _, projectSSHKey := range projectSSHKeys {
			if projectSSHKey.Name == keyID {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("the given ssh key %s does not belong to the given project %s (%s)", keyID, project.Spec.Name, project.Name)
		}
	}

	sshKey, err := getSSHKey(ctx, userInfoGetter, sshKeyProvider, privilegedSSHKeyProvider, projectID, keyID)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	apiKey := apiv1.SSHKey{
		ObjectMeta: apiv1.ObjectMeta{
			ID:                sshKey.Name,
			Name:              sshKey.Spec.Name,
			CreationTimestamp: apiv1.NewTime(sshKey.CreationTimestamp.Time),
		},
	}

	if sshKey.IsUsedByCluster(clusterID) {
		return apiKey, nil
	}
	sshKey.AddToCluster(clusterID)
	if err := UpdateClusterSSHKey(ctx, userInfoGetter, sshKeyProvider, privilegedSSHKeyProvider, sshKey, projectID); err != nil {
		return nil, err
	}

	return apiKey, nil
}

func DetachSSHKeyEndpoint(ctx context.Context, userInfoGetter provider.UserInfoGetter, projectID, clusterID, keyID string, projectProvider provider.ProjectProvider, privilegedProjectProvider provider.PrivilegedProjectProvider, sshKeyProvider provider.SSHKeyProvider, privilegedSSHKeyProvider provider.PrivilegedSSHKeyProvider) (interface{}, error) {
	clusterProvider := ctx.Value(middleware.ClusterProviderContextKey).(provider.ClusterProvider)
	privilegedClusterProvider := ctx.Value(middleware.PrivilegedClusterProviderContextKey).(provider.PrivilegedClusterProvider)

	project, err := common.GetProject(ctx, userInfoGetter, projectProvider, privilegedProjectProvider, projectID, nil)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	_, err = GetInternalCluster(ctx, userInfoGetter, clusterProvider, privilegedClusterProvider, project, projectID, clusterID, &provider.ClusterGetOptions{})
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	// sanity check, make sure that the key belongs to the project
	// alternatively we could examine the owner references
	{
		projectSSHKeys, err := sshKeyProvider.List(ctx, project, nil)
		if err != nil {
			return nil, common.KubernetesErrorToHTTPError(err)
		}

		found := false
		for _, projectSSHKey := range projectSSHKeys {
			if projectSSHKey.Name == keyID {
				found = true
				break
			}
		}
		if !found {
			return nil, utilerrors.NewNotFound("sshkey", keyID)
		}
	}

	clusterSSHKey, err := getSSHKey(ctx, userInfoGetter, sshKeyProvider, privilegedSSHKeyProvider, projectID, keyID)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	clusterSSHKey.RemoveFromCluster(clusterID)
	if err := UpdateClusterSSHKey(ctx, userInfoGetter, sshKeyProvider, privilegedSSHKeyProvider, clusterSSHKey, projectID); err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}
	return nil, nil
}

func ListSSHKeysEndpoint(ctx context.Context, userInfoGetter provider.UserInfoGetter, projectID, clusterID string, projectProvider provider.ProjectProvider, privilegedProjectProvider provider.PrivilegedProjectProvider, sshKeyProvider provider.SSHKeyProvider) (interface{}, error) {
	clusterProvider := ctx.Value(middleware.ClusterProviderContextKey).(provider.ClusterProvider)
	privilegedClusterProvider := ctx.Value(middleware.PrivilegedClusterProviderContextKey).(provider.PrivilegedClusterProvider)

	project, err := common.GetProject(ctx, userInfoGetter, projectProvider, privilegedProjectProvider, projectID, nil)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}
	_, err = GetInternalCluster(ctx, userInfoGetter, clusterProvider, privilegedClusterProvider, project, projectID, clusterID, &provider.ClusterGetOptions{})
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}
	keys, err := sshKeyProvider.List(ctx, project, &provider.SSHKeyListOptions{ClusterName: clusterID})
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}
	apiKeys := common.ConvertInternalSSHKeysToExternal(keys)
	return apiKeys, nil
}

func UpdateClusterSSHKey(ctx context.Context, userInfoGetter provider.UserInfoGetter, sshKeyProvider provider.SSHKeyProvider, privilegedSSHKeyProvider provider.PrivilegedSSHKeyProvider, clusterSSHKey *kubermaticv1.UserSSHKey, projectID string) error {
	adminUserInfo, err := userInfoGetter(ctx, "")
	if err != nil {
		return utilerrors.New(http.StatusInternalServerError, err.Error())
	}
	if adminUserInfo.IsAdmin {
		if _, err := privilegedSSHKeyProvider.UpdateUnsecured(ctx, clusterSSHKey); err != nil {
			return common.KubernetesErrorToHTTPError(err)
		}
		return nil
	}
	userInfo, err := userInfoGetter(ctx, projectID)
	if err != nil {
		return utilerrors.New(http.StatusInternalServerError, err.Error())
	}
	if _, err = sshKeyProvider.Update(ctx, userInfo, clusterSSHKey); err != nil {
		return common.KubernetesErrorToHTTPError(err)
	}
	return nil
}

func updateCluster(ctx context.Context, userInfoGetter provider.UserInfoGetter, clusterProvider provider.ClusterProvider, privilegedClusterProvider provider.PrivilegedClusterProvider, project *kubermaticv1.Project, cluster *kubermaticv1.Cluster) (*kubermaticv1.Cluster, error) {
	adminUserInfo, err := userInfoGetter(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get user information: %w", err)
	}
	if adminUserInfo.IsAdmin {
		return privilegedClusterProvider.UpdateUnsecured(ctx, project, cluster)
	}
	userInfo, err := userInfoGetter(ctx, project.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get user information: %w", err)
	}
	return clusterProvider.Update(ctx, project, userInfo, cluster)
}

func updateAndDeleteCluster(ctx context.Context, userInfoGetter provider.UserInfoGetter, clusterProvider provider.ClusterProvider, privilegedClusterProvider provider.PrivilegedClusterProvider, project *kubermaticv1.Project, cluster *kubermaticv1.Cluster) error {
	adminUserInfo, err := userInfoGetter(ctx, "")
	if err != nil {
		return utilerrors.New(http.StatusInternalServerError, err.Error())
	}
	if adminUserInfo.IsAdmin {
		cluster, err := privilegedClusterProvider.UpdateUnsecured(ctx, project, cluster)
		if err != nil {
			return common.KubernetesErrorToHTTPError(err)
		}
		err = privilegedClusterProvider.DeleteUnsecured(ctx, cluster)
		if err != nil {
			return common.KubernetesErrorToHTTPError(err)
		}
		return nil
	}

	return updateAndDeleteClusterForRegularUser(ctx, userInfoGetter, clusterProvider, project, cluster)
}

func updateAndDeleteClusterForRegularUser(ctx context.Context, userInfoGetter provider.UserInfoGetter, clusterProvider provider.ClusterProvider, project *kubermaticv1.Project, cluster *kubermaticv1.Cluster) error {
	userInfo, err := userInfoGetter(ctx, project.Name)
	if err != nil {
		return utilerrors.New(http.StatusInternalServerError, err.Error())
	}
	if cluster, err = clusterProvider.Update(ctx, project, userInfo, cluster); err != nil {
		return common.KubernetesErrorToHTTPError(err)
	}

	err = clusterProvider.Delete(ctx, userInfo, cluster)
	if err != nil {
		return common.KubernetesErrorToHTTPError(err)
	}
	return nil
}

func createNewCluster(ctx context.Context, userInfoGetter provider.UserInfoGetter, clusterProvider provider.ClusterProvider, privilegedClusterProvider provider.PrivilegedClusterProvider, project *kubermaticv1.Project, cluster *kubermaticv1.Cluster) (*kubermaticv1.Cluster, error) {
	adminUserInfo, err := userInfoGetter(ctx, "")
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}
	if adminUserInfo.IsAdmin {
		return privilegedClusterProvider.NewUnsecured(ctx, project, cluster, adminUserInfo.Email)
	}
	userInfo, err := userInfoGetter(ctx, project.Name)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}
	return clusterProvider.New(ctx, project, userInfo, cluster)
}

func GetInternalCluster(ctx context.Context, userInfoGetter provider.UserInfoGetter, clusterProvider provider.ClusterProvider, privilegedClusterProvider provider.PrivilegedClusterProvider, project *kubermaticv1.Project, projectID, clusterID string, options *provider.ClusterGetOptions) (*kubermaticv1.Cluster, error) {
	adminUserInfo, err := userInfoGetter(ctx, "")
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}
	if adminUserInfo.IsAdmin {
		cluster, err := privilegedClusterProvider.GetUnsecured(ctx, project, clusterID, options)
		if err != nil {
			return nil, common.KubernetesErrorToHTTPError(err)
		}
		return cluster, nil
	}

	return getClusterForRegularUser(ctx, userInfoGetter, clusterProvider, privilegedClusterProvider, project, projectID, clusterID, options)
}

func getClusterForRegularUser(ctx context.Context, userInfoGetter provider.UserInfoGetter, clusterProvider provider.ClusterProvider, privilegedClusterProvider provider.PrivilegedClusterProvider, project *kubermaticv1.Project, projectID, clusterID string, options *provider.ClusterGetOptions) (*kubermaticv1.Cluster, error) {
	userInfo, err := userInfoGetter(ctx, projectID)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}
	cluster, err := clusterProvider.Get(ctx, userInfo, clusterID, options)
	if err != nil {
		// Request came from the specified user. Instead `Not found` error status the `Forbidden` is returned.
		// Next request with privileged user checks if the cluster doesn't exist or some other error occurred.
		if !isStatus(err, http.StatusForbidden) {
			return nil, common.KubernetesErrorToHTTPError(err)
		}
		// Check if cluster really doesn't exist or some other error occurred.
		if _, errGetUnsecured := privilegedClusterProvider.GetUnsecured(ctx, project, clusterID, options); errGetUnsecured != nil {
			return nil, common.KubernetesErrorToHTTPError(errGetUnsecured)
		}
		// Cluster is not ready yet, return original error
		return nil, common.KubernetesErrorToHTTPError(err)
	}
	return cluster, nil
}

func isStatus(err error, status int32) bool {
	var statusErr *apierrors.StatusError

	return errors.As(err, &statusErr) && status == statusErr.Status().Code
}

func ConvertInternalClusterToExternal(internalCluster *kubermaticv1.Cluster, datacenter *kubermaticv1.Datacenter, filterSystemLabels bool, incompatibilities ...*version.ProviderIncompatibility) *apiv1.Cluster {
	cluster := &apiv1.Cluster{
		ObjectMeta: apiv1.ObjectMeta{
			ID:                internalCluster.Name,
			Name:              internalCluster.Spec.HumanReadableName,
			Annotations:       internalCluster.Annotations,
			CreationTimestamp: apiv1.NewTime(internalCluster.CreationTimestamp.Time),
			DeletionTimestamp: func() *apiv1.Time {
				if internalCluster.DeletionTimestamp != nil {
					deletionTimestamp := apiv1.NewTime(internalCluster.DeletionTimestamp.Time)
					return &deletionTimestamp
				}
				return nil
			}(),
		},
		Labels:          internalCluster.Labels,
		InheritedLabels: internalCluster.Status.InheritedLabels,
		Spec: apiv1.ClusterSpec{
			Cloud:                                internalCluster.Spec.Cloud,
			Version:                              internalCluster.Spec.Version,
			MachineNetworks:                      internalCluster.Spec.MachineNetworks,
			OIDC:                                 internalCluster.Spec.OIDC,
			UpdateWindow:                         internalCluster.Spec.UpdateWindow,
			AuditLogging:                         internalCluster.Spec.AuditLogging,
			UsePodSecurityPolicyAdmissionPlugin:  internalCluster.Spec.UsePodSecurityPolicyAdmissionPlugin,
			UsePodNodeSelectorAdmissionPlugin:    internalCluster.Spec.UsePodNodeSelectorAdmissionPlugin,
			UseEventRateLimitAdmissionPlugin:     internalCluster.Spec.UseEventRateLimitAdmissionPlugin,
			EnableUserSSHKeyAgent:                internalCluster.Spec.EnableUserSSHKeyAgent,
			BackupConfig:                         internalCluster.Spec.BackupConfig,
			KubeLB:                               internalCluster.Spec.KubeLB,
			KubernetesDashboard:                  internalCluster.Spec.KubernetesDashboard,
			AdmissionPlugins:                     internalCluster.Spec.AdmissionPlugins,
			OPAIntegration:                       internalCluster.Spec.OPAIntegration,
			PodNodeSelectorAdmissionPluginConfig: internalCluster.Spec.PodNodeSelectorAdmissionPluginConfig,
			EventRateLimitConfig:                 internalCluster.Spec.EventRateLimitConfig,
			ServiceAccount:                       internalCluster.Spec.ServiceAccount,
			MLA:                                  internalCluster.Spec.MLA,
			ContainerRuntime:                     internalCluster.Spec.ContainerRuntime,
			ClusterNetwork:                       &internalCluster.Spec.ClusterNetwork,
			CNIPlugin:                            internalCluster.Spec.CNIPlugin,
			ExposeStrategy:                       internalCluster.Spec.ExposeStrategy,
			APIServerAllowedIPRanges:             internalCluster.Spec.APIServerAllowedIPRanges,
			DisableCSIDriver:                     internalCluster.Spec.DisableCSIDriver,
			Kyverno:                              internalCluster.Spec.Kyverno,
		},
		Status: apiv1.ClusterStatus{
			Version:              internalCluster.Status.Versions.ControlPlane,
			URL:                  internalCluster.Status.Address.URL,
			ExternalCCMMigration: convertInternalCCMStatusToExternal(internalCluster, datacenter, incompatibilities...),
		},
		Type: apiv1.KubernetesClusterType,
	}

	if filterSystemLabels {
		cluster.Labels = label.FilterLabels(label.ClusterResourceType, internalCluster.Labels)
	}
	if cluster.Annotations == nil {
		cluster.Annotations = make(map[string]string)
	}

	return cluster
}

func ValidateClusterSpec(updateManager common.UpdateManager, body apiv1.CreateClusterSpec) error {
	if body.Cluster.Spec.Cloud.DatacenterName == "" {
		return errors.New("cluster datacenter name is empty")
	}
	if body.Cluster.ID != "" {
		return errors.New("cluster.ID is read-only")
	}
	if !ClusterTypes.Has(body.Cluster.Type) {
		return fmt.Errorf("invalid cluster type %s", body.Cluster.Type)
	}
	if body.Cluster.Spec.Version.Semver() == nil {
		return errors.New("invalid cluster: invalid cloud spec \"Version\" is required but was not specified")
	}
	if len(body.Cluster.Name) > 100 {
		return errors.New("invalid cluster name: too long (greater than 100 characters)")
	}

	providerName, err := kubermaticv1helper.ClusterCloudProviderName(body.Cluster.Spec.Cloud)
	if err != nil {
		return fmt.Errorf("failed to get the cloud provider name: %w", err)
	}
	versions, err := updateManager.GetVersionsForProvider(kubermaticv1.ProviderType(providerName))
	if err != nil {
		return fmt.Errorf("failed to get available cluster versions: %w", err)
	}
	for _, availableVersion := range versions {
		if body.Cluster.Spec.Version.Semver().Equal(availableVersion.Version) {
			return nil
		}
	}

	return fmt.Errorf("invalid cluster: invalid cloud spec: unsupported version %v", body.Cluster.Spec.Version.Semver())
}

func ConvertClusterMetrics(podMetrics *v1beta1.PodMetricsList, nodeMetrics []v1beta1.NodeMetrics, availableNodesResources map[string]corev1.ResourceList, clusterName string) (*apiv1.ClusterMetrics, error) {
	if podMetrics == nil {
		return nil, fmt.Errorf("metric list can not be nil")
	}

	clusterMetrics := &apiv1.ClusterMetrics{
		Name:                clusterName,
		ControlPlaneMetrics: apiv1.ControlPlaneMetrics{},
		NodesMetrics:        apiv1.NodesMetric{},
	}

	for _, m := range nodeMetrics {
		resourceMetricsInfo := common.ResourceMetricsInfo{
			Name:      m.Name,
			Metrics:   m.Usage.DeepCopy(),
			Available: availableNodesResources[m.Name],
		}

		availableCPU, foundCPU := resourceMetricsInfo.Available[corev1.ResourceCPU]
		availableMemory, foundMemory := resourceMetricsInfo.Available[corev1.ResourceMemory]
		if foundCPU && foundMemory {
			quantityCPU := resourceMetricsInfo.Metrics[corev1.ResourceCPU]
			clusterMetrics.NodesMetrics.CPUTotalMillicores += quantityCPU.MilliValue()
			clusterMetrics.NodesMetrics.CPUAvailableMillicores += availableCPU.MilliValue()

			quantityM := resourceMetricsInfo.Metrics[corev1.ResourceMemory]
			clusterMetrics.NodesMetrics.MemoryTotalBytes += quantityM.Value() / (1024 * 1024)
			clusterMetrics.NodesMetrics.MemoryAvailableBytes += availableMemory.Value() / (1024 * 1024)
		}
	}

	fractionCPU := float64(clusterMetrics.NodesMetrics.CPUTotalMillicores) / float64(clusterMetrics.NodesMetrics.CPUAvailableMillicores) * 100
	clusterMetrics.NodesMetrics.CPUUsedPercentage += int64(fractionCPU)
	fractionMemory := float64(clusterMetrics.NodesMetrics.MemoryTotalBytes) / float64(clusterMetrics.NodesMetrics.MemoryAvailableBytes) * 100
	clusterMetrics.NodesMetrics.MemoryUsedPercentage += int64(fractionMemory)

	for _, podMetrics := range podMetrics.Items {
		for _, container := range podMetrics.Containers {
			usage := container.Usage.DeepCopy()
			quantityCPU := usage[corev1.ResourceCPU]
			clusterMetrics.ControlPlaneMetrics.CPUTotalMillicores += quantityCPU.MilliValue()
			quantityM := usage[corev1.ResourceMemory]
			clusterMetrics.ControlPlaneMetrics.MemoryTotalBytes += quantityM.Value() / (1024 * 1024)
		}
	}

	return clusterMetrics, nil
}

func getSSHKey(ctx context.Context, userInfoGetter provider.UserInfoGetter, sshKeyProvider provider.SSHKeyProvider, privilegedSSHKeyProvider provider.PrivilegedSSHKeyProvider, projectID, keyName string) (*kubermaticv1.UserSSHKey, error) {
	adminUserInfo, err := userInfoGetter(ctx, "")
	if err != nil {
		return nil, utilerrors.New(http.StatusInternalServerError, err.Error())
	}
	if adminUserInfo.IsAdmin {
		return privilegedSSHKeyProvider.GetUnsecured(ctx, keyName)
	}
	userInfo, err := userInfoGetter(ctx, projectID)
	if err != nil {
		return nil, utilerrors.New(http.StatusInternalServerError, err.Error())
	}
	return sshKeyProvider.Get(ctx, userInfo, keyName)
}

func convertInternalCCMStatusToExternal(cluster *kubermaticv1.Cluster, datacenter *kubermaticv1.Datacenter, incompatibilities ...*version.ProviderIncompatibility) apiv1.ExternalCCMMigrationStatus {
	switch externalCCMEnabled, externalCCMSupported := cluster.Spec.Features[kubermaticv1.ClusterFeatureExternalCloudProvider], resources.MigrationToExternalCloudControllerSupported(datacenter, cluster, incompatibilities...); {
	case externalCCMEnabled:
		if kubermaticv1helper.NeedCCMMigration(cluster) {
			return apiv1.ExternalCCMMigrationInProgress
		}

		return apiv1.ExternalCCMMigrationNotNeeded

	case externalCCMSupported:
		return apiv1.ExternalCCMMigrationSupported

	default:
		return apiv1.ExternalCCMMigrationUnsupported
	}
}

func GetClusterClientWithClusterID(ctx context.Context, userInfoGetter provider.UserInfoGetter, projectProvider provider.ProjectProvider,
	privilegedProjectProvider provider.PrivilegedProjectProvider, projectID, clusterID string) (ctrlruntimeclient.Client, error) {
	clusterProvider := ctx.Value(middleware.ClusterProviderContextKey).(provider.ClusterProvider)
	cluster, err := GetCluster(ctx, projectProvider, privilegedProjectProvider, userInfoGetter, projectID, clusterID, nil)
	if err != nil {
		return nil, err
	}

	client, err := common.GetClusterClient(ctx, userInfoGetter, clusterProvider, cluster, projectID)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}
	return client, nil
}

func checkIfPresetCustomized(ctx context.Context, projectID string, adminUserInfo provider.UserInfo, cloudSpec kubermaticv1.CloudSpec, credentialManager provider.PresetProvider, credentialName string) bool {
	preset, _ := credentialManager.GetPreset(ctx, &adminUserInfo, &projectID, credentialName)

	// At the moment, the only provider that can be customized is OpenStack.
	if cloudSpec.Openstack != nil && preset.Spec.Openstack.IsCustomizable {
		presetSpec := preset.Spec.Openstack
		openstackCloudSpec := cloudSpec.Openstack
		if presetSpec.Network != openstackCloudSpec.Network || presetSpec.RouterID != openstackCloudSpec.RouterID || presetSpec.FloatingIPPool != openstackCloudSpec.FloatingIPPool || presetSpec.SecurityGroups != openstackCloudSpec.SecurityGroups {
			return true
		}
	}
	// TODO: Add all other providers

	return false
}
