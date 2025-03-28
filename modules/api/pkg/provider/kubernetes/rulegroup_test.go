/*
Copyright 2021 The Kubermatic Kubernetes Platform contributors.

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

package kubernetes_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"k8c.io/dashboard/v2/pkg/handler/test"
	"k8c.io/dashboard/v2/pkg/provider"
	"k8c.io/dashboard/v2/pkg/provider/kubernetes"
	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	"k8c.io/kubermatic/v2/pkg/test/diff"
	"k8c.io/kubermatic/v2/pkg/test/fake"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	restclient "k8s.io/client-go/rest"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	testRuleGroupName        = "test-rule-group"
	testRuleGroupClusterName = "test-rule-group"
)

func TestGetRuleGroup(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name              string
		existingObjects   []ctrlruntimeclient.Object
		userInfo          *provider.UserInfo
		cluster           *kubermaticv1.Cluster
		expectedRuleGroup *kubermaticv1.RuleGroup
		expectedError     string
	}{
		{
			name: "get ruleGroup",
			existingObjects: []ctrlruntimeclient.Object{
				test.GenRuleGroup(testRuleGroupName, testRuleGroupClusterName, kubermaticv1.RuleGroupTypeMetrics, false),
			},
			userInfo:          &provider.UserInfo{Email: "john@acme.com", Groups: []string{"owners-abcd"}},
			cluster:           genCluster(testRuleGroupClusterName, "kubernetes", "my-first-project-ID", "test-rule-group", "john@acme.com"),
			expectedRuleGroup: test.GenRuleGroup(testRuleGroupName, testRuleGroupClusterName, kubermaticv1.RuleGroupTypeMetrics, false),
		},
		{
			name:          "ruleGroup is not found",
			userInfo:      &provider.UserInfo{Email: "john@acme.com", Groups: []string{"owners-abcd"}},
			cluster:       genCluster(testRuleGroupClusterName, "kubernetes", "my-first-project-ID", "test-rule-group", "john@acme.com"),
			expectedError: "rulegroups.kubermatic.k8c.io \"test-rule-group\" not found",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewClientBuilder().
				WithObjects(tc.existingObjects...).
				Build()
			fakeImpersonationClient := func(impCfg restclient.ImpersonationConfig) (ctrlruntimeclient.Client, error) {
				return client, nil
			}

			ruleGroupProvider := kubernetes.NewRuleGroupProvider(fakeImpersonationClient, client)

			ruleGroup, err := ruleGroupProvider.Get(context.Background(), tc.userInfo, tc.cluster, testRuleGroupName)
			if len(tc.expectedError) == 0 {
				if err != nil {
					t.Fatal(err)
				}
				tc.expectedRuleGroup.ResourceVersion = ruleGroup.ResourceVersion
				assert.Equal(t, tc.expectedRuleGroup, ruleGroup)
			} else {
				if err == nil {
					t.Fatalf("expected error message")
				}
				assert.Equal(t, tc.expectedError, err.Error())
			}
		})
	}
}

func TestListRuleGroup(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name               string
		existingObjects    []ctrlruntimeclient.Object
		listOptions        *provider.RuleGroupListOptions
		userInfo           *provider.UserInfo
		cluster            *kubermaticv1.Cluster
		expectedRuleGroups []*kubermaticv1.RuleGroup
		expectedError      string
	}{
		{
			name: "list all ruleGroups",
			existingObjects: []ctrlruntimeclient.Object{
				test.GenRuleGroup("test-1", testRuleGroupClusterName, kubermaticv1.RuleGroupTypeMetrics, false),
				test.GenRuleGroup("test-2", testRuleGroupClusterName, kubermaticv1.RuleGroupTypeMetrics, false),
				test.GenRuleGroup("test-3", testRuleGroupClusterName, kubermaticv1.RuleGroupTypeMetrics, false),
			},
			userInfo: &provider.UserInfo{Email: "john@acme.com", Groups: []string{"owners-abcd"}},
			cluster:  genCluster(testRuleGroupClusterName, "kubernetes", "my-first-project-ID", "test-rule-group", "john@acme.com"),
			expectedRuleGroups: []*kubermaticv1.RuleGroup{
				test.GenRuleGroup("test-1", testRuleGroupClusterName, kubermaticv1.RuleGroupTypeMetrics, false),
				test.GenRuleGroup("test-2", testRuleGroupClusterName, kubermaticv1.RuleGroupTypeMetrics, false),
				test.GenRuleGroup("test-3", testRuleGroupClusterName, kubermaticv1.RuleGroupTypeMetrics, false),
			},
		},
		{
			name: "list all ruleGroups with empty list options",
			existingObjects: []ctrlruntimeclient.Object{
				test.GenRuleGroup("test-1", testRuleGroupClusterName, kubermaticv1.RuleGroupTypeMetrics, false),
				test.GenRuleGroup("test-2", testRuleGroupClusterName, kubermaticv1.RuleGroupTypeMetrics, false),
				test.GenRuleGroup("test-3", testRuleGroupClusterName, kubermaticv1.RuleGroupTypeMetrics, false),
			},
			listOptions: &provider.RuleGroupListOptions{},
			userInfo:    &provider.UserInfo{Email: "john@acme.com", Groups: []string{"owners-abcd"}},
			cluster:     genCluster(testRuleGroupClusterName, "kubernetes", "my-first-project-ID", "test-rule-group", "john@acme.com"),
			expectedRuleGroups: []*kubermaticv1.RuleGroup{
				test.GenRuleGroup("test-1", testRuleGroupClusterName, kubermaticv1.RuleGroupTypeMetrics, false),
				test.GenRuleGroup("test-2", testRuleGroupClusterName, kubermaticv1.RuleGroupTypeMetrics, false),
				test.GenRuleGroup("test-3", testRuleGroupClusterName, kubermaticv1.RuleGroupTypeMetrics, false),
			},
		},
		{
			name: "list ruleGroups with metrics type as list options",
			existingObjects: []ctrlruntimeclient.Object{
				test.GenRuleGroup("test-1", testRuleGroupClusterName, kubermaticv1.RuleGroupTypeMetrics, false),
				test.GenRuleGroup("test-2", testRuleGroupClusterName, "FakeType", false),
				test.GenRuleGroup("test-3", testRuleGroupClusterName, kubermaticv1.RuleGroupTypeMetrics, false),
			},
			listOptions: &provider.RuleGroupListOptions{RuleGroupType: kubermaticv1.RuleGroupTypeMetrics},
			userInfo:    &provider.UserInfo{Email: "john@acme.com", Groups: []string{"owners-abcd"}},
			cluster:     genCluster(testRuleGroupClusterName, "kubernetes", "my-first-project-ID", "test-rule-group", "john@acme.com"),
			expectedRuleGroups: []*kubermaticv1.RuleGroup{
				test.GenRuleGroup("test-1", testRuleGroupClusterName, kubermaticv1.RuleGroupTypeMetrics, false),
				test.GenRuleGroup("test-3", testRuleGroupClusterName, kubermaticv1.RuleGroupTypeMetrics, false),
			},
		},
		{
			name:     "ruleGroup is not found",
			userInfo: &provider.UserInfo{Email: "john@acme.com", Groups: []string{"owners-abcd"}},
			cluster:  genCluster(testRuleGroupClusterName, "kubernetes", "my-first-project-ID", "test-rule-group", "john@acme.com"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewClientBuilder().
				WithObjects(tc.existingObjects...).
				Build()
			fakeImpersonationClient := func(impCfg restclient.ImpersonationConfig) (ctrlruntimeclient.Client, error) {
				return client, nil
			}

			ruleGroupProvider := kubernetes.NewRuleGroupProvider(fakeImpersonationClient, client)

			ruleGroups, err := ruleGroupProvider.List(context.Background(), tc.userInfo, tc.cluster, tc.listOptions)
			if len(tc.expectedError) == 0 {
				if err != nil {
					t.Fatal(err)
				}
				if len(tc.expectedRuleGroups) != len(ruleGroups) {
					t.Fatalf("expected to get %d ruleGroups, but got %d", len(tc.expectedRuleGroups), len(ruleGroups))
				}
				ruleGroupMap := make(map[string]*kubermaticv1.RuleGroup)
				for _, ruleGroup := range ruleGroups {
					ruleGroup.ResourceVersion = ""
					ruleGroupMap[ruleGroup.Name] = ruleGroup
				}

				for _, expectedRuleGroup := range tc.expectedRuleGroups {
					ruleGroup, ok := ruleGroupMap[expectedRuleGroup.Name]
					if !ok {
						t.Errorf("expected ruleGroup %s is not in resulting ruleGroups", expectedRuleGroup.Name)
					}

					if !diff.SemanticallyEqual(expectedRuleGroup, ruleGroup) {
						t.Fatalf("Got unexpected ruleGroup:\n%v", diff.ObjectDiff(expectedRuleGroup, ruleGroup))
					}
				}
			} else {
				if err == nil {
					t.Fatalf("expected error message")
				}
				assert.Equal(t, tc.expectedError, err.Error())
			}
		})
	}
}

func TestCreateRuleGroup(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name              string
		existingObjects   []ctrlruntimeclient.Object
		userInfo          *provider.UserInfo
		cluster           *kubermaticv1.Cluster
		expectedRuleGroup *kubermaticv1.RuleGroup
		expectedError     string
	}{
		{
			name:              "create ruleGroup",
			userInfo:          &provider.UserInfo{Email: "john@acme.com", Groups: []string{"owners-abcd"}},
			cluster:           genCluster(testRuleGroupClusterName, "kubernetes", "my-first-project-ID", "test-rule-group", "john@acme.com"),
			expectedRuleGroup: test.GenRuleGroup(testRuleGroupName, testRuleGroupClusterName, kubermaticv1.RuleGroupTypeMetrics, false),
		},
		{
			name: "create ruleGroup which already exists",
			existingObjects: []ctrlruntimeclient.Object{
				test.GenRuleGroup(testRuleGroupName, testRuleGroupClusterName, kubermaticv1.RuleGroupTypeMetrics, false),
			},
			userInfo:          &provider.UserInfo{Email: "john@acme.com", Groups: []string{"owners-abcd"}},
			cluster:           genCluster(testRuleGroupClusterName, "kubernetes", "my-first-project-ID", "test-rule-group", "john@acme.com"),
			expectedRuleGroup: test.GenRuleGroup(testRuleGroupName, testRuleGroupClusterName, kubermaticv1.RuleGroupTypeMetrics, false),
			expectedError:     "rulegroups.kubermatic.k8c.io \"test-rule-group\" already exists",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewClientBuilder().
				WithObjects(tc.existingObjects...).
				Build()
			fakeImpersonationClient := func(impCfg restclient.ImpersonationConfig) (ctrlruntimeclient.Client, error) {
				return client, nil
			}

			ruleGroupProvider := kubernetes.NewRuleGroupProvider(fakeImpersonationClient, client)

			_, err := ruleGroupProvider.Create(context.Background(), tc.userInfo, tc.expectedRuleGroup)
			if len(tc.expectedError) == 0 {
				if err != nil {
					t.Fatal(err)
				}

				ruleGroup, err := ruleGroupProvider.Get(context.Background(), tc.userInfo, tc.cluster, tc.expectedRuleGroup.Name)
				if err != nil {
					t.Fatal(err)
				}
				assert.Equal(t, tc.expectedRuleGroup, ruleGroup)
			} else {
				if err == nil {
					t.Fatalf("expected error message")
				}
				assert.Equal(t, tc.expectedError, err.Error())
			}
		})
	}
}

func TestUpdateRuleGroup(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name              string
		existingObjects   []ctrlruntimeclient.Object
		userInfo          *provider.UserInfo
		cluster           *kubermaticv1.Cluster
		expectedRuleGroup *kubermaticv1.RuleGroup
		expectedError     string
	}{
		{
			name: "update ruleGroup type",
			existingObjects: []ctrlruntimeclient.Object{
				test.GenRuleGroup(testRuleGroupName, testRuleGroupClusterName, "FakeType", false),
			},
			userInfo:          &provider.UserInfo{Email: "john@acme.com", Groups: []string{"owners-abcd"}},
			cluster:           genCluster(testRuleGroupClusterName, "kubernetes", "my-first-project-ID", "test-rule-group", "john@acme.com"),
			expectedRuleGroup: test.GenRuleGroup(testRuleGroupName, testRuleGroupClusterName, kubermaticv1.RuleGroupTypeMetrics, false),
		},
		{
			name:              "update ruleGroup which doesn't exist",
			userInfo:          &provider.UserInfo{Email: "john@acme.com", Groups: []string{"owners-abcd"}},
			cluster:           genCluster(testRuleGroupClusterName, "kubernetes", "my-first-project-ID", "test-rule-group", "john@acme.com"),
			expectedRuleGroup: test.GenRuleGroup(testRuleGroupName, testRuleGroupClusterName, kubermaticv1.RuleGroupTypeMetrics, false),
			expectedError:     "rulegroups.kubermatic.k8c.io \"test-rule-group\" not found",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewClientBuilder().
				WithObjects(tc.existingObjects...).
				Build()
			fakeImpersonationClient := func(impCfg restclient.ImpersonationConfig) (ctrlruntimeclient.Client, error) {
				return client, nil
			}

			ruleGroupProvider := kubernetes.NewRuleGroupProvider(fakeImpersonationClient, client)
			if len(tc.expectedError) == 0 {
				currentRuleGroup, err := ruleGroupProvider.Get(context.Background(), tc.userInfo, tc.cluster, tc.expectedRuleGroup.Name)
				if err != nil {
					t.Fatal(err)
				}
				tc.expectedRuleGroup.ResourceVersion = currentRuleGroup.ResourceVersion
				_, err = ruleGroupProvider.Update(context.Background(), tc.userInfo, tc.expectedRuleGroup)
				if err != nil {
					t.Fatal(err)
				}
				ruleGroup, err := ruleGroupProvider.Get(context.Background(), tc.userInfo, tc.cluster, tc.expectedRuleGroup.Name)
				if err != nil {
					t.Fatal(err)
				}
				assert.Equal(t, tc.expectedRuleGroup, ruleGroup)
			} else {
				_, err := ruleGroupProvider.Update(context.Background(), tc.userInfo, tc.expectedRuleGroup)
				if err == nil {
					t.Fatalf("expected error message")
				}
				assert.Equal(t, tc.expectedError, err.Error())
			}
		})
	}
}

func TestDeleteRuleGroup(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name            string
		existingObjects []ctrlruntimeclient.Object
		userInfo        *provider.UserInfo
		cluster         *kubermaticv1.Cluster
		ruleGroupName   string
		expectedError   string
	}{
		{
			name: "delete ruleGroup",
			existingObjects: []ctrlruntimeclient.Object{
				test.GenRuleGroup(testRuleGroupName, testRuleGroupClusterName, "FakeType", false),
			},
			userInfo:      &provider.UserInfo{Email: "john@acme.com", Groups: []string{"owners-abcd"}},
			cluster:       genCluster(testRuleGroupClusterName, "kubernetes", "my-first-project-ID", "test-rule-group", "john@acme.com"),
			ruleGroupName: testRuleGroupName,
		},
		{
			name:          "delete ruleGroup which doesn't exist",
			userInfo:      &provider.UserInfo{Email: "john@acme.com", Groups: []string{"owners-abcd"}},
			cluster:       genCluster(testRuleGroupClusterName, "kubernetes", "my-first-project-ID", "test-rule-group", "john@acme.com"),
			ruleGroupName: testRuleGroupName,
			expectedError: "rulegroups.kubermatic.k8c.io \"test-rule-group\" not found",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewClientBuilder().
				WithObjects(tc.existingObjects...).
				Build()
			fakeImpersonationClient := func(impCfg restclient.ImpersonationConfig) (ctrlruntimeclient.Client, error) {
				return client, nil
			}

			ruleGroupProvider := kubernetes.NewRuleGroupProvider(fakeImpersonationClient, client)
			err := ruleGroupProvider.Delete(context.Background(), tc.userInfo, tc.cluster, tc.ruleGroupName)
			if len(tc.expectedError) == 0 {
				if err != nil {
					t.Fatal(err)
				}
				_, err = ruleGroupProvider.Get(context.Background(), tc.userInfo, tc.cluster, tc.ruleGroupName)
				assert.True(t, apierrors.IsNotFound(err))
			} else {
				if err == nil {
					t.Fatalf("expected error message")
				}
				assert.Equal(t, tc.expectedError, err.Error())
			}
		})
	}
}
