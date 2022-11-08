// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package injector handles mutating webhook operations.
package injector

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/mattbaird/jsonpatch"
	"gvisor.dev/gvisor/pkg/log"
	admv1beta1 "k8s.io/api/admission/v1beta1"
	admregv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeclientset "k8s.io/client-go/kubernetes"
)

const (
	// Name is the name of the admission webhook service. The admission
	// webhook must be exposed in the following service; this is mainly for
	// the server certificate.
	Name = "gvisor-injection-admission-webhook"

	// serviceNamespace is the namespace of the admission webhook service.
	serviceNamespace = "e2e"

	fullName = Name + "." + serviceNamespace + ".svc"
)

// CreateConfiguration creates MutatingWebhookConfiguration and registers the
// webhook admission controller with the kube-apiserver. The webhook will only
// take effect on pods in the namespaces selected by `podNsSelector`. If `podNsSelector`
// is empty, the webhook will take effect on all pods.
func CreateConfiguration(clientset kubeclientset.Interface, selector *metav1.LabelSelector) error {
	fail := admregv1beta1.Fail

	config := &admregv1beta1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: Name,
		},
		Webhooks: []admregv1beta1.MutatingWebhook{
			{
				Name: fullName,
				ClientConfig: admregv1beta1.WebhookClientConfig{
					Service: &admregv1beta1.ServiceReference{
						Name:      Name,
						Namespace: serviceNamespace,
					},
					CABundle: caCert,
				},
				Rules: []admregv1beta1.RuleWithOperations{
					{
						Operations: []admregv1beta1.OperationType{
							admregv1beta1.Create,
						},
						Rule: admregv1beta1.Rule{
							APIGroups:   []string{"*"},
							APIVersions: []string{"*"},
							Resources:   []string{"pods"},
						},
					},
				},
				FailurePolicy:     &fail,
				NamespaceSelector: selector,
			},
		},
	}
	log.Infof("Creating MutatingWebhookConfiguration %q", config.Name)
	if _, err := clientset.AdmissionregistrationV1beta1().MutatingWebhookConfigurations().Create(config); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("failed to create MutatingWebhookConfiguration %q: %s", config.Name, err)
		}
		log.Infof("MutatingWebhookConfiguration %q already exists; use the existing one", config.Name)
	}
	return nil
}

// GetTLSConfig retrieves the CA cert that signed the cert used by the webhook.
func GetTLSConfig() *tls.Config {
	sc, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		log.Warningf("Failed to generate X509 key pair: %v", err)
		os.Exit(1)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{sc},
	}
}

// Admit performs admission checks and mutations on Pods.
func Admit(writer http.ResponseWriter, req *http.Request) {
	review := &admv1beta1.AdmissionReview{}
	if err := json.NewDecoder(req.Body).Decode(review); err != nil {
		log.Infof("Failed with error (%v) to decode Admit request: %+v", err, *req)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	log.Debugf("admitPod: %+v", review)
	var err error
	review.Response, err = admitPod(review.Request)
	if err != nil {
		log.Warningf("admitPod failed: %v", err)
		review.Response = &admv1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Reason:  metav1.StatusReasonInvalid,
				Message: err.Error(),
			},
		}
		sendResponse(writer, review)
		return
	}

	log.Debugf("Processed admission review: %+v", review)
	sendResponse(writer, review)
}

func sendResponse(writer http.ResponseWriter, response any) {
	b, err := json.Marshal(response)
	if err != nil {
		log.Warningf("Failed with error (%v) to marshal response: %+v", err, response)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	writer.WriteHeader(http.StatusOK)
	writer.Write(b)
}

func admitPod(req *admv1beta1.AdmissionRequest) (*admv1beta1.AdmissionResponse, error) {
	// Verify that the request is indeed a Pod.
	resource := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	if req.Resource != resource {
		return nil, fmt.Errorf("unexpected resource %+v in pod admission", req.Resource)
	}

	// Decode the request into a Pod.
	pod := &v1.Pod{}
	if err := json.Unmarshal(req.Object.Raw, pod); err != nil {
		return nil, fmt.Errorf("failed to decode pod object %s/%s", req.Namespace, req.Name)
	}

	// Copy first to change it.
	podCopy := pod.DeepCopy()
	updatePod(podCopy)
	patch, err := createPatch(req.Object.Raw, podCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to create patch for pod %s/%s (generatedName: %s)", pod.Namespace, pod.Name, pod.GenerateName)
	}

	log.Debugf("Patched pod %s/%s (generateName: %s): %+v", pod.Namespace, pod.Name, pod.GenerateName, podCopy)
	patchType := admv1beta1.PatchTypeJSONPatch
	return &admv1beta1.AdmissionResponse{
		Allowed:   true,
		Patch:     patch,
		PatchType: &patchType,
	}, nil
}

func updatePod(pod *v1.Pod) {
	gvisor := "gvisor"
	pod.Spec.RuntimeClassName = &gvisor

	// We don't run SELinux test for gvisor.
	// If SELinuxOptions are specified, this is usually for volume test to pass
	// on SELinux. This can be safely ignored.
	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.SELinuxOptions != nil {
		pod.Spec.SecurityContext.SELinuxOptions = nil
	}
	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]
		if c.SecurityContext != nil && c.SecurityContext.SELinuxOptions != nil {
			c.SecurityContext.SELinuxOptions = nil
		}
	}
	for i := range pod.Spec.InitContainers {
		c := &pod.Spec.InitContainers[i]
		if c.SecurityContext != nil && c.SecurityContext.SELinuxOptions != nil {
			c.SecurityContext.SELinuxOptions = nil
		}
	}
}

func createPatch(old []byte, newObj any) ([]byte, error) {
	new, err := json.Marshal(newObj)
	if err != nil {
		return nil, err
	}
	patch, err := jsonpatch.CreatePatch(old, new)
	if err != nil {
		return nil, err
	}
	return json.Marshal(patch)
}
