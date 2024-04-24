// Copyright 2024 The Knative Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	_ "embed"
	"fmt"
	"strings"

	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"time"

	"github.com/go-logr/stdr"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	clog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

//go:embed ca.pem
var caCert []byte

//go:embed server-key.pem
var privateKey []byte

//go:embed server.pem
var webhookCert []byte

func main() {

	clog.SetLogger(stdr.New(log.Default()))

	block, _ := pem.Decode([]byte(webhookCert))

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal("failed to parse certs ", err)
	}

	block, _ = pem.Decode([]byte(privateKey))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal("failed to parse key", err)
	}

	// Create a manager
	cfg, err := ctrl.GetConfig()
	if err != nil {
		log.Print(err)
		time.Sleep(5 * time.Second)
		log.Fatal("failed to get config", err)
	}

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{})
	if err != nil {
		log.Print(err)
		time.Sleep(5 * time.Second)
		panic(err)
	}

	// Create a webhook server.
	hookServer := webhook.NewServer(webhook.Options{
		Port: 8443,
		TLSOpts: []func(*tls.Config){
			func(cfg *tls.Config) {
				cfg.RootCAs = x509.NewCertPool()
				cfg.RootCAs.AppendCertsFromPEM(caCert)

				cfg.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					return &tls.Certificate{
						PrivateKey: key,
						Certificate: [][]byte{
							cert.Raw,
						},
					}, nil
				}
			},
		},
	})

	if err := mgr.Add(hookServer); err != nil {
		panic(err)
	}

	// Register the webhooks in the server.
	hookServer.Register("/mutating", newAdmission(mgr.GetClient()))

	// Start the server by starting a previously-set-up manager
	log.Print("running server...")
	err = mgr.Start(ctrl.SetupSignalHandler())
	if err != nil {
		// handle error
		log.Print(err)
		time.Sleep(5 * time.Second)
		log.Fatal("failed to start server", err)
	}
}

func newAdmission(c client.Client) *webhook.Admission {
	return &webhook.Admission{
		Handler: admission.HandlerFunc(func(ctx context.Context, req webhook.AdmissionRequest) webhook.AdmissionResponse {
			bytes := req.Object.Raw
			obj := &unstructured.Unstructured{}

			log.Print("handling request")
			if err := json.Unmarshal(bytes, obj); err != nil {
				return webhook.Errored(401, fmt.Errorf("error parsing resource: %w", err))
			}

			for i, ref := range obj.GetOwnerReferences() {
				if len(strings.TrimSpace(string(ref.UID))) != 0 {
					continue
				}
				gv, err := schema.ParseGroupVersion(ref.APIVersion)
				if err != nil {
					return webhook.Errored(401, fmt.Errorf("error parsing owner APIVersion owner: %w", err))
				}

				gvk := gv.WithKind(ref.Kind)
				owner := &unstructured.Unstructured{}
				owner.SetGroupVersionKind(schema.GroupVersionKind{
					Group:   gvk.Group,
					Kind:    gvk.Kind,
					Version: gvk.Version,
				})

				err = c.Get(context.Background(), client.ObjectKey{
					Namespace: obj.GetNamespace(),
					Name:      ref.Name,
				}, owner)

				if err != nil {
					return webhook.Errored(401, fmt.Errorf("error fetching owner - unable to compute uid: %w", err))
				}

				uid := owner.GetUID()
				if len(strings.TrimSpace(string(uid))) == 0 {
					return webhook.Errored(401, fmt.Errorf("error fetching owner - unable to compute uid: %w", err))
				}

				patch := webhook.JSONPatchOp{Operation: "add", Path: fmt.Sprintf("/metadata/ownerReferences/%d/uid", i), Value: uid}
				log.Print("apply patch", patch)
				return webhook.Patched("patches", patch)
			}

			return webhook.Allowed("allowed")
		}),
	}
}
