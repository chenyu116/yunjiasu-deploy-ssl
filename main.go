package main

import (
	"github.com/chenyu116/yunjiasu-deploy-ssl/config"
	"github.com/chenyu116/yunjiasu-deploy-ssl/yunjiasu"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog"
	"time"
)

func main() {
	config.ReadConfig()
	cfg := config.GetConfig()
	if cfg.Secret.AccessKey == "" {
		klog.Fatal("need accessKey")
	}
	if cfg.Secret.SecretKey == "" {
		klog.Fatal("need secretKey")
	}

	if len(cfg.Certs) == 0 {
		klog.Fatal("need certificates")
	}

	k8sConfig, err := rest.InClusterConfig()
	if err != nil {
		klog.Fatal(err)
	}
	clientSet, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		klog.Fatal(err)
	}
	y := yunjiasu.NewYunjiasu(cfg)
	y.SetK8sClientset(clientSet)
	for {
		if !y.Processing() {
			y.Start()
			y.SyncYunjiasuCerts()
			y.SyncK8sCerts()
			y.CheckCerts()
			y.Reset()
			y.Stop()
			klog.Infof("next check after %s",cfg.Common.CheckInterval)
		}

		time.Sleep(cfg.Common.CheckInterval)
	}
}
