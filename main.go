package main

import (
	"github.com/chenyu116/yunjiasu-deploy-ssl/config"
	"github.com/chenyu116/yunjiasu-deploy-ssl/yunjiasu"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	"os"
	"time"
)

func main() {
	accessKey := os.Getenv("ACCESS_KEY")
	secretKey := os.Getenv("SECRET_KEY")
	if accessKey == "" {
		klog.Fatal("need ENV ACCESS_KEY")
	}
	if secretKey == "" {
		klog.Fatal("need ENV SECRET_KEY")
	}
	config.ReadConfig()
	cfg := config.GetConfig()
	if len(cfg.Certs) == 0 {
		klog.Fatal("no certificates")
	}
	cfg.Secret.AccessKey = accessKey
	cfg.Secret.SecretKey = secretKey

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
			klog.Infof("next check after %s", cfg.Common.CheckInterval)
		}

		time.Sleep(cfg.Common.CheckInterval)
	}
}
