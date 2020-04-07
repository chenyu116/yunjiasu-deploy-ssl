package config

import (
  "github.com/spf13/viper"
  "k8s.io/klog"
  "time"
)

var c Config

func init() {
  viper.SetConfigType("yaml")
  viper.SetConfigName("config")
  viper.AddConfigPath("/mnt")
  viper.AddConfigPath(".")
}

func GetConfig() Config {
  return c
}

func GetCommonConfig() CommonConfig {
  return c.Common
}

func Get(key string) interface{} {
  return viper.Get(key)
}

func GetBool(key string) bool {
  return viper.GetBool(key)
}

func GetInt(key string) int {
  return viper.GetInt(key)
}

func GetString(key string) string {
  return viper.GetString(key)
}

func GetStringMapString(key string) map[string]string {
  return viper.GetStringMapString(key)
}
func GetStringSlice(key string) []string {
  return viper.GetStringSlice(key)
}

func IsSet(key string) bool {
  return viper.IsSet(key)
}

func Set(key string, value interface{}) {
  viper.Set(key, value)
}

type CommonConfig struct {
  BaseURL         string        `mapstructure:"baseURL"`
  SignatureMethod string        `mapstructure:"signatureMethod"`
  CheckInterval   time.Duration `mapstructure:"checkInterval"`
  SyncRetryTimes  int           `mapstructure:"syncRetryTimes"`
}

type CertConfig struct {
  Domain       string `mapstructure:"domain"`
  TlsName      string `mapstructure:"tlsName"`
  TlsNamespace string `mapstructure:"tlsNamespace"`
}
type SecretConfig struct {
  AccessKey string `mapstructure:"accessKey"`
  SecretKey string `mapstructure:"secretKey"`
}

type Config struct {
  Secret SecretConfig `mapstructure:"secret"`
  Certs  []CertConfig `mapstructure:"certs"`
  Common CommonConfig `mapstructure:"common"`
}

func SetConfigPath(path string) {
  viper.SetConfigFile(path)
}

func ReadConfig() {
  err := viper.ReadInConfig()
  klog.Infof("Using configuration file: %s", viper.ConfigFileUsed())

  if err != nil {
    klog.Fatal(err.Error())
  }

  err = viper.Unmarshal(&c)
  if err != nil {
    klog.Fatal(err.Error())
  }
}
