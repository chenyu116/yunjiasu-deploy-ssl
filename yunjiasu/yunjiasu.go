package yunjiasu

import (
  "bytes"
  "context"
  "crypto/hmac"
  "crypto/sha1"
  "crypto/x509"
  "encoding/base64"
  "encoding/json"
  "encoding/pem"
  "github.com/chenyu116/yunjiasu-deploy-ssl/config"
  "io/ioutil"
  metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
  "k8s.io/client-go/kubernetes"
  "k8s.io/klog"
  "net/http"
  "sort"
  "strconv"
  "strings"
  "sync"
  "time"
)

// 签名算法
const (
  SIGN_METHOD      string = "HMAC-SHA1"
  OPENAPI_BASE_URL string = "https://api.su.baidu.com/"
  PATH             string = "v3/yjs/custom_certificates"

  STATUS_PENDING  = 0
  STATUS_UPLOADED = 1
  STATUS_DEPLOYED = 2
  STATUS_DELETED  = 4
  STATUS_RENAMED  = 8
)

type yunjiasuResponse_messages struct {
  ClientUuid string `json:"client_uuid"`
}

type yunjiasuResponse_result_custom_certificate struct {
  Info         string   `json:"info"`
  Hosts        []string `json:"hosts"`
  HostsContent string   `json:"hosts_content"`
  Issuer       string   `json:"issuer"`
  ExpiresOn    string   `json:"expires_on"`
  Switch       int      `json:"switch"`
  Id           string   `json:"id"`
}
type yunjiasuResponse_result_custom_certificates struct {
  yunjiasuResponse
  Result []yunjiasuResponse_result_custom_certificate `json:"result"`
}

type yunjiasuResponse_custom_certificate struct {
  yunjiasuResponse
  Result yunjiasuResponse_result_custom_certificate `json:"result"`
}

type yunjiasuResponse struct {
  Success  bool                        `json:"success"`
  Errors   []string                    `json:"errors"`
  Messages []yunjiasuResponse_messages `json:"messages"`
}

func NewYunjiasu(cfg config.Config) *yunjiasu {
  if cfg.Common.BaseURL == "" {
    cfg.Common.BaseURL = OPENAPI_BASE_URL
  }
  if cfg.Common.SignatureMethod == "" {
    cfg.Common.SignatureMethod = SIGN_METHOD
  }
  return &yunjiasu{cfg: cfg, certs: make(map[string]yunjiasuCert, len(cfg.Certs))}
}

type yunjiasuCert struct {
  Domain       string    `json:"domain"`
  TlsName      string    `json:"tls_name"`
  TlsNamespace string    `json:"tls_namespace"`
  CertId       string    `json:"cert_id"`
  ExpiresOn    time.Time `json:"expires_on"`
  TlsNotAfter  time.Time `json:"tls_not_after"`
  TlsCrt       []byte    `json:"tls_crt"`
  TlsKey       []byte    `json:"tls_key"`
  Status       int       `json:"status"`
}

type yunjiasu struct {
  cfg          config.Config
  mu           sync.Mutex
  certs        map[string]yunjiasuCert
  k8sClientset *kubernetes.Clientset
  processing   bool
}

func (y *yunjiasu) getInitedCommonParamsMap(authPathInfo string) map[string]string {
  authTimestamp := strconv.FormatInt(time.Now().Unix(), 10)

  paramMap := map[string]string{
    "X-Auth-Access-Key":       y.cfg.Secret.AccessKey,
    "X-Auth-Nonce":            authTimestamp,
    "X-Auth-Path-Info":        authPathInfo,
    "X-Auth-Signature-Method": y.cfg.Common.SignatureMethod,
    "X-Auth-Timestamp":        authTimestamp,
  }

  return paramMap
}

//排序并拼接参数
func (y *yunjiasu) getParsedAllParams(paramMap map[string]string) string {
  var paramList []string

  for k, v := range paramMap {
    var buffer bytes.Buffer
    buffer.WriteString(k)
    buffer.WriteString("=")
    buffer.WriteString(v)

    paramList = append(paramList, buffer.String())
  }

  sort.Strings(paramList)

  return strings.Join(paramList, "&")
}

//获取请求的header
func (y *yunjiasu) getRequestHeader(path string, bizParamsMap map[string]string) map[string]string {
  commonParamsMap := y.getInitedCommonParamsMap(path)
  allParamsMap := make(map[string]string)
  headersMap := make(map[string]string)

  for k, v := range commonParamsMap {
    headersMap[k] = v
  }

  for k, v := range commonParamsMap {
    allParamsMap[k] = v
  }

  for k, v := range bizParamsMap {
    allParamsMap[k] = v
  }

  allParamsStr := y.getParsedAllParams(allParamsMap)

  sign := y.getSignature(y.cfg.Secret.SecretKey, allParamsStr)

  headersMap["X-Auth-Sign"] = sign

  return headersMap
}

//发送http请求
func (y *yunjiasu) request(method string, path string, bizParamsMap map[string]string,
  headers map[string]string) ([]byte, error) {
  url := OPENAPI_BASE_URL + path

  params, err := json.Marshal(bizParamsMap)
  if err != nil {
    return nil, err
  }

  payload := strings.NewReader(string(params))
  ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
  defer cancel()
  req, err := http.NewRequestWithContext(ctx, method, url, payload)
  if err != nil {
    return nil, err
  }

  for k, v := range headers {
    req.Header.Add(k, v)
  }

  res, _ := http.DefaultClient.Do(req)

  defer res.Body.Close()
  body, err := ioutil.ReadAll(res.Body)
  if err != nil {
    return nil, err
  }
  return body, nil
}

func (y *yunjiasu) getSignature(secKey string, text string) string {
  key := []byte(secKey)
  mac := hmac.New(sha1.New, key)
  mac.Write([]byte(text))

  return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func (y *yunjiasu) saveCert(cert yunjiasuCert) {
  y.mu.Lock()
  y.certs[cert.TlsName] = cert
  y.mu.Unlock()
}

func (y *yunjiasu) Processing() bool {
  return y.processing
}

func (y *yunjiasu) Start() {
  y.processing = true
}

func (y *yunjiasu) Stop() {
  y.processing = false
}
func (y *yunjiasu) SetK8sClientset(clientset *kubernetes.Clientset) {
  y.k8sClientset = clientset
}
func (y *yunjiasu) deleteYunjiasuCert(cert yunjiasuCert) error {
  paramMap := map[string]string{
    "domain": cert.Domain,
    "info":   cert.TlsName,
  }
  headersMap := y.getRequestHeader(PATH, paramMap)
  body, err := y.request("DELETE", PATH, paramMap, headersMap)
  if err != nil {
    return err
  }
  var resp yunjiasuResponse_custom_certificate
  err = json.Unmarshal(body, &resp)
  if err != nil {
    return err
  }
  return nil
}
func (y *yunjiasu) renameYunjiasuCert(cert yunjiasuCert) error {
  paramMap := map[string]string{
    "domain":   cert.Domain,
    "info":     cert.TlsName + "_temp",
    "new_info": cert.TlsName,
    "switch":   "1",
  }
  headersMap := y.getRequestHeader(PATH, paramMap)
  body, err := y.request("PATCH", PATH, paramMap, headersMap)
  if err != nil {
    return err
  }
  var resp yunjiasuResponse_custom_certificate
  err = json.Unmarshal(body, &resp)
  if err != nil {
    return err
  }
  return nil
}
func (y *yunjiasu) deployYunjiasuCert(cert yunjiasuCert) error {
  paramMap := map[string]string{
    "domain":   cert.Domain,
    "info":     cert.TlsName + "_upload",
    "new_info": cert.TlsName + "_temp",
    "switch":   "1",
  }
  headersMap := y.getRequestHeader(PATH, paramMap)
  body, err := y.request("PATCH", PATH, paramMap, headersMap)
  if err != nil {
    return err
  }
  var resp yunjiasuResponse_custom_certificate
  err = json.Unmarshal(body, &resp)
  if err != nil {
    return err
  }
  return nil
}
func (y *yunjiasu) uploadYunjiasuCert(cert yunjiasuCert) error {
  paramMap := map[string]string{
    "domain":      cert.Domain,
    "info":        cert.TlsName + "_upload",
    "certificate": string(cert.TlsCrt),
    "private_key": string(cert.TlsKey),
  }
  headersMap := y.getRequestHeader(PATH, paramMap)
  body, err := y.request("POST", PATH, paramMap, headersMap)
  if err != nil {
    return err
  }
  var resp yunjiasuResponse_custom_certificate
  err = json.Unmarshal(body, &resp)
  if err != nil {
    return err
  }
  return nil
}

func (y *yunjiasu) CheckCerts() {
  klog.Info("[CheckCerts] start checking certs")
  var wg sync.WaitGroup
  wg.Add(len(y.certs))
  for _, v := range y.certs {
    go func(cert yunjiasuCert) {
      defer func() {
        klog.Infof("[CheckCerts] checking %s finished",cert.TlsName)
        wg.Done()
      }()
      klog.Infof("[CheckCerts] checking %s",cert.TlsName)
      if cert.ExpiresOn.Before(cert.TlsNotAfter) {
        var err error
        for i := 0; i < y.cfg.Common.SyncRetryTimes; i++ {
          if cert.Status&STATUS_UPLOADED == 0 {
            err = y.uploadYunjiasuCert(cert)
            if err != nil {
              klog.Errorf("[%s > %s] uploadYunjiasuCert: %s", cert.Domain, cert.TlsName, err.Error())
              continue
            }
            cert.Status = STATUS_UPLOADED
          }
          if cert.Status&STATUS_DEPLOYED == 0 {
            err = y.deployYunjiasuCert(cert)
            if err != nil {
              klog.Errorf("[%s > %s] deployYunjiasuCert: %s", cert.Domain, cert.TlsName, err.Error())
              continue
            }
            cert.Status = cert.Status | STATUS_DEPLOYED
          }
          if cert.CertId != "" && cert.Status&STATUS_DELETED == 0 {
            err = y.deleteYunjiasuCert(cert)
            if err != nil {
              klog.Errorf("[%s > %s] deleteYunjiasuCert: %s", cert.Domain, cert.TlsName, err.Error())
              continue
            }
            cert.Status = cert.Status | STATUS_DELETED
          }
          if v.Status&STATUS_RENAMED == 0 {
            err = y.renameYunjiasuCert(cert)
            if err != nil {
              klog.Errorf("[%s > %s] renameYunjiasuCert: %s", cert.Domain, cert.TlsName, err.Error())
              continue
            }
            cert.Status = cert.Status | STATUS_RENAMED
          }
          cert.ExpiresOn = cert.TlsNotAfter
          y.saveCert(cert)
          return
        }
      }
    }(v)
  }
  wg.Wait()
  klog.Info("[CheckCerts] finished")
}

func (y *yunjiasu) SyncK8sCerts() {
  klog.Info("[SyncK8sCerts] synchronize k8s certs")
  for _, v := range y.certs {
    s, err := y.k8sClientset.CoreV1().Secrets(v.TlsNamespace).Get(v.TlsName, metav1.GetOptions{})
    if err != nil {
      klog.Errorf("[SyncK8sCerts] %s", err.Error())
      continue
    }
    certDERBlock, _ := pem.Decode(s.Data["tls.crt"])
    if certDERBlock == nil {
      klog.Infof("[SyncK8sCerts] %s tls.crt is empty", v.TlsName)
      continue
    }
    x509Cert, err := x509.ParseCertificate(certDERBlock.Bytes)
    if err != nil {
      klog.Errorf("[SyncK8sCerts] %s", err.Error())
      continue
    }

    v.TlsNotAfter = x509Cert.NotAfter
    v.TlsCrt = s.Data["tls.crt"]
    v.TlsKey = s.Data["tls.key"]
    y.saveCert(v)
  }
  klog.Info("[SyncK8sCerts] k8s certs synchronized")
}

func (y *yunjiasu) Reset() {
  klog.Info("[Reset] certificates")
  y.certs = make(map[string]yunjiasuCert,len(y.cfg.Certs))
}
func (y *yunjiasu) SyncYunjiasuCerts() {
  klog.Info("[SyncYunjiasuCerts] synchronize yunjiasu certs")
  var wg sync.WaitGroup
  wg.Add(len(y.cfg.Certs))
  for _, v := range y.cfg.Certs {
    go func(cert config.CertConfig) {
      defer wg.Done()
      if cert.TlsName == "" || cert.Domain == "" || cert.TlsNamespace == "" {
        return
      }
      var resp yunjiasuResponse_result_custom_certificates
      cr := yunjiasuCert{
        Domain:       cert.Domain,
        TlsName:      cert.TlsName,
        TlsNamespace: cert.TlsNamespace,
      }

      for i := 0; i < y.cfg.Common.SyncRetryTimes; i++ {
        paramMap := map[string]string{
          "domain": cert.Domain,
        }

        headersMap := y.getRequestHeader(PATH, paramMap)

        body, err := y.request("GET", PATH+"?domain="+cert.Domain, paramMap, headersMap)
        if err != nil {
          klog.Errorf("[SyncYunjiasuCerts] %s", err.Error())
        }
        if err == nil {
          err = json.Unmarshal(body, &resp)
          if err != nil {
            klog.Errorf("[SyncYunjiasuCerts] %s", err.Error())
          }
          if err == nil {
            if len(resp.Result) == 0 {
              break
            }
            for _, r := range resp.Result {
              if r.Info != cert.TlsName {
                continue
              }
              expireOn, err := time.Parse(time.RFC3339, r.ExpiresOn)
              if err != nil {
                klog.Errorf("[SyncYunjiasuCerts] parse time to RFC3339 fail: %s", err.Error())
                continue
              }
              cr.ExpiresOn = expireOn
              cr.Status = STATUS_PENDING
              cr.CertId = r.Id
            }
            break
          }
        }
        klog.Error("[SyncYunjiasuCerts] waiting for retry")
        time.Sleep(time.Second * 10)
      }
      y.saveCert(cr)
    }(v)
  }
  wg.Wait()
  klog.Info("[SyncYunjiasuCerts] yunjiasu certs synchronized")
}
