package main

import (
    "context"
    "crypto"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/hex"
    "encoding/pem"
    "fmt"
    "log"
    "os"
    "path/filepath"
    "sort"
    "strings"
    "time"

    "github.com/docker/docker/api/types"
    "github.com/docker/docker/api/types/filters"
    swm "github.com/docker/docker/api/types/swarm"
    docker "github.com/docker/docker/client"
    "github.com/go-acme/lego/v4/certificate"
    dnsprov "github.com/go-acme/lego/v4/providers/dns"
    "github.com/go-acme/lego/v4/lego"
    "github.com/go-acme/lego/v4/registration"
)

func env(key, def string) string {
    if v := os.Getenv(key); v != "" { return v }
    return def
}

func mustEnv(key string) string {
    v := os.Getenv(key)
    if v == "" { log.Fatalf("missing env %s", key) }
    return v
}

func sha256Hex(b []byte) string {
    h := sha256.Sum256(b)
    return hex.EncodeToString(h[:])
}

func main() {
    // Config
    // DOCKER_HOST 可选：若未设置且容器挂载了 /var/run/docker.sock，则默认走本地 unix socket
    // 先加载 PROVIDER_ENV_FILES，确保后续读取到 EAB_KID/EAB_HMAC 等变量
    loadEnvFiles(env("PROVIDER_ENV_FILES", ""))
    labels := env("EDGE_SERVICE_LABELS", env("EDGE_SERVICE_LABEL", "edge.cert.enabled=true"))
    interval := env("LOOP_INTERVAL", "12h")
    domainsCSV := env("DOMAINS", "")
    email := mustEnv("LEGO_EMAIL")
    provider := mustEnv("DNS_PROVIDER")
    renewDays := env("RENEW_DAYS", "30")
    keySet := env("KEY_SET", "ec256")
    acmeServer := env("ACME_SERVER", "")
    eabKid := env("EAB_KID", "")
    eabHmac := env("EAB_HMAC", "")
    certMode := strings.ToLower(env("CERT_MODE", "san")) // san | split
    retainN := parseInt(env("RETAIN_GENERATIONS", "2"), 2)
    persistDir := env("PERSIST_DIR", "/data/.lego")
    tlsCfgEnable := strings.EqualFold(env("TLS_CONFIG_ENABLE", "false"), "true")
    tlsCfgPrefix := env("TLS_CONFIG_NAME_PREFIX", "prod-edge-traefik-certs")
    tlsCfgTarget := env("TLS_CONFIG_TARGET", "/etc/traefik/dynamic/certs.yml")
    certExt := ensureDot(env("CERT_FILE_EXT", ".crt"))
    keyExt := ensureDot(env("KEY_FILE_EXT", ".key"))
    combinedPEM := strings.EqualFold(env("COMBINED_PEM_ENABLE", "false"), "true")
    pemExt := ensureDot(env("PEM_FILE_EXT", ".pem"))
    pemOrder := strings.ToLower(env("PEM_ORDER", "key-first")) // key-first | cert-first
    useTraefikNative := strings.EqualFold(env("EDGE_TRAEFIK_USE_NATIVE_LABELS", "true"), "true")

    d, err := time.ParseDuration(interval)
    if err != nil { d = 12 * time.Hour }

    // Prefer env; fallback to default socket; enable API version negotiation
    opts := []docker.Opt{docker.FromEnv, docker.WithAPIVersionNegotiation()}
    if h := os.Getenv("DOCKER_HOST"); h != "" {
        opts = append(opts, docker.WithHost(h))
    }
    cli, err := docker.NewClientWithOpts(opts...)
    if err != nil { log.Fatal(err) }
    defer cli.Close()

    for {
        ctx := context.Background()
        svcs, err := cli.ServiceList(ctx, types.ServiceListOptions{Filters: buildLabelFilter(labels)})
        if err != nil { log.Println("service list:", err) } else {
            if len(svcs) == 0 { log.Println("no service matched labels:", labels) }
            for _, s := range svcs {
                // Per-service overrides via labels
                svcLabels := s.Spec.Labels
                var domains []string
                if v := strings.TrimSpace(svcLabels["edge.cert.domains"]); v != "" {
                    domains = parseCSV(v)
                } else if v := strings.TrimSpace(svcLabels["edge.traefik.domains"]); v != "" {
                    domains = parseCSV(v)
                } else if useTraefikNative {
                    domains = extractTraefikDomains(svcLabels)
                } else if domainsCSV != "" {
                    domains = parseCSV(domainsCSV)
                }
                if len(domains) == 0 { log.Println("no domains provided for service:", s.Spec.Name); continue }
                svcKeySet := firstNonEmpty(strings.ToLower(svcLabels["edge.cert.key_set"]), keySet)
                svcRenew := firstNonEmpty(svcLabels["edge.cert.renew_days"], renewDays)
                svcMode := strings.ToLower(firstNonEmpty(svcLabels["edge.cert.mode"], certMode))
                // TLS config only when显式开启
                svcTlsEnable := tlsCfgEnable || equalTrue(svcLabels["edge.cert.tls_config_enable"]) 
                svcTlsTarget := firstNonEmpty(svcLabels["edge.cert.tls_config_target"], tlsCfgTarget)
                svcTlsPrefix := firstNonEmpty(svcLabels["edge.cert.tls_config_name_prefix"], tlsCfgPrefix)
                safeSvc := safeName(s.Spec.Name)
                ts := time.Now().Format("200601021504")
                var secretsToAdd []*swm.SecretReference
                var cfgName, cfgID string

                if svcMode == "split" {
                    if svcTlsEnable {
                        cfgName = fmt.Sprintf("%s-%s-%s", svcTlsPrefix, safeSvc, ts)
                    }
                    // Build certs.yml dynamically
                    var b strings.Builder
                    if svcTlsEnable { b.WriteString("tls:\n  certificates:\n") }
                    for _, dmn := range domains {
                        due, _ := isDueForRenew(filepath.Join(persistDir, dmn+".crt"), svcRenew)
                        var certPEM, keyPEM []byte
                        if due {
                            certPEM, keyPEM, err = obtainOrRenew(email, provider, svcKeySet, acmeServer, eabKid, eabHmac, []string{dmn})
                            if err != nil { log.Println("acme obtain:", dmn, err); continue }
                        } else {
                            certPEM, _ = os.ReadFile(filepath.Join(persistDir, dmn+".crt"))
                            keyPEM, _ = os.ReadFile(filepath.Join(persistDir, dmn+".key"))
                            if len(certPEM) == 0 || len(keyPEM) == 0 {
                                certPEM, keyPEM, err = obtainOrRenew(email, provider, svcKeySet, acmeServer, eabKid, eabHmac, []string{dmn})
                                if err != nil { log.Println("acme obtain:", dmn, err); continue }
                            }
                        }
                        _ = os.MkdirAll(persistDir, 0o755)
                        _ = os.WriteFile(filepath.Join(persistDir, dmn+".crt"), certPEM, 0o600)
                        _ = os.WriteFile(filepath.Join(persistDir, dmn+".key"), keyPEM, 0o600)

                        safe := safeName(dmn)
                        crtName := "tls-crt-" + safe + "-" + ts
                        keyName := "tls-key-" + safe + "-" + ts
                        // mount names seen inside container (human-friendly)
                        fileBase := strings.ReplaceAll(dmn, "*", "star")
                        mountCrt := fileBase + certExt
                        mountKey := fileBase + keyExt
                        crtID, err := createOrReplaceSecret(ctx, cli, crtName, certPEM)
                        if err != nil { log.Println("secret crt:", err); continue }
                        keyID, err := createOrReplaceSecret(ctx, cli, keyName, keyPEM)
                        if err != nil { log.Println("secret key:", err); continue }
                        secretsToAdd = append(secretsToAdd,
                            &swm.SecretReference{SecretID: crtID, SecretName: crtName, File: &swm.SecretReferenceFileTarget{Name: mountCrt, Mode: 0o400}},
                            &swm.SecretReference{SecretID: keyID, SecretName: keyName, File: &swm.SecretReferenceFileTarget{Name: mountKey, Mode: 0o400}},
                        )
                        if combinedPEM {
                            var pemCombined []byte
                            if pemOrder == "cert-first" {
                                pemCombined = append(append([]byte{}, certPEM...), '\n')
                                pemCombined = append(pemCombined, keyPEM...)
                            } else {
                                pemCombined = append(append([]byte{}, keyPEM...), '\n')
                                pemCombined = append(pemCombined, certPEM...)
                            }
                            pemName := "tls-pem-" + safe + "-" + ts
                            mountPem := fileBase + pemExt
                            pemID, err := createOrReplaceSecret(ctx, cli, pemName, pemCombined)
                            if err != nil { log.Println("secret pem:", err) } else {
                                secretsToAdd = append(secretsToAdd,
                                    &swm.SecretReference{SecretID: pemID, SecretName: pemName, File: &swm.SecretReferenceFileTarget{Name: mountPem, Mode: 0o400}},
                                )
                            }
                        }
                        if svcTlsEnable {
                            b.WriteString("    - certFile: /run/secrets/")
                            b.WriteString(mountCrt)
                            b.WriteString("\n      keyFile: /run/secrets/")
                            b.WriteString(mountKey)
                            b.WriteString("\n")
                        }
                    }
                    if svcTlsEnable {
                        data := []byte(b.String())
                        if id, err := createOrReplaceConfig(ctx, cli, cfgName, data); err != nil { log.Println("config:", err) } else { cfgID = id }
                    }
                } else { // san
                    mainDomain := domains[0]
                    // Decide renew window
                    due, _ := isDueForRenew(filepath.Join(persistDir, mainDomain+".crt"), svcRenew)
                    var certPEM, keyPEM []byte
                    if due {
                        certPEM, keyPEM, err = obtainOrRenew(email, provider, svcKeySet, acmeServer, eabKid, eabHmac, domains)
                        if err != nil { log.Println("acme obtain:", err); continue }
                    } else {
                        certPEM, _ = os.ReadFile(filepath.Join(persistDir, mainDomain+".crt"))
                        keyPEM, _ = os.ReadFile(filepath.Join(persistDir, mainDomain+".key"))
                        if len(certPEM) == 0 || len(keyPEM) == 0 {
                            certPEM, keyPEM, err = obtainOrRenew(email, provider, svcKeySet, acmeServer, eabKid, eabHmac, domains)
                            if err != nil { log.Println("acme obtain:", err); continue }
                        }
                    }
                    _ = os.MkdirAll(persistDir, 0o755)
                    _ = os.WriteFile(filepath.Join(persistDir, mainDomain+".crt"), certPEM, 0o600)
                    _ = os.WriteFile(filepath.Join(persistDir, mainDomain+".key"), keyPEM, 0o600)
                    mainSafe := safeName(mainDomain)
                    crtName := "tls-crt-" + mainSafe + "-" + ts
                    keyName := "tls-key-" + mainSafe + "-" + ts
                    fileBase := strings.ReplaceAll(mainDomain, "*", "star")
                    mountCrt := fileBase + certExt
                    mountKey := fileBase + keyExt
                    crtID, err := createOrReplaceSecret(ctx, cli, crtName, certPEM)
                    if err != nil { log.Println("secret crt:", err); continue }
                    keyID, err := createOrReplaceSecret(ctx, cli, keyName, keyPEM)
                    if err != nil { log.Println("secret key:", err); continue }
                    secretsToAdd = append(secretsToAdd,
                        &swm.SecretReference{SecretID: crtID, SecretName: crtName, File: &swm.SecretReferenceFileTarget{Name: mountCrt, Mode: 0o400}},
                        &swm.SecretReference{SecretID: keyID, SecretName: keyName, File: &swm.SecretReferenceFileTarget{Name: mountKey, Mode: 0o400}},
                    )
                    if combinedPEM {
                        var pemCombined []byte
                        if pemOrder == "cert-first" {
                            pemCombined = append(append([]byte{}, certPEM...), '\n')
                            pemCombined = append(pemCombined, keyPEM...)
                        } else {
                            pemCombined = append(append([]byte{}, keyPEM...), '\n')
                            pemCombined = append(pemCombined, certPEM...)
                        }
                        pemName := "tls-pem-" + mainSafe + "-" + ts
                        mountPem := fileBase + pemExt
                        pemID, err := createOrReplaceSecret(ctx, cli, pemName, pemCombined)
                        if err != nil { log.Println("secret pem:", err) } else {
                            secretsToAdd = append(secretsToAdd,
                                &swm.SecretReference{SecretID: pemID, SecretName: pemName, File: &swm.SecretReferenceFileTarget{Name: mountPem, Mode: 0o400}},
                            )
                        }
                    }
                    if svcTlsEnable {
                        cfgName = fmt.Sprintf("%s-%s-%s", svcTlsPrefix, safeSvc, ts)
                        data := []byte("tls:\n  certificates:\n    - certFile: /run/secrets/" + mountCrt + "\n      keyFile: /run/secrets/" + mountKey + "\n")
                        if id, err := createOrReplaceConfig(ctx, cli, cfgName, data); err != nil { log.Println("config:", err) } else { cfgID = id }
                    }
                }

                // Update service: replace any previous refs and apply new ones
                if err := updateServiceSecretsAndConfigs(ctx, cli, s, secretsToAdd, svcTlsEnable, cfgID, cfgName, svcTlsPrefix, svcTlsTarget); err != nil {
                    log.Println("service update:", err)
                } else {
                    log.Println("updated service:", s.Spec.Name)
                    // GC old secrets/configs beyond retention
                    if err := gcOldSecrets(ctx, cli, s, retainN); err != nil { log.Println("gc secrets:", err) }
                    if svcTlsEnable { if err := gcOldConfigs(ctx, cli, s, svcTlsPrefix, retainN); err != nil { log.Println("gc configs:", err) } }
                }
            }
        }
        time.Sleep(d)
    }
}

func buildLabelFilter(csv string) filters.Args {
    f := filters.NewArgs()
    for _, kv := range strings.Split(csv, ",") {
        kv = strings.TrimSpace(kv)
        if kv == "" { continue }
        parts := strings.SplitN(kv, "=", 2)
        if len(parts) != 2 { continue }
        f.Add("label", fmt.Sprintf("%s=%s", parts[0], parts[1]))
    }
    return f
}

// ACME with lego (DNS-01)
func obtainOrRenew(email, provider, keySet, acmeServer, eabKid, eabHmac string, domains []string) ([]byte, []byte, error) {
    // minimal user with in-memory key (new each run is fine when reuse-key true)
    u := &legoUser{email: email}
    u.generateKey(keySet)
    cfg := lego.NewConfig(u)
    if acmeServer != "" { cfg.CADirURL = acmeServer }
    client, err := lego.NewClient(cfg)
    if err != nil { return nil, nil, err }
    // DNS provider via env
    prov, err := dnsprov.NewDNSChallengeProviderByName(provider)
    if err != nil { return nil, nil, err }
    if err := client.Challenge.SetDNS01Provider(prov); err != nil { return nil, nil, err }
    if eabKid != "" && eabHmac != "" {
        if _, err = client.Registration.RegisterWithExternalAccountBinding(
            registration.RegisterEABOptions{Kid: eabKid, HmacEncoded: eabHmac, TermsOfServiceAgreed: true},
        ); err != nil { return nil, nil, err }
    } else {
        if _, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true}); err != nil { return nil, nil, err }
    }
    // Obtain
    req := certificate.ObtainRequest{Domains: domains, Bundle: true}
    res, err := client.Certificate.Obtain(req)
    if err != nil { return nil, nil, err }
    return res.Certificate, res.PrivateKey, nil
}

type legoUser struct { email string; key crypto.PrivateKey }
func (u *legoUser) GetEmail() string                        { return u.email }
func (u *legoUser) GetRegistration() *registration.Resource { return nil }
func (u *legoUser) GetPrivateKey() crypto.PrivateKey        { return u.key }
func (u *legoUser) generateKey(keySet string) {
    switch keySet {
    case "rsa2048": k, _ := rsa.GenerateKey(rand.Reader, 2048); u.key = k
    case "rsa4096": k, _ := rsa.GenerateKey(rand.Reader, 4096); u.key = k
    case "ec384": u.key, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
    default: u.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    }
}

func isDueForRenew(certPath, renewDaysStr string) (bool, error) {
    b, err := os.ReadFile(certPath)
    if err != nil { return true, nil } // no cert -> need obtain
    block, _ := pem.Decode(b)
    if block == nil { return true, nil }
    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil { return true, nil }
    days := 30
    if v, err := time.ParseDuration(renewDaysStr+"24h"); err == nil { days = int(v.Hours()/24) }
    renewAt := cert.NotAfter.AddDate(0, 0, -days)
    return time.Now().After(renewAt), nil
}

func createOrReplaceSecret(ctx context.Context, cli *docker.Client, name string, data []byte) (string, error) {
    // delete if exists
    lst, err := cli.SecretList(ctx, types.SecretListOptions{Filters: filters.NewArgs(filters.Arg("name", name))})
    if err == nil && len(lst) > 0 {
        _ = cli.SecretRemove(ctx, lst[0].ID)
    }
    id, err := cli.SecretCreate(ctx, swm.SecretSpec{Annotations: swm.Annotations{Name: name}, Data: data})
    if err != nil { return "", err }
    return id.ID, nil
}

func createOrReplaceConfig(ctx context.Context, cli *docker.Client, name string, data []byte) (string, error) {
    lst, err := cli.ConfigList(ctx, types.ConfigListOptions{Filters: filters.NewArgs(filters.Arg("name", name))})
    if err == nil && len(lst) > 0 { _ = cli.ConfigRemove(ctx, lst[0].ID) }
    id, err := cli.ConfigCreate(ctx, swm.ConfigSpec{Annotations: swm.Annotations{Name: name}, Data: data})
    if err != nil { return "", err }
    return id.ID, nil
}

func updateServiceSecretsAndConfigs(ctx context.Context, cli *docker.Client, svc swm.Service, newSecrets []*swm.SecretReference, withCfg bool, cfgID, cfgName, cfgPrefix, cfgTarget string) error {
    inspect, _, err := cli.ServiceInspectWithRaw(ctx, svc.ID, types.ServiceInspectOptions{})
    if err != nil { return err }
    spec := inspect.Spec
    cs := spec.TaskTemplate.ContainerSpec
    // 清理旧前缀的动态 secrets（split 模式会大量增加，先移除同前缀再追加新集合）
    kept := make([]*swm.SecretReference, 0, len(cs.Secrets))
    for _, r := range cs.Secrets {
        if strings.HasPrefix(r.SecretName, "tls-crt-") || strings.HasPrefix(r.SecretName, "tls-key-") || strings.HasPrefix(r.SecretName, "tls-pem-") {
            // 移除旧的版本化证书条目
            continue
        }
        kept = append(kept, r)
    }
    cs.Secrets = append(kept, newSecrets...)

    // Configs update (optional)
    if withCfg {
        cfgs := make([]*swm.ConfigReference, 0, len(cs.Configs)+1)
        for _, c := range cs.Configs {
            if strings.HasPrefix(c.ConfigName, cfgPrefix+"-") { continue }
            cfgs = append(cfgs, c)
        }
        cfgs = append(cfgs, &swm.ConfigReference{ConfigID: cfgID, ConfigName: cfgName, File: &swm.ConfigReferenceFileTarget{Name: cfgTarget, Mode: 0o444}})
        cs.Configs = cfgs
    }

    // Ensure start-first
    if spec.UpdateConfig == nil { spec.UpdateConfig = &swm.UpdateConfig{} }
    spec.UpdateConfig.Order = swm.UpdateOrderStartFirst
    spec.TaskTemplate.ContainerSpec = cs
    // bump force update
    spec.TaskTemplate.ForceUpdate++
    _, err = cli.ServiceUpdate(ctx, svc.ID, inspect.Version, spec, types.ServiceUpdateOptions{})
    return err
}

func parseCSV(csv string) []string {
    out := []string{}
    for _, s := range strings.Split(csv, ",") {
        s = strings.TrimSpace(s)
        if s != "" { out = append(out, s) }
    }
    return out
}

func parseInt(s string, def int) int {
    if s == "" { return def }
    var n int
    if _, err := fmt.Sscanf(s, "%d", &n); err == nil && n > 0 { return n }
    return def
}

type secRef struct{ ID, Name, TS, Kind, Group string }

func splitSecretName(name string) (kind, group, ts string, ok bool) {
    // tls-crt-<safe>-<ts> / tls-key-<safe>-<ts> （仅新标准）
    if strings.HasPrefix(name, "tls-crt-") { kind = "crt" } else if strings.HasPrefix(name, "tls-key-") || strings.HasPrefix(name, "tls-pem-") { kind = "key" } else { return "", "", "", false }
    rest := strings.TrimPrefix(strings.TrimPrefix(name, "tls-crt-"), "tls-key-")
    rest = strings.TrimPrefix(rest, "tls-pem-")
    parts := strings.Split(rest, "-")
    if len(parts) < 2 { return "", "", "", false }
    group = strings.Join(parts[:len(parts)-1], "-")
    ts = parts[len(parts)-1]
    if len(ts) < 8 { return "", "", "", false }
    return kind, group, ts, true
}

func gcOldSecrets(ctx context.Context, cli *docker.Client, svc swm.Service, retain int) error {
    // collect current referenced secret names to protect
    cur := map[string]struct{}{}
    for _, r := range svc.Spec.TaskTemplate.ContainerSpec.Secrets {
        cur[r.SecretName] = struct{}{}
    }
    lst, err := cli.SecretList(ctx, types.SecretListOptions{})
    if err != nil { return err }
    groups := map[string][]secRef{}
    for _, s := range lst {
        if !(strings.HasPrefix(s.Spec.Name, "tls-crt-") || strings.HasPrefix(s.Spec.Name, "tls-key-") || strings.HasPrefix(s.Spec.Name, "tls-pem-")) { continue }
        if _, protected := cur[s.Spec.Name]; protected { continue }
        kind, group, ts, ok := splitSecretName(s.Spec.Name)
        if !ok { continue }
        key := kind+"/"+group
        groups[key] = append(groups[key], secRef{ID: s.ID, Name: s.Spec.Name, TS: ts, Kind: kind, Group: group})
    }
    for _, arr := range groups {
        sort.Slice(arr, func(i, j int) bool { return arr[i].TS < arr[j].TS })
        for i := 0; i < len(arr)-retain; i++ {
            _ = cli.SecretRemove(ctx, arr[i].ID)
        }
    }
    return nil
}

func gcOldConfigs(ctx context.Context, cli *docker.Client, svc swm.Service, prefix string, retain int) error {
    // 仅按“当前服务”的配置前缀清理：<prefix>-<safeSvc>-<ts>
    safeSvc := safeName(svc.Spec.Name)
    svcPrefix := prefix + "-" + safeSvc + "-"
    // current attached configs to protect
    cur := map[string]struct{}{}
    for _, c := range svc.Spec.TaskTemplate.ContainerSpec.Configs { cur[c.ConfigName] = struct{}{} }
    lst, err := cli.ConfigList(ctx, types.ConfigListOptions{})
    if err != nil { return err }
    type cfgRef struct{ ID, Name, TS string }
    arr := []cfgRef{}
    for _, c := range lst {
        if !strings.HasPrefix(c.Spec.Name, svcPrefix) { continue }
        if _, ok := cur[c.Spec.Name]; ok { continue }
        ts := c.Spec.Name[len(svcPrefix):]
        arr = append(arr, cfgRef{ID: c.ID, Name: c.Spec.Name, TS: ts})
    }
    sort.Slice(arr, func(i, j int) bool { return arr[i].TS < arr[j].TS })
    for i := 0; i < len(arr)-retain; i++ { _ = cli.ConfigRemove(ctx, arr[i].ID) }
    return nil
}

func loadEnvFiles(csv string) {
    for _, kv := range strings.Split(csv, ",") {
        kv = strings.TrimSpace(kv)
        if kv == "" { continue }
        parts := strings.SplitN(kv, "=", 2)
        if len(parts) != 2 { continue }
        path := parts[1]
        b, err := os.ReadFile(path)
        if err != nil { log.Println("env file read:", path, err); continue }
        os.Setenv(parts[0], strings.TrimSpace(string(b)))
    }
}

// helpers
func firstNonEmpty(vals ...string) string {
    for _, v := range vals { if strings.TrimSpace(v) != "" { return v } }
    return ""
}

func equalTrue(v string) bool {
    return strings.EqualFold(strings.TrimSpace(v), "true") || strings.EqualFold(strings.TrimSpace(v), "1") || strings.EqualFold(strings.TrimSpace(v), "yes")
}

func safeName(s string) string {
    // make it docker-resource-name friendly, not for file paths
    r := strings.NewReplacer("*", "star", ".", "-", "/", "-", ":", "-", " ", "-", "_", "-")
    out := r.Replace(strings.ToLower(s))
    // trim to RFC 1123: start/end must be alnum; collapse duplicates
    out = strings.Trim(out, "-")
    for strings.Contains(out, "--") { out = strings.ReplaceAll(out, "--", "-") }
    if out == "" { out = "x" }
    return out
}

func ensureDot(ext string) string {
    if ext == "" { return "" }
    if strings.HasPrefix(ext, ".") { return ext }
    return "." + ext
}

// Extracts domains from native Traefik labels, e.g.:
// traefik.http.routers.<name>.rule=Host(`a.example.com`,`b.example.com`) or Host(`example.com`) || Host(`*.a.example.com`)
func extractTraefikDomains(lbls map[string]string) []string {
    out := map[string]struct{}{}
    for k, v := range lbls {
        if !strings.HasPrefix(k, "traefik.http.routers.") || !strings.HasSuffix(k, ".rule") { continue }
        s := v
        // very lightweight parse: find Host(`...`)
        idx := 0
        for {
            h := strings.Index(s[idx:], "Host(")
            if h < 0 { break }
            start := idx + h + len("Host(")
            // find matching ')'
            end := strings.Index(s[start:], ")")
            if end < 0 { break }
            inside := s[start : start+end]
            // split by ',' and strip quotes/backticks
            for _, seg := range strings.Split(inside, ",") {
                seg = strings.TrimSpace(seg)
                seg = strings.Trim(seg, "`\"")
                if seg != "" { out[seg] = struct{}{} }
            }
            idx = start + end + 1
        }
    }
    // flatten
    res := make([]string, 0, len(out))
    for d := range out { res = append(res, d) }
    sort.Strings(res)
    return res
}


