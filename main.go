package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/pkg/errors"

	"github.com/namsral/flag"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
)

const (
	annotationPrefix string = "dnslb/"
)

type Service struct {
	Name      string
	Namespace string
	IPs       []string
}

type Domain struct {
	Name         string
	Flags        map[string]bool
	NodeSelector string
	Service      *Service
}

var (
	podSelector       string
	podNamespace      string
	concurrency       int
	ingressNamespace  string
	nodeSelector      string
	nodeAddressType   string
	dryRun            bool
	jsonLog           bool
	cfAPIKey          string
	cfAPIEmail        string
	kubeconfig        string
	checkInterval     int
	fullCheckInterval int
	daemon            bool
	verbose           bool
)

func main() {
	flag.Parse()
	if err := validate(); err != nil {
		fmt.Printf("bad args: %v", err)
	}
	if verbose {
		log.SetLevel(log.DebugLevel)
	}
	if jsonLog {
		log.SetFormatter(&log.JSONFormatter{})
	} else {
		log.SetFormatter(&log.TextFormatter{
			DisableColors: true,
			FullTimestamp: true,
		})
	}
	ips := []string{}
	domains := map[string]Domain{}
	var err error
	if daemon {
		checkTicker := time.NewTicker(time.Duration(checkInterval) * time.Second)
		fullCheckTicker := time.NewTicker(time.Duration(fullCheckInterval) * time.Second)
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		fullCheck := false
		for {
			select {
			case sig := <-sigs:
				fmt.Printf("exit %v", sig)
				return
			case <-fullCheckTicker.C:
				fullCheck = true
			case <-checkTicker.C:
				log.Debug("Start checking")
				if fullCheck {
					log.Debug("Clearing ips and domains cache for full check")
					ips = []string{}
					domains = map[string]Domain{}
					fullCheck = false
				}
				if ips, domains, err = run(ips, domains); err != nil {
					log.WithError(err).Warn("got error")
				}
			}
		}
	} else {
		if _, _, err = run(ips, domains); err != nil {
			log.WithError(err).Warn("got error")
		}
	}
}
func validate() error {
	if cfAPIKey == "" || cfAPIEmail == "" {
		return errors.Errorf("Cloudflare ApiKey and Email MUST be defined")
	}
	if podSelector == "" {
		return errors.Errorf("pod selector MUST be defined")
	}
	if nodeAddressType != "ExternalIP" && nodeAddressType != "InternalIP" {
		return errors.Errorf("Node address type MUST be InternalIP or ExternalIP")
	}
	return nil
}
func run(oldIPs []string, oldDomains map[string]Domain) (ips []string, domains map[string]Domain, err error) {

	ctx := context.Background()

	cl, err := getClient()
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to initialize Kubernetes client")
	}

	api, err := cloudflare.New(cfAPIKey, cfAPIEmail)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to initialize Cloudflare API")
	}

	ips, err = getNodesIPs(ctx, cl, "")
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to get nodes ips")
	}
	// log.Debugf("%+v", ips)

	domains, err = getDomains(ctx, cl)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to get domains")
	}
	log.Debugf("%+v", domains)

	if len(domains) == 0 {
		return nil, nil, errors.Wrap(err, "no domains found")
	}
	if reflect.DeepEqual(oldIPs, ips) && reflect.DeepEqual(oldDomains, domains) {
		log.Debug("Nothing changed")
		return ips, domains, nil
	}
	ch := make(chan string, 10)
	var wg sync.WaitGroup
	wg.Add(concurrency)
	err = nil
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			for d := range ch {
				if err != nil {
					return
				}
				if err = syncDNS(ctx, cl, api, d, ips, domains[d]); err != nil {
					log.WithError(err).Errorf("failed to sync domain=%v", d)
					return
				}
			}
		}()
	}
	go func() {
		for d := range domains {
			ch <- d
		}
		close(ch)
	}()
	wg.Wait()
	return
}

func syncDNS(ctx context.Context, cl *kubernetes.Clientset, api *cloudflare.API, domain string, nodesIps []string, d Domain) (err error) {
	if d.NodeSelector != "" {
		nodesIps, err = getNodesIPs(ctx, cl, d.NodeSelector)
		if err != nil {
			return errors.Wrapf(err, "failed to get ips with selector=%v", d.NodeSelector)
		}
	}
	ips := []string{}
	for _, a := range nodesIps {
		for _, b := range d.Service.IPs {
			if a == b {
				ips = append(ips, a)
			}
		}
	}
	// log.Debugf("%v %+v %+v %+v", domain, d.Service, ips, nodesIps)
	parts := strings.Split(domain, ".")
	zone := strings.Join(parts[len(parts)-2:], ".")
	proxied := false
	if v, ok := d.Flags["cloudflare-proxied"]; ok && v {
		proxied = true
	}
	log.Debugf("processing domain=\"%s\" proxied=%v", domain, proxied)
	id, err := api.ZoneIDByName(zone)
	if err != nil {
		return errors.Wrapf(err, "failed to get zone=%v", zone)
	}
	recs, err := api.DNSRecords(ctx, id, cloudflare.DNSRecord{})
	if err != nil {
		return errors.Wrapf(err, "failed to get DNS records for domain=%v", domain)
	}
	for _, r := range recs {
		if r.Name != domain || r.Type != "A" {
			continue
		}
		exist := false
		for _, ip := range ips {
			if *r.Proxied == proxied && r.Content == ip && r.Type == "A" {
				exist = true
				break
			}
		}
		if !exist {
			log.Debugf("drop record name=\"%s\" ip=%s proxied=%v", domain, r.Content, r.Proxied)
			if !dryRun {
				err := api.DeleteDNSRecord(ctx, id, r.ID)
				if err != nil {
					return errors.Wrapf(err, "failed to drop record name=\"%s\" ip=%s proxied=%v", domain, r.Content, proxied)
				}
			}
		}
	}
	for _, ip := range ips {
		exist := false
		for _, r := range recs {
			if r.Name == domain && *r.Proxied == proxied && r.Content == ip && r.Type == "A" {
				exist = true
				break
			}
		}
		if !exist {
			log.Debugf("add record name=\"%s\" ip=%s proxied=%v", domain, ip, proxied)
			if !dryRun {
				_, err := api.CreateDNSRecord(ctx, id, cloudflare.DNSRecord{
					Type:    "A",
					Name:    domain,
					Content: ip,
					Proxied: &proxied,
				})
				if err != nil {
					return errors.Wrapf(err, "failed to add record name=\"%s\" ip=%s proxied=%v", domain, ip, proxied)
				}
			}
		} else {
			log.Debugf("record name=\"%s\" ip=%s proxied=%v already exists", domain, ip, proxied)
		}
	}
	return nil
}

func getDomains(ctx context.Context, cl *kubernetes.Clientset) (map[string]Domain, error) {
	hosts := map[string]Domain{}
	svcs := map[string]*Service{}

	ings, err := cl.NetworkingV1().Ingresses(ingressNamespace).List(ctx, metav1.ListOptions{})

	if err != nil {
		return nil, errors.Wrap(err, "failed to get ingress")
	}
	for _, i := range ings.Items {
		n := i.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Name
		svc := &Service{Name: n, Namespace: i.Namespace}
		if s, ok := svcs[n]; ok {
			svc = s
		} else {
			svcs[n] = svc
		}
		for _, r := range i.Spec.Rules {
			hosts[r.Host] = Domain{Name: r.Host, Service: svc, Flags: map[string]bool{}}
		}
		for _, t := range i.Spec.TLS {
			for _, h := range t.Hosts {
				hosts[h] = Domain{Name: h, Service: svc, Flags: map[string]bool{}}
			}
		}
		for k, v := range i.Annotations {
			if strings.HasPrefix(k, annotationPrefix) {
				if k == annotationPrefix+"node-selector" {
					pp := strings.Split(v, "]")
					log.Debugf("%+v", pp)
					ppp := strings.TrimPrefix(pp[0], "[")
					ns := pp[1]
					for _, vh := range strings.Split(ppp, ",") {
						vhh := strings.TrimSpace(vh)
						if e, ok := hosts[vhh]; ok {
							e.NodeSelector = ns
							hosts[vhh] = e
						}
					}
				} else {
					for _, vh := range strings.Split(v, ",") {
						vhh := strings.TrimSpace(vh)
						if _, ok := hosts[vhh]; ok {
							hosts[vhh].Flags[strings.TrimPrefix(k, annotationPrefix)] = true
						}
					}
				}
			}
		}
	}
	for _, v := range svcs {
		v.IPs, err = getServiceIPs(ctx, cl, v.Name, v.Namespace)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get service ips")
		}
	}
	return hosts, nil

}

func getServiceIPs(ctx context.Context, cl *kubernetes.Clientset, n string, ns string) ([]string, error) {
	svc, err := cl.CoreV1().Services(ns).Get(ctx, n, metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to find svc")
	}
	opts := metav1.ListOptions{}
	opts.LabelSelector = labels.SelectorFromSet(svc.Spec.Selector).String()
	pods, err := cl.CoreV1().Pods(ns).List(ctx, opts)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list pods")
	}
	nodes := []string{}
	for _, p := range pods.Items {
		if p.Status.Phase == corev1.PodRunning {
			exist := false
			for _, n := range nodes {
				if p.Spec.NodeName == n {
					exist = true
					break
				}
			}
			if !exist {
				nodes = append(nodes, p.Spec.NodeName)
			}
		}
	}
	ips, err := getIPs(ctx, cl, nodes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get ips for service pods")
	}
	return ips, nil
}

func getNodesIPs(ctx context.Context, cl *kubernetes.Clientset, selector string) ([]string, error) {
	nodes, err := getNodes(ctx, cl, selector)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get nodes")
	}
	ips, err := getIPs(ctx, cl, nodes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get ips")
	}
	return ips, nil
}

func getIPs(ctx context.Context, cl *kubernetes.Clientset, nodes []string) ([]string, error) {

	res := []string{}

	for _, n := range nodes {
		node, err := cl.CoreV1().Nodes().Get(ctx, n, metav1.GetOptions{})
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get node by name=%v", n)
		}
		for _, a := range node.Status.Addresses {
			if a.Type == corev1.NodeAddressType(nodeAddressType) {
				res = append(res, a.Address)
			}
		}
	}

	return res, nil
}

func getNodes(ctx context.Context, cl *kubernetes.Clientset, selector string) ([]string, error) {
	runNodes, err := getRunningNodes(ctx, cl)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get running nodes")
	}

	selNodes, err := getSelectedNodes(ctx, cl, selector)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get running nodes")
	}

	var nodes []string
	if len(selNodes) == 0 {
		nodes = runNodes
	} else {
		nodes = []string{}
		for _, rn := range runNodes {
			for _, sn := range selNodes {
				if rn == sn {
					nodes = append(nodes, rn)
				}
			}
		}
	}
	return nodes, nil
}

func getRunningNodes(ctx context.Context, cl *kubernetes.Clientset) ([]string, error) {
	opts := metav1.ListOptions{}
	if podSelector != "" {
		opts.LabelSelector = podSelector
	}
	pods, err := cl.CoreV1().Pods(podNamespace).List(ctx, opts)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list pods")
	}
	nodes := []string{}
	for _, p := range pods.Items {
		if p.Status.Phase == corev1.PodRunning {
			exist := false
			for _, n := range nodes {
				if p.Spec.NodeName == n {
					exist = true
					break
				}
			}
			if !exist {
				nodes = append(nodes, p.Spec.NodeName)
			}
		}
	}
	return nodes, nil
}

func getSelectedNodes(ctx context.Context, cl *kubernetes.Clientset, selector string) ([]string, error) {
	sel := []string{}
	if nodeSelector != "" {
		sel = append(sel, nodeSelector)
	}
	if selector != "" {
		sel = append(sel, selector)
	}
	if len(sel) == 0 {
		return []string{}, nil
	}
	opts := metav1.ListOptions{}
	opts.LabelSelector = strings.Join(sel, ",")
	nodes, err := cl.CoreV1().Nodes().List(ctx, opts)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list nodes")
	}
	if len(nodes.Items) == 0 {
		return nil, errors.Errorf("no nodes selected")
	}
	res := []string{}
	for _, n := range nodes.Items {
		res = append(res, n.Name)
	}
	return res, nil
}
func getClient() (*kubernetes.Clientset, error) {
	path := os.ExpandEnv(kubeconfig)
	var config *rest.Config
	if _, err := os.Stat(path); err == nil {
		config, err = clientcmd.BuildConfigFromFlags("", path)
		if err != nil {
			return nil, err
		}
	} else {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
	}
	cl, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return cl, nil
}

func help(err string) {
	println("error: " + err)
}

func init() {
	flag.StringVar(
		&podNamespace,
		"pod-namespace",
		"",
		"pod namespace to be balanced [$POD_NAMESPACE]",
	)
	flag.StringVar(
		&podSelector,
		"pod-selector",
		"app.kubernetes.io/name=ingress-nginx",
		"pod selector to be balanced [$POD_SELECTOR]",
	)
	flag.StringVar(
		&ingressNamespace,
		"ingress-namespace",
		"",
		"ingresses to be balanced [$INGRESS_NAMESPACE]",
	)
	flag.StringVar(
		&nodeSelector,
		"node-selector",
		"",
		"node selector to be balanced, in case if you wish to reduce balancing only to specific nodes [$NODE_SELECTOR]",
	)
	flag.StringVar(
		&nodeAddressType,
		"node-address-type",
		"ExternalIP",
		"node address type to balance to, MUST be InternalIP or ExternalIP [$NODE_ADDRESS_TYPE]",
	)
	flag.StringVar(
		&cfAPIKey,
		"cf-api-key",
		"",
		"Cloudflare API Key [$CF_API_KEY]",
	)
	flag.StringVar(
		&cfAPIEmail,
		"cf-api-email",
		"",
		"Cloudflare API Email [$CF_API_EMAIL]",
	)
	flag.BoolVar(
		&dryRun,
		"dry-run",
		false,
		"dry run mode [$DRY_RUN]",
	)
	flag.BoolVar(
		&daemon,
		"daemon",
		false,
		"daemon mode [$DAEMON]",
	)
	flag.BoolVar(
		&verbose,
		"verbose",
		false,
		"verbose mode [$VERBOSE]",
	)
	flag.BoolVar(
		&jsonLog,
		"json-log",
		false,
		"outputs logs in json [$JSON_LOG]",
	)
	flag.StringVar(
		&kubeconfig,
		"kubeconfig",
		"$HOME/.kube/config",
		"path to kubernetes config file [$KUBECONFIG]",
	)
	flag.IntVar(
		&checkInterval,
		"check-interval",
		30,
		"check interval in seconds [$CHECK_INTERVAL]",
	)
	flag.IntVar(
		&fullCheckInterval,
		"full-check-interval",
		600,
		"full check interval in seconds [$FULL_CHECK_INTERVAL]",
	)
	flag.IntVar(
		&concurrency,
		"concurrency",
		5,
		"number of concurrent dns syncs [$CONCURRENCY]",
	)
}
