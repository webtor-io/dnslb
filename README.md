# dnslb

Round-robin DNS LoadBalancer for Kubernetes.

## Should I use it?

You shouldn't use it if:

1. You are running your cluster on GKE, AKS, EKS or similar managed Kubernetes cluster.
LoadBalancer is already there, so you should just set your service type to `LoadBalancer` and
load-balancing will be served for you out of the box.

2. You are running Kubernetes cluster at environment that offers Layer2-traffic between nodes or it is possible
to establish BGP-sessions between your nodes and routing hardware. So in this case you should go with [MetalLB](https://metallb.universe.tf/).

3. You just running a single node cluster so you can just make single A-recored at your DNS provider to point to your node.

In any other scenario **dnslb** might be the only way to get load-balancing and explosure of your
services.

## Drawbacks

It is well-known that DNS round-robin is not the best choice for load-balancing because of caching of DNS-responses on clien-side. So keep in mind
if some of your nodes goes down users may still try to reach them for a long time.

## How does it work?

1. Search for pods by selector specified by `pod-selector`.
2. Checks whether they are running or not and gets IPs of nodes they are running on.
3. Searches for ingress-objects and gets all domains that are defined in them (hosts and TLS sections).
4. Publishes A-records for each domain and each node IP to DNS-provider.

## What DNS providers are supported?

Only Cloudflare right now.

## Prerequirements

You should have ingres-controller in your cluster with `HostPort` enabled.

## Usage

```
% ./dnslb --help
Usage of ./dnslb:
  -cf-api-email string
    	Cloudflare API Email [$CF_API_EMAIL]
  -cf-api-key string
    	Cloudflare API Key [$CF_API_KEY]
  -check-interval int
    	check interval in seconds [$CHECK_INTERVAL] (default 10)
  -concurrency int
    	number of concurrent dns syncs [$CONCURRENCY] (default 5)
  -daemon
    	daemon mode [$DAEMON]
  -dry-run
    	dry run mode [$DRY_RUN]
  -full-check-interval int
    	full check interval in seconds [$FULL_CHECK_INTERVAL] (default 600)
  -ingress-namespace string
    	ingresses to be balanced [$INGRESS_NAMESPACE]
  -json-log
    	outputs logs in json [$JSON_LOG]
  -kubeconfig string
    	path to kubernetes config file [$KUBECONFIG] (default "$HOME/.kube/config")
  -node-address-type string
    	node address type to balance to, MUST be InternalIP or ExternalIP [$NODE_ADDRESS_TYPE] (default "ExternalIP")
  -node-selector string
    	node selector to be balanced, in case if you wish to reduce balancing only to specific nodes [$NODE_SELECTOR]
  -pod-namespace string
    	pod namespace to be balanced [$POD_NAMESPACE]
  -pod-selector string
    	pod selector to be balanced [$POD_SELECTOR] (default "app.kubernetes.io/component=controller,app=nginx-ingress")
  -verbose
    	verbose mode [$VERBOSE]
```

## Special ingress annotation

By adding special annotation to your ingress-objects you can modify **dnslb** behaviour.

`dnslb/cloudflare-proxied` - specifies which domains should be proxied through Cloudflare (example value `example.org,someothere.org`). By default all records are created with `DNS only`.

## Helm chart
You can find helm-chart [there](https://github.com/webtor-io/helm-charts/tree/master/charts/dnslb).
