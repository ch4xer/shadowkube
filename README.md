# ShadowKbue

This is the prototype of cluster protection system based on shadow honeypot and behavior baseline, once the container behavior deviates from the baseline, the system will convert the infected node and container into honeypot and connect them to a pre-built shadow cluster.

## Prerequirement

1. Prepare two Kubernetes cluster, for convenient, both clusters were setup with virtual machines of VirtualBox.
2. install falco to all nodes of both clusters
3. enable falco's grpc feature, and generate openssl certificates for all nodes and host running the code, see [falco-grpc](https://falco.org/docs/grpc/grpc-config/)
4. open `config.json` and change nodes information in `production` and `shadow` to the corresponding hostname of targeted clusters, change `cert`, `key` and `ca` to the corresponding path of falco certificates in the host.
5. optionally, set `report`,  the address of traffic proxy receiving signals from this program.

## Setup Baseline

1. open `config.json`, set `detect` to `false`
2. running falco on all the nodes
3. run program with `go run .`
4. execute normal workflows on the applications on the production cluster.

## Online Detection

1. open `config.json`, set `detect` to `true`
2. execute malicious workflows on the cluster application, eg. command injection attack.
