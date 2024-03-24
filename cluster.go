package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type Cluster struct {
	master         Node
	nodes          []Node
	servicesIP     []string
	kubeCli        *kubernetes.Clientset
	convertedNodes []Node
}

func newProduction(c *Config) *Cluster {
	return initCluster(c.Production)
}

func newShadow(c *Config) *Cluster {
	return initCluster(c.Shadow)
}

func initCluster(nodes []Node) *Cluster {
	var err error
	cluster := Cluster{}
	home := os.Getenv("HOME")
	kubeconfig := filepath.Join(home, ".kube", "config")
	config, _ := clientcmd.BuildConfigFromFlags("", kubeconfig)
	cluster.kubeCli, err = kubernetes.NewForConfig(config)
	if err != nil {
		panic(err)
	}
	cluster.servicesIP = cluster.getServicesIP()
	cluster.master = nodes[0]
	cluster.master.init()
	cluster.nodes = nodes
	for i := range cluster.nodes {
		cluster.nodes[i].init()
	}
	cluster.convertedNodes = []Node{}
	return &cluster
}

func (c *Cluster) getPods() []v1.Pod {
	pods, err := c.kubeCli.CoreV1().Pods("default").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		panic(err)
	}
	return pods.Items
}

func (c *Cluster) getServicesIP() []string {
	services, err := c.kubeCli.CoreV1().Services("default").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		panic(err)
	}
	var result = []string{}
	for _, s := range services.Items {
		result = append(result, s.Spec.ClusterIP)
	}
	return result
}

// NOTE: no use
func (c *Cluster) svcIP(name string) []string {
	service, err := c.kubeCli.CoreV1().Services("default").Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		panic(err)
	}
	labelSelector := metav1.FormatLabelSelector(&metav1.LabelSelector{MatchLabels: service.Spec.Selector})
	pods, err := c.kubeCli.CoreV1().Pods("default").List(context.TODO(), metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		panic(err)
	}
	var result []string
	for _, pod := range pods.Items {
		result = append(result, pod.Status.PodIP)
	}
	return result
}

func (c *Cluster) getDeployments() []string {
	result := []string{}
	deployments, err := c.kubeCli.AppsV1().Deployments("default").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		panic(err)
	}
	for _, d := range deployments.Items {
		result = append(result, d.Name)
	}
	return result
}

func (c *Cluster) getNetPolicies() []netv1.NetworkPolicy {
	netPolices, err := c.kubeCli.NetworkingV1().NetworkPolicies("default").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		panic(err)
	}
	return netPolices.Items
}

func (c *Cluster) countConvertedNode() int {
	return len(c.convertedNodes)
}

func (c *Cluster) findNode(id string) *Node {
	for _, n := range c.nodes {
		if n.IP == id {
			return &n
		}
	}
	for _, n := range c.nodes {
		if n.Host == id {
			return &n
		}
	}
	return nil
}

func (c *Cluster) reset() {
	c.convertedNodes = []Node{}
	for _, n := range c.nodes {
		n.reset()
	}
}

func (c *Cluster) convert(threat ThreatInfo, shadowMaster Node) bool {
	var target *Node
	others := []Node{}
	for i := range c.nodes {
		if c.nodes[i].IP == threat.host {
			target = &c.nodes[i]
		} else {
			others = append(others, c.nodes[i])
		}
	}

	target.initVictim(threat.origin)
	target.convert(c.servicesIP, shadowMaster.IP)
	c.convertedNodes = append(c.convertedNodes, *target)

	msg := fmt.Sprintf("Convert %s done", target.IP)
	logInfo(msg)
	for _, n := range others {
		n.isolate(target.IP)
	}
	msg = fmt.Sprintf("Isolate %s done", target.IP)
	logInfo(msg)
	return true
}

func (c *Cluster) clean(threat ThreatInfo) bool {
	if threat.origin == "host" {
		return false
	}
	if err := c.rmContainer(c.master, threat.origin); err != nil {
		return false
	}
	return true
}

func (c *Cluster) rmContainer(node Node, container string) error {
	return node.rmContainer(container)
}
