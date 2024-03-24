package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type Node struct {
	Host              string `json:"host"`
	IP                string `json:"ip"`
	victimContainer   string
	victimContainerID string
	converted         bool
	containers        []string
}

func (n *Node) init() {
	n.converted = false
	n.containers = n.getContainers()
}

func (n *Node) exec(cmd string) (string, error) {
	sshConf := &ssh.ClientConfig{
		User:            "root",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth: []ssh.AuthMethod{
			ssh.Password("toor"),
		},
	}

	server := fmt.Sprintf("%s:%d", n.IP, 22)
	conn, err := ssh.Dial("tcp", server, sshConf)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	session, _ := conn.NewSession()
	out, err := session.CombinedOutput(cmd)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(string(out), "\n"), nil
}

func (n *Node) getContainers() []string {
	if len(n.containers) > 0 {
		return n.containers
	}
	var containers []string
	cmd := "docker ps -a"
	out, err := n.exec(cmd)
	if err != nil {
		panic(err)
	}
	lines := strings.Split(out, "\n")

	for _, line := range lines[1:] {
		parts := strings.Fields(line)
		if len(parts) > 0 {
			containers = append(containers, parts[len(parts)-1])
		}
	}
	return containers
}

func (n *Node) rmOtherContainers(remain string) error {
	fail := 0
	for _, container := range n.containers {
		if container != remain {
			cmd := fmt.Sprintf("docker rm -f %s", container)
			_, err := n.exec(cmd)
			if err != nil {
				fail += 1
			}
		}
	}
	if fail > 0 {
		err := fmt.Errorf("failed to destroy %d pods", fail)
		return err
	}
	return nil
}

func (n *Node) rmContainer(container string) error {
	cmd := fmt.Sprintf("docker rm -f %s", container)
	_, err := n.exec(cmd)
	if err != nil {
		return err
	}
	return nil
}

func (n *Node) upload(src, dst string) {
	sshConf := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.Password("toor"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	server := fmt.Sprintf("%s:%d", n.IP, 22)
	conn, err := ssh.Dial("tcp", server, sshConf)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	sftpClient, err := sftp.NewClient(conn)
	if err != nil {
		panic(err)
	}
	defer sftpClient.Close()

	// Open the source file
	srcFile, err := os.Open(src)
	if err != nil {
		panic(err)
	}
	defer srcFile.Close()

	dstFile, err := sftpClient.Create(dst)
	if err != nil {
		panic(err)
	}
	defer dstFile.Close()

	_, err = dstFile.ReadFrom(srcFile)
	if err != nil {
		panic(err)
	}
}

func (n *Node) convert(ips []string, redirectDst string) bool {
	n.converted = true
	n.stopKubelet()
	n.rmOtherContainers(n.victimContainer)
	n.replaceCerts()
	n.replaceSA()
	n.changeIptable(ips, redirectDst)
	return true
}

func (n *Node) reset() {
	var err error
	c1 := fmt.Sprintf("VBoxManage controlvm %s poweroff", n.Host)
	if _, err = execute(c1); err != nil {
		logInfo("Failed to poweroff %s", n.Host)
		return
	}
	c2 := fmt.Sprintf("VBoxManage snapshot %s restore weather", n.Host)
	if _, err = execute(c2); err != nil {
		logInfo("Failed to restore %s", n.Host)
		return
	}
	c3 := fmt.Sprintf("VBoxManage startvm %s --type headless", n.Host)
	if _, err = execute(c3); err != nil {
		logInfo("Failed to startvm %s", n.Host)
		return
	}
	n.converted = false
}

func (n *Node) stopKubelet() {
	n.exec("systemctl stop kubelet")
}

func (n *Node) replaceCerts() {
	n.upload("secrets/kubernetes/kubelet.conf", "/etc/kubernetes/kubelet.conf")
	n.upload("secrets/kubernetes/pki/ca.crt", "/etc/kubernetes/pki/ca.crt")
	n.exec("rm -rf /var/lib/kubelet/pki/*")
	n.upload("secrets/kubelet/pki/kubelet-client-current.pem", "/var/lib/kubelet/kubelet-client-current.pem")
	n.upload("secrets/kubelet/pki/kubelet.crt", "/var/lib/kubelet/kubelet.crt")
	n.upload("secrets/kubelet/pki/kubelet.key", "/var/lib/kubelet/kubelet.key")
}

func (n *Node) replaceSA() {
	if n.victimContainer == "host" {
		return
	}
	path := fmt.Sprintf("/var/lib/kubelet/pods/%s/volumes/kubernetes.io~secret", n.victimContainerID)
	sec, err := n.exec(fmt.Sprintf("ls %s", path))
	if err != nil {
		panic(err)
	}
	dstToken := fmt.Sprintf("%s/%s/token", path, sec)
	dstCA := fmt.Sprintf("%s/%s/ca.crt", path, sec)
	// var srcToken string
	// var srcCA string
	// groups, _ := os.ReadDir("secrets/kubelet/pods")
	// for _, g := range groups {
	// 	if strings.Contains(n.victimName, g.Name()) {
	// 		srcToken = fmt.Sprintf("secrets/kubelet/pods/%s/token", g.Name())
	// 		srcCA = fmt.Sprintf("secrets/kubelet/pods/%s/ca.crt", g.Name())
	// 	}
	// }
	srcToken := "secrets/sa/token"
	srcCA := "secrets/sa/ca.crt"
	n.upload(srcToken, dstToken)
	n.upload(srcCA, dstCA)
}

func (n *Node) changeIptable(target []string, dest string) {
	for _, t := range target {
		cmd := fmt.Sprintf("iptables -t nat -A PREROUTING -d %s -j DNAT --to-destination %s", t, dest)
		n.exec(cmd)
		logConsole(cmd)
		cmd = fmt.Sprintf("iptables -t nat -A POSTROUTING -s %s -j SNAT --to-source %s", dest, t)
		n.exec(cmd)
		logConsole(cmd)
	}
	// // 10.96.0.1 is kubernative virtual ip
	// cmd := "iptables -t nat -A PREROUTING -d 10.96.0.1 -j DNAT --to-destination 192.168.60.126"
	// n.exec(cmd)
	// // only for local weather app test
	// cmd = "iptables -t nat -A PREROUTING -d 10.105.180.218 -j DNAT --to-destination 192.168.60.126"
	// n.exec(cmd)
}

func (n *Node) isolate(ip string) {
	cmd := fmt.Sprintf("iptables -A INPUT -s %s -j DROP", ip)
	n.exec(cmd)
	cmd = fmt.Sprintf("iptables -A OUTPUT -d %s -j DROP", ip)
	n.exec(cmd)
}

func (n *Node) initVictim(name string) {
	n.victimContainer = name
	if name == "host" {
		return
	}
	cmd1 := fmt.Sprintf("docker inspect %s --format '{{.Id}}'", n.victimContainer)
	completeId, _ := n.exec(cmd1)
	cmd2 := fmt.Sprintf("cat /var/lib/docker/containers/%s/hostconfig.json", completeId)
	conf, _ := n.exec(cmd2)
	re := regexp.MustCompile(`/var/lib/kubelet/pods/([a-f0-9\-]+)/`)
	matches := re.FindStringSubmatch(conf)
	logInfo("%s", matches)
	if len(matches) > 1 {
		n.victimContainerID = matches[1]
	} else {
		panic("Failed to find the victim pod id")
	}
}
