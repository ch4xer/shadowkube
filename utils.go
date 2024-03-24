package main

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
)

var AllLog *os.File
var AbnormalLog *os.File
var AppLog *os.File
var LogInit bool = false

func initLog(config *Config) {
	AppLog, _ = os.OpenFile("log/"+config.Log.App, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0777)
	AllLog, _ = os.OpenFile("log/"+config.Log.All, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0777)
	AbnormalLog, _ = os.OpenFile("log/"+config.Log.Abnormal, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0777)
	LogInit = true
}

func logConsole(format string, args ...interface{}) {
	var s string
	if len(args) > 0 {
		s = fmt.Sprintf(format, args...)
	} else {
		s = format
	}
	AppLog.WriteString(s + "\n")
	log.Printf("%s", s)
}

func logInfo(format string, args ...interface{}) {
	if !LogInit {
		panic("Logger not initialized")
	}
	var s string
	if len(args) > 0 {
		s = fmt.Sprintf(format, args...)
	} else {
		s = format
	}
	AppLog.WriteString(s + "\n")
	log.Printf("%s", s)
}

func logAll(behavior *Behavior) {
	if !LogInit {
		panic("Logger not initialized")
	}
	AllLog.WriteString(behavior.Output + "\n")
}

func logAbnormal(behavior *Behavior) {
	if !LogInit {
		panic("Logger not initialized")
	}
	if strings.Contains(behavior.Output, "python") {
		return
	}
	AbnormalLog.WriteString(behavior.Output + "\n")
}

func prsDst(conn string) string {
	// example: 10.0.2.15:46950->220.181.38.149:80
	parts := strings.Split(conn, "->")
	if len(parts) != 2 {
		return ""
	}
	dst := strings.Split(parts[1], ":")[0]
	return dst
}

func alarm(api string) {
	hc := http.Client{}

	form := url.Values{}
	form.Set("secret", "toor")

	req, err := http.NewRequest("POST", api, strings.NewReader(form.Encode()))
	if err != nil {
		logInfo(err.Error())
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	_, err = hc.Do(req)
	if err != nil {
		logInfo("Error sending alarm")
		return
	}
	logInfo("Alarm sent")
}

func execute(command string) (string, error) {
	cmd := exec.Command("bash", "-c", command)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = nil
	err := cmd.Run()
	if err != nil {
		return "", err
	}
	return stdout.String(), nil
}

func noWaitExec(command string) {
	parts := strings.Fields(command)
	cmd := exec.Command(parts[0], parts[1:]...)
	err := cmd.Start()
	if err != nil {
		panic(err)
	}
}
