package main

import (
	"encoding/json"
	"os"
)

type Config struct {
	Report     string   `json:"report"`
	Cert       string   `json:"cert"`
	Key        string   `json:"key"`
	CA         string   `json:"ca"`
	Rule       string   `json:"rule"`
	Detect     bool     `json:"detect"`
	Log        Log      `json:"log"`
	Threshold  float64  `json:"threshold"`
	WinTime    int      `json:"time_window"`
	AliveTime  int      `json:"alive_time"`
	MaxConvert int      `json:"max_convert"`
	Production []Node   `json:"production"`
	Shadow     []Node   `json:"shadow"`
	Skip       []string `json:"skip"`
}

type Log struct {
	App      string `json:"app"`
	All      string `json:"all_falco"`
	Abnormal string `json:"abnormal"`
}

func loadConf(conf string) *Config {
	file, err := os.Open(conf)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	config := &Config{}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(config)
	if err != nil {
		panic(err)
	}
	return config
}
