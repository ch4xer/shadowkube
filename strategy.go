package main

type Strategy int

const (
	NoAction Strategy = iota
	ConvertCluster
	CleanCluster
	ResetCluster
)
