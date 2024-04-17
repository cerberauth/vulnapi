package main

import "github.com/cerberauth/vulnapi/cmd"

var (
	version = "dev"
)

func main() {
	cmd.Execute(version)
}
