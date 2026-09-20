package main

import (
	"flag"
	"fmt"
	"os"
	"swgbar/coreworker/engine"
)

func main() {
	versionFlag := flag.Bool("version", false, "Print CoreWorker version")
	flag.Parse()

	if *versionFlag {
		fmt.Println("SWGBar CoreWorker v1.1 (Go)")
		return
	}

	if err := engine.RunWorkerStdio(); err != nil {
		fmt.Fprintf(os.Stderr, "CoreWorker exited with error: %v\n", err)
		os.Exit(1)
	}
}
