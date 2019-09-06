//
// Copyright (c) 2017-2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/kardianos/service"

	kataService "github.com/kata-containers/agent/pkg/service"
)



func init() {
	if len(os.Args) > 1 && os.Args[1] == "init" {
		runtime.GOMAXPROCS(1)
		runtime.LockOSThread()
		//factory, _ := libcontainer.New("")
		//if err := factory.StartInitialization(); err != nil {
		//	agentLog.WithError(err).Error("init failed")
		//}
		panic("--this line should have never been executed, congratulations--")
	}
}

func main() {
	defer kataService.HandlePanic()

	prog := &kataService.Service{}
	s, err := service.New(prog, kataService.ServiceConfig)
	if err != nil {
		log.Fatal(err)
	}

	logger, err := s.Logger(nil)
	if err != nil {
		log.Fatal(err)
	}

	if len(os.Args) < 2 {
		err = s.Run()
		if err != nil {
			logger.Error(err)
		}
		return
	}

	cmd := os.Args[1]

	switch cmd {
	case "install":
		err = s.Install()
		if err != nil {
			log.Println(err)
		} else {
			fmt.Printf("%v installed\n", kataService.AgentName)
		}
		err = s.Start()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%v started\n", kataService.AgentName)
	case "uninstall":
		s.Stop()
		if err != nil {
			log.Println(err)
		} else {
			fmt.Printf("%v stopped\n", kataService.AgentName)
		}
		err = s.Uninstall()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%v uninstalled\n", kataService.AgentName)
	case "version":
		fmt.Printf("%v version %v\n", kataService.AgentName, kataService.Version)
	}

}
