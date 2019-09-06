//
// Copyright (c) 2017-2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"os"
	"runtime"

	"github.com/kardianos/service"
	"github.com/sirupsen/logrus"

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

	srv := &kataService.Service{}
	s, err := service.New(srv, kataService.ServiceConfig)
	if err != nil {
		logrus.Fatal(err)
	}

	srv.Logger = logrus.WithField("name", kataService.AgentName).
		WithField("pid", os.Getpid()).
		WithField("source", "agent")

	if len(os.Args) < 2 {
		srv.Logger.Infof("---------- run %v (%v) ----------", os.Args, kataService.AgentName)
		err = s.Run()
		if err != nil {
			srv.Logger.Error(err)
		}
		return
	}

	cmd := os.Args[1]
	srv.Logger.Infof("---------- %v %v ----------", cmd, kataService.AgentName)

	switch cmd {
	case "install":
		err = s.Install()
		if err != nil {
			srv.Logger.Warn(err)
		} else {
			srv.Logger.Infof("%v installed\n", kataService.AgentName)
		}
		err = s.Start()
		if err != nil {
			srv.Logger.Warn(err)
		} else {
			srv.Logger.Infof("%v started\n", kataService.AgentName)
		}
		err = kataService.FailureRecory()
		if err != nil {
			srv.Logger.Warn(err)
		} else {
			srv.Logger.Infof("%v set recovery action ok\n", kataService.AgentName)
		}
	case "uninstall":
		s.Stop()
		if err != nil {
			srv.Logger.Warn(err)
		} else {
			srv.Logger.Infof("%v stopped\n", kataService.AgentName)
		}
		err = s.Uninstall()
		if err != nil {
			logrus.Fatal(err)
		}
		srv.Logger.Infof("%v uninstalled\n", kataService.AgentName)
	case "version":
		srv.Logger.Infof("%v version %v\n", kataService.AgentName, kataService.Version)
	}

}
