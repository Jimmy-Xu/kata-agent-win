package service

import (
	"log"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc/mgr"
)

func FailureRecory() error {

	m, err := mgr.Connect()
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno == syscall.ERROR_ACCESS_DENIED {
			log.Println("Skipping test: we don't have rights to manage services.")
			return err
		}
		log.Fatalf("SCM connection failed: %s", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(AgentName)
	if err != nil {
		log.Fatalf("service %s is not installed", AgentName)
	}
	defer s.Close()

	r := []mgr.RecoveryAction{
		{
			Type:  mgr.ServiceRestart,
			Delay: 2 * time.Second,
		},
		{
			Type:  mgr.ServiceRestart,
			Delay: 5 * time.Second,
		},
		{
			Type:  mgr.ServiceRestart,
			Delay: 20 * time.Second,
		},
		{
			Type:  mgr.ServiceRestart,
			Delay: 60 * time.Second,
		},
	}

	// 4 recovery actions with reset period
	err = s.SetRecoveryActions(r, uint32(10000))
	if err != nil {
		log.Fatalf("SetRecoveryActions failed: %v", err)
	}
	return nil
}
