//
// Copyright (c) 2017-2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package service

import (
	"context"
	"fmt"

	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/yamux"
	//"github.com/mdlayher/vsock"
	"github.com/sirupsen/logrus"

	"github.com/kata-containers/agent/pkg/serial"
)

var (
	channelExistMaxTries   = 200
	channelExistWaitTime   = 50 * time.Millisecond
	channelCloseTimeout    = 5 * time.Second
	isAFVSockSupportedFunc = isAFVSockSupported
)

type channel interface {
	setup() error
	wait() error
	listen() (net.Listener, error)
	teardown() error
}

// Creates a new channel to communicate the agent with the proxy or shim.
// The runtime hot plugs a serial port or a vsock PCI depending of the configuration
// file and if the host has support for vsocks. newChannel iterates in a loop looking
// for the serial port or vsock device.
// The timeout is defined by channelExistMaxTries and channelExistWaitTime and it
// can be calculated by using the following operation:
// (channelExistMaxTries * channelExistWaitTime) / 1000 = timeout in seconds
// If there are neither vsocks nor serial ports, an error is returned.
func newChannel(ctx context.Context) (channel, error) {
	//span, _ := trace(ctx, "channel", "newChannel")
	//defer span.Finish()

	logrus.Infof("newChannel - begin")
	defer logrus.Infof("newChannel - end")

	var serialErr error
	//var vsockErr error
	var ch channel

	//specify channel
	commCh = serialCh
	logrus.Infof("newChannel:%v", commCh)
	for i := 0; i < channelExistMaxTries; i++ {
		switch commCh {
		case serialCh:
			if ch, serialErr = checkForSerialChannel(ctx); serialErr == nil && ch.(*serialChannel) != nil {
				return ch, nil
			} else {
				if strings.Contains(serialErr.Error(), "Access is denied") {
					logrus.Fatalf("ch:%v err:%v", ch, serialErr)
				} else {
					logrus.Warnf("ch:%v err:%v", ch, serialErr)
				}
			}
		//case vsockCh:
		//	//if ch, vsockErr = checkForVsockChannel(ctx); vsockErr == nil && ch.(*vSockChannel) != nil {
		//	//	return ch, nil
		//	//}

		case unknownCh:
			// If we have not been explicitly passed if vsock is used or not, maybe due to
			// an older runtime, try to check for vsock support.
			//if ch, vsockErr = checkForVsockChannel(ctx); vsockErr == nil && ch.(*vSockChannel) != nil {
			//	return ch, nil
			//}
			if ch, serialErr = checkForSerialChannel(ctx); serialErr == nil && ch.(*serialChannel) != nil {
				return ch, nil
			}
		}

		time.Sleep(channelExistWaitTime)
	}

	if serialErr != nil {
		AgentLog.WithError(serialErr).Error("Serial port not found")
	}

	//if vsockErr != nil {
	//	AgentLog.WithError(vsockErr).Error("VSock not found")
	//}

	return nil, fmt.Errorf("Neither vsocks nor serial ports were found")
}

func checkForSerialChannel(ctx context.Context) (*serialChannel, error) {
	span, _ := trace(ctx, "channel", "checkForSerialChannel")
	defer span.Finish()

	logrus.Infof("checkForSerialChannel: %v", serialChannelName)

	// Check serial port path
	serialPath, serialErr := findVirtualSerialPath(serialChannelName)
	if serialErr == nil {
		span.SetTag("channel-type", "serial")
		span.SetTag("serial-path", serialPath)
		AgentLog.Debug("Serial channel type detected")
		return &serialChannel{serialPath: serialPath}, nil
	} else {
		logrus.Errorf("serialPath:%v, serialErr:%v", serialPath, serialErr)
	}

	return nil, serialErr
}

//func checkForVsockChannel(ctx context.Context) (*vSockChannel, error) {
//	span, _ := trace(ctx, "channel", "checkForVsockChannel")
//	defer span.Finish()
//
//	// check vsock path
//	if _, err := os.Stat(vSockDevPath); err != nil {
//		return nil, err
//	}
//
//	vSockSupported, vsockErr := isAFVSockSupportedFunc()
//	if vSockSupported && vsockErr == nil {
//		span.SetTag("channel-type", "vsock")
//		AgentLog.Debug("Vsock channel type detected")
//		return &vSockChannel{}, nil
//	}
//
//	return nil, fmt.Errorf("Vsock not found : %s", vsockErr)
//}

type vSockChannel struct {
}

func (c *vSockChannel) setup() error {
	return nil
}

func (c *vSockChannel) wait() error {
	return nil
}

func (c *vSockChannel) listen() (net.Listener, error) {
	//l, err := vsock.Listen(vSockPort)
	//if err != nil {
	//	return nil, err
	//}

	//return l, nil
	return nil, nil
}

func (c *vSockChannel) teardown() error {
	return nil
}

type serialChannel struct {
	serialPath string
	//serialConn *os.File
	serialConn *serial.Port
	waitCh     <-chan struct{}
}

func (c *serialChannel) setup() error {
	// Open serial channel.
	//file, err := os.OpenFile(c.serialPath, os.O_RDWR, os.ModeDevice)
	//if err != nil {
	//	return err
	//}
	//
	//c.serialConn = file

	logrus.Infof("serialChannel.setup() - begin")
	defer logrus.Infof("serialChannel.setup() - end")

	com := &serial.Config{Name: c.serialPath}
	s, err := serial.OpenPort(com)
	if err != nil {
		//if c.serialConn != nil {
		//	logrus.Warnf("failed to open serial port %v again, error:%v", c.serialPath, err)
		//	return nil
		//}
		logrus.Fatalf("failed to open serial port %v, error:%v", c.serialPath, err)
	}
	logrus.Infof("setup() - open serial port %v ok", c.serialPath)
	c.serialConn = s

	return nil
}

func (c *serialChannel) wait() error {
	logrus.Infof("serialChannel.wait() - begin")
	defer logrus.Infof("serialChannel.wait() - end")

	//var event unix.EpollEvent
	//var events [1]unix.EpollEvent
	//
	//fd := c.serialConn.Fd()
	//if fd == 0 {
	//	return fmt.Errorf("serial port IO closed")
	//}
	//
	//epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	//if err != nil {
	//	return err
	//}
	//defer unix.Close(epfd)
	//
	//// EPOLLOUT: Writable when there is a connection
	//// EPOLLET: Edge trigger as EPOLLHUP is always on when there is no connection
	//// 0xffffffff: EPOLLET is negative and cannot fit in uint32 in golang
	//event.Events = unix.EPOLLOUT | unix.EPOLLET&0xffffffff
	//event.Fd = int32(fd)
	//if err = unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, int(fd), &event); err != nil {
	//	return err
	//}
	//defer unix.EpollCtl(epfd, unix.EPOLL_CTL_DEL, int(fd), nil)
	//
	//for {
	//	nev, err := unix.EpollWait(epfd, events[:], -1)
	//	if err != nil {
	//		return err
	//	}
	//
	//	for i := 0; i < nev; i++ {
	//		ev := events[i]
	//		if ev.Fd == int32(fd) {
	//			AgentLog.WithField("events", ev.Events).Debug("New serial channel event")
	//			if ev.Events&unix.EPOLLOUT != 0 {
	//				return nil
	//			}
	//			if ev.Events&unix.EPOLLERR != 0 {
	//				return fmt.Errorf("serial port IO failure")
	//			}
	//			if ev.Events&unix.EPOLLHUP != 0 {
	//				continue
	//			}
	//		}
	//	}
	//}

	// Never reach here

	return nil
}

// yamuxWriter is a type responsible for logging yamux messages to the agent
// log.
type yamuxWriter struct {
}

// Write implements the Writer interface for the yamuxWriter.
func (yw yamuxWriter) Write(bytes []byte) (int, error) {
	message := string(bytes)

	l := len(message)

	// yamux messages are all warnings and errors
	AgentLog.WithField("component", "yamux").Warn(message)

	return l, nil
}

func (c *serialChannel) listen() (net.Listener, error) {
	logrus.Infof("serialChannel.listen() - begin")
	defer logrus.Infof("serialChannel.listen() - end")

	config := yamux.DefaultConfig()
	// yamux client runs on the proxy side, sometimes the client is
	// handling other requests and it's not able to response to the
	// ping sent by the server and the communication is closed. To
	// avoid any IO timeouts in the communication between agent and
	// proxy, keep alive should be disabled.
	config.EnableKeepAlive = false
	config.LogOutput = yamuxWriter{}

	// Initialize Yamux server.
	session, err := yamux.Server(c.serialConn, config)
	if err != nil {
		return nil, err
	}
	logrus.Infof("listen() - init yamux server over serialport:%v ok", c.serialPath)
	c.waitCh = session.CloseChan()

	return session, nil
}

func (c *serialChannel) teardown() error {
	// wait for the session to be fully shutdown first
	logrus.Infof("serialChannel.teardown() - begin")
	defer logrus.Infof("serialChannel.teardown() - end")

	if c.waitCh != nil {
		t := time.NewTimer(channelCloseTimeout)
		select {
		case <-c.waitCh:
			t.Stop()
		case <-t.C:
			return fmt.Errorf("timeout waiting for yamux channel to close")
		}
	}
	return c.serialConn.Close()
}

// isAFVSockSupported checks if vsock channel is used by the runtime
// by checking for devices under the vhost-vsock driver path.
// It returns true if a device is found for the vhost-vsock driver.
func isAFVSockSupported() (bool, error) {
	// Driver path for virtio-vsock
	sysVsockPath := "/sys/bus/virtio/drivers/vmw_vsock_virtio_transport/"

	files, err := ioutil.ReadDir(sysVsockPath)

	// This should not happen for a hypervisor with vsock driver
	if err != nil {
		return false, err
	}

	// standard driver files that should be ignored
	driverFiles := []string{"bind", "uevent", "unbind"}

	for _, file := range files {
		for _, f := range driverFiles {
			if file.Name() == f {
				continue
			}
		}

		fPath := filepath.Join(sysVsockPath, file.Name())
		fInfo, err := os.Lstat(fPath)
		if err != nil {
			return false, err
		}

		if fInfo.Mode()&os.ModeSymlink == 0 {
			continue
		}

		link, err := os.Readlink(fPath)
		if err != nil {
			return false, err
		}

		if strings.Contains(link, "devices") {
			return true, nil
		}
	}

	return false, nil
}

func findVirtualSerialPath(serialName string) (string, error) {
	dir, err := os.Open(serialName)
	if err != nil {
		return "", err
	}

	defer dir.Close()

	//ports, err := dir.Readdirnames(0)
	//if err != nil {
	//	return "", err
	//}
	//
	//for _, port := range ports {
	//	path := filepath.Join(virtIOPath, port, "name")
	//	content, err := ioutil.ReadFile(path)
	//	if err != nil {
	//		if os.IsNotExist(err) {
	//			AgentLog.WithField("file", path).Debug("Skip parsing of non-existent file")
	//			continue
	//		}
	//		return "", err
	//	}
	//
	//	if strings.Contains(string(content), serialName) {
	//		return filepath.Join(devRootPath, port), nil
	//	}
	//}

	return serialName, nil

	//return "", grpcStatus.Errorf(codes.NotFound, "Could not find virtio port %s", serialName)
}
