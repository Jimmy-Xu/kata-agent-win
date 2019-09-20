//
// Copyright (c) 2017-2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package service

import (
	"bufio"
	"golang.org/x/sys/windows"
	"net"

	//"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	gpb "github.com/gogo/protobuf/types"
	"github.com/kata-containers/agent/pkg/types"
	pb "github.com/kata-containers/agent/protocols/grpc"
	//"github.com/opencontainers/runc/libcontainer"
	//"github.com/opencontainers/runc/libcontainer/configs"
	//"github.com/opencontainers/runc/libcontainer/seccomp"
	//"github.com/opencontainers/runc/libcontainer/specconv"
	//"github.com/opencontainers/runc/libcontainer/utils"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	//"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	grpcStatus "google.golang.org/grpc/status"
)

type agentGRPC struct {
	sandbox *sandbox
	version string
}

// CPU and Memory hotplug
const (
	cpuRegexpPattern = "cpu[0-9]*"
	memRegexpPattern = "memory[0-9]*"
)

var (
	// set when StartTracing() is called.
	startTracingCalled = false

	// set when StopTracing() is called.
	stopTracingCalled = false
)

type onlineResource struct {
	sysfsOnlinePath string
	regexpPattern   string
}

type cookie map[string]bool

var emptyResp = &gpb.Empty{}

const onlineCPUMemWaitTime = 100 * time.Millisecond

var onlineCPUMaxTries = uint32(100)

// handleError will log the specified error if wait is false
func handleError(wait bool, err error) error {
	if !wait {
		AgentLog.WithError(err).Error()
	}

	return err
}

// Online resources, nbResources specifies the maximum number of resources to online.
// If nbResources is <= 0 then there is no limit and all resources are connected.
// Returns the number of resources connected.
func onlineResources(resource onlineResource, nbResources int32) (uint32, error) {
	return 0, nil
}

// updates a cpuset cgroups path visiting each sub-directory in cgroupPath parent and writing
// the maximal set of cpus in cpuset.cpus file, finally the cgroupPath is updated with the requsted
//value.
// cookies are used for performance reasons in order to
// don't update a cgroup twice.
func updateCpusetPath(cgroupPath string, newCpuset string, cookies cookie) error {
	return nil
}

func (a *agentGRPC) onlineCPUMem(req *pb.OnlineCPUMemRequest) error {
	return nil
}

func setConsoleCarriageReturn(fd int) error {
	return nil
}

func buildProcess(agentProcess *pb.Process, procID string, init bool) (*process, error) {
	user := agentProcess.User.Username
	if user == "" {
		// We can specify the user and the group separated by ":"
		user = fmt.Sprintf("%d:%d", agentProcess.User.UID, agentProcess.User.GID)
	}

	additionalGids := []string{}
	for _, gid := range agentProcess.User.AdditionalGids {
		additionalGids = append(additionalGids, fmt.Sprintf("%d", gid))
	}

	//proc := &process{
	//	id: procID,
	//	process: libcontainer.Process{
	//		Cwd:              agentProcess.Cwd,
	//		Args:             agentProcess.Args,
	//		Env:              agentProcess.Env,
	//		User:             user,
	//		AdditionalGroups: additionalGids,
	//		Init:             init,
	//	},
	//}

	//if agentProcess.Terminal {
	//	parentSock, childSock, err := utils.NewSockPair("console")
	//	if err != nil {
	//		return nil, err
	//	}
	//
	//	proc.process.ConsoleSocket = childSock
	//	proc.consoleSock = parentSock
	//
	//	epoller, err := newEpoller()
	//	if err != nil {
	//		return nil, err
	//	}
	//
	//	proc.epoller = epoller
	//
	//	return proc, nil
	//}

	//rStdin, wStdin, err := os.Pipe()
	//if err != nil {
	//	return nil, err
	//}
	//
	//rStdout, wStdout, err := os.Pipe()
	//if err != nil {
	//	return nil, err
	//}
	//
	//rStderr, wStderr, err := os.Pipe()
	//if err != nil {
	//	return nil, err
	//}

	//proc.process.Stdin = rStdin
	//proc.process.Stdout = wStdout
	//proc.process.Stderr = wStderr
	//
	//proc.stdin = wStdin
	//proc.stdout = rStdout
	//proc.stderr = rStderr

	//return proc, nil

	return nil, nil
}

func (a *agentGRPC) Check(ctx context.Context, req *pb.CheckRequest) (*pb.HealthCheckResponse, error) {
	logrus.Infof("receive [Check] CheckRequest：%v", *req)
	return &pb.HealthCheckResponse{Status: pb.HealthCheckResponse_SERVING}, nil
}

func (a *agentGRPC) Version(ctx context.Context, req *pb.CheckRequest) (*pb.VersionCheckResponse, error) {
	logrus.Infof("receive [Version] CheckRequest：%v", *req)
	return &pb.VersionCheckResponse{
		GrpcVersion:  pb.APIVersion,
		AgentVersion: a.version,
	}, nil

}

func (a *agentGRPC) getContainer(cid string) (*container, error) {
	if !a.sandbox.running {
		return nil, grpcStatus.Error(codes.FailedPrecondition, "Sandbox not started")
	}

	ctr, err := a.sandbox.getContainer(cid)
	if err != nil {
		return nil, err
	}

	return ctr, nil
}

// Shared function between CreateContainer and ExecProcess, because those expect
// a process to be run.
func (a *agentGRPC) execProcess(ctr *container, proc *process, createContainer bool) (err error) {
	if ctr == nil {
		return grpcStatus.Error(codes.InvalidArgument, "Container cannot be nil")
	}

	if proc == nil {
		return grpcStatus.Error(codes.InvalidArgument, "Process cannot be nil")
	}

	// This lock is very important to avoid any race with reaper.reap().
	// Indeed, if we don't lock this here, we could potentially get the
	// SIGCHLD signal before the channel has been created, meaning we will
	// miss the opportunity to get the exit code, leading WaitProcess() to
	// wait forever on the new channel.
	// This lock has to be taken before we run the new process.
	//a.sandbox.subreaper.lock()
	//defer a.sandbox.subreaper.unlock()

	proc.exitCodeCh = make(chan int, 1)

	// Create process channel to allow WaitProcess to wait on it.
	// This channel is buffered so that reaper.reap() will not
	// block until WaitProcess listen onto this channel.
	//a.sandbox.subreaper.setExitCodeCh(pid, proc.exitCodeCh)

	return nil
}

// Shared function between CreateContainer and ExecProcess, because those expect
// the console to be properly setup after the process has been started.
func (a *agentGRPC) postExecProcess(ctr *container, proc *process) error {
	if ctr == nil {
		return grpcStatus.Error(codes.InvalidArgument, "Container cannot be nil")
	}

	if proc == nil {
		return grpcStatus.Error(codes.InvalidArgument, "Process cannot be nil")
	}
	return nil
}

// rollbackFailingContainerCreation rolls back important steps that might have
// been performed before the container creation failed.
// - Destroy the container created by libcontainer
// - Delete the container from the agent internal map
// - Unmount all mounts related to this container
func (a *agentGRPC) rollbackFailingContainerCreation(ctr *container) {
}

func (a *agentGRPC) CreateContainer(ctx context.Context, req *pb.CreateContainerRequest) (resp *gpb.Empty, err error) {
	return nil, nil
}

// Path overridden in unit tests
var procSysDir = "/proc/sys"

// writeSystemProperty writes the value to a path under /proc/sys as determined from the key.
// For e.g. net.ipv4.ip_forward translated to /proc/sys/net/ipv4/ip_forward.
func writeSystemProperty(key, value string) error {
	keyPath := strings.Replace(key, ".", "/", -1)
	return ioutil.WriteFile(filepath.Join(procSysDir, keyPath), []byte(value), 0644)
}

func isNetworkSysctl(sysctl string) bool {
	return strings.HasPrefix(sysctl, "net.")
}

// libcontainer checks if the container is running in a separate network namespace
// before applying the network related sysctls. If it sees that the network namespace of the container
// is the same as the "host", it errors out. Since we do no create a new net namespace inside the guest,
// libcontainer would error out while verifying network sysctls. To overcome this, we dont pass
// network sysctls to libcontainer, we instead have the agent directly apply them. All other namespaced
// sysctls are applied by libcontainer.
func (a *agentGRPC) applyNetworkSysctls(ociSpec *specs.Spec) error {
	sysctls := ociSpec.Linux.Sysctl
	for key, value := range sysctls {
		if isNetworkSysctl(key) {
			if err := writeSystemProperty(key, value); err != nil {
				return err
			}
			delete(sysctls, key)
		}
	}

	ociSpec.Linux.Sysctl = sysctls
	return nil
}

func (a *agentGRPC) handleCPUSet(ociSpec *specs.Spec) error {
	return nil
}

func (a *agentGRPC) createContainerChecks(req *pb.CreateContainerRequest) (err error) {
	if !a.sandbox.running {
		return grpcStatus.Error(codes.FailedPrecondition, "Sandbox not started, impossible to run a new container")
	}

	if _, err = a.sandbox.getContainer(req.ContainerId); err == nil {
		return grpcStatus.Errorf(codes.AlreadyExists, "Container %s already exists, impossible to create", req.ContainerId)
	}

	if a.pidNsExists(req.OCI) {
		return grpcStatus.Errorf(codes.FailedPrecondition, "Unexpected PID namespace received for container %s, should have been cleared out", req.ContainerId)
	}

	return nil
}

func (a *agentGRPC) pidNsExists(grpcSpec *pb.Spec) bool {
	return false
}

func (a *agentGRPC) updateSharedPidNs(ctr *container) error {
	return nil
}

func (a *agentGRPC) StartContainer(ctx context.Context, req *pb.StartContainerRequest) (*gpb.Empty, error) {
	return emptyResp, nil
}

func (a *agentGRPC) ExecProcess(ctx context.Context, req *pb.ExecProcessRequest) (*gpb.Empty, error) {
	ctr, err := a.getContainer(req.ContainerId)
	if err != nil {
		return emptyResp, err
	}

	//status, err := ctr.container.Status()
	//if err != nil {
	//	return nil, err
	//}
	//
	//if status == libcontainer.Stopped {
	//	return nil, grpcStatus.Errorf(codes.FailedPrecondition, "Cannot exec in stopped container %s", req.ContainerId)
	//}

	proc, err := buildProcess(req.Process, req.ExecId, false)
	if err != nil {
		return emptyResp, err
	}

	if err := a.execProcess(ctr, proc, false); err != nil {
		return emptyResp, err
	}

	return emptyResp, a.postExecProcess(ctr, proc)
}

func (a *agentGRPC) SignalProcess(ctx context.Context, req *pb.SignalProcessRequest) (*gpb.Empty, error) {
	return emptyResp, nil
}

// Check is the container process installed the
// handler for specific signal.
func isSignalHandled(pid int, signum syscall.Signal) bool {
	var sigMask uint64 = 1 << (uint(signum) - 1)
	procFile := fmt.Sprintf("/proc/%d/status", pid)
	file, err := os.Open(procFile)
	if err != nil {
		AgentLog.WithField("procFile", procFile).Warn("Open proc file failed")
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "SigCgt:") {
			maskSlice := strings.Split(line, ":")
			if len(maskSlice) != 2 {
				AgentLog.WithField("procFile", procFile).Warn("Parse the SigCgt field failed")
				return false
			}
			sigCgtStr := strings.TrimSpace(maskSlice[1])
			sigCgtMask, err := strconv.ParseUint(sigCgtStr, 16, 64)
			if err != nil {
				AgentLog.WithField("sigCgt", sigCgtStr).Warn("parse the SigCgt to hex failed")
				return false
			}
			return (sigCgtMask & sigMask) == sigMask
		}
	}
	return false
}

func (a *agentGRPC) WaitProcess(ctx context.Context, req *pb.WaitProcessRequest) (*pb.WaitProcessResponse, error) {
	return &pb.WaitProcessResponse{}, nil
}

func getPIDIndex(title string) int {
	// looking for PID field in ps title
	fields := strings.Fields(title)
	for i, f := range fields {
		if f == "PID" {
			return i
		}
	}
	return -1
}

func (a *agentGRPC) ListProcesses(ctx context.Context, req *pb.ListProcessesRequest) (*pb.ListProcessesResponse, error) {
	resp := &pb.ListProcessesResponse{}
	return resp, nil
}

func (a *agentGRPC) UpdateContainer(ctx context.Context, req *pb.UpdateContainerRequest) (*gpb.Empty, error) {
	return nil, nil
}

func (a *agentGRPC) StatsContainer(ctx context.Context, req *pb.StatsContainerRequest) (*pb.StatsContainerResponse, error) {
	resp := &pb.StatsContainerResponse{}
	return resp, nil

}

func (a *agentGRPC) PauseContainer(ctx context.Context, req *pb.PauseContainerRequest) (*gpb.Empty, error) {
	a.sandbox.Lock()
	defer a.sandbox.Unlock()

	return emptyResp, nil
}

func (a *agentGRPC) ResumeContainer(ctx context.Context, req *pb.ResumeContainerRequest) (*gpb.Empty, error) {
	a.sandbox.Lock()
	defer a.sandbox.Unlock()

	return emptyResp, nil
}

func (a *agentGRPC) RemoveContainer(ctx context.Context, req *pb.RemoveContainerRequest) (*gpb.Empty, error) {
	return emptyResp, nil
}

func (a *agentGRPC) WriteStdin(ctx context.Context, req *pb.WriteStreamRequest) (*pb.WriteStreamResponse, error) {
	proc, _, err := a.sandbox.getProcess(req.ContainerId, req.ExecId)
	if err != nil {
		return &pb.WriteStreamResponse{}, err
	}

	proc.RLock()
	defer proc.RUnlock()
	stdinClosed := proc.stdinClosed

	// Ignore this call to WriteStdin() if STDIN has already been closed
	// earlier.
	if stdinClosed {
		return &pb.WriteStreamResponse{}, nil
	}

	var file *os.File
	if proc.termMaster != nil {
		file = proc.termMaster
	} else {
		file = proc.stdin
	}

	n, err := file.Write(req.Data)
	if err != nil {
		return &pb.WriteStreamResponse{}, err
	}

	return &pb.WriteStreamResponse{
		Len: uint32(n),
	}, nil
}

func (a *agentGRPC) ReadStdout(ctx context.Context, req *pb.ReadStreamRequest) (*pb.ReadStreamResponse, error) {
	data, err := a.sandbox.readStdio(req.ContainerId, req.ExecId, int(req.Len), true)
	if err != nil {
		return &pb.ReadStreamResponse{}, err
	}

	return &pb.ReadStreamResponse{
		Data: data,
	}, nil
}

func (a *agentGRPC) ReadStderr(ctx context.Context, req *pb.ReadStreamRequest) (*pb.ReadStreamResponse, error) {
	data, err := a.sandbox.readStdio(req.ContainerId, req.ExecId, int(req.Len), false)
	if err != nil {
		return &pb.ReadStreamResponse{}, err
	}

	return &pb.ReadStreamResponse{
		Data: data,
	}, nil
}

func (a *agentGRPC) CloseStdin(ctx context.Context, req *pb.CloseStdinRequest) (*gpb.Empty, error) {
	proc, _, err := a.sandbox.getProcess(req.ContainerId, req.ExecId)
	if err != nil {
		return emptyResp, err
	}

	// If stdin is nil, which can be the case when using a terminal,
	// there is nothing to do.
	if proc.stdin == nil {
		return emptyResp, nil
	}

	proc.Lock()
	defer proc.Unlock()

	if err := proc.stdin.Close(); err != nil {
		return emptyResp, err
	}

	proc.stdinClosed = true

	return emptyResp, nil
}

func (a *agentGRPC) TtyWinResize(ctx context.Context, req *pb.TtyWinResizeRequest) (*gpb.Empty, error) {
	proc, _, err := a.sandbox.getProcess(req.ContainerId, req.ExecId)
	if err != nil {
		return emptyResp, err
	}

	if proc.termMaster == nil {
		return emptyResp, grpcStatus.Error(codes.FailedPrecondition, "Terminal is not set, impossible to resize it")
	}

	//winsize := &unix.Winsize{
	//	Row: uint16(req.Row),
	//	Col: uint16(req.Column),
	//}
	//
	//// Set new terminal size.
	//if err := unix.IoctlSetWinsize(int(proc.termMaster.Fd()), unix.TIOCSWINSZ, winsize); err != nil {
	//	return emptyResp, err
	//}

	return emptyResp, nil
}

func (a *agentGRPC) CreateSandbox(ctx context.Context, req *pb.CreateSandboxRequest) (*gpb.Empty, error) {
	return emptyResp, nil
}

func (a *agentGRPC) DestroySandbox(ctx context.Context, req *pb.DestroySandboxRequest) (*gpb.Empty, error) {
	return emptyResp, nil
}

func (a *agentGRPC) UpdateInterface(ctx context.Context, req *pb.UpdateInterfaceRequest) (*types.Interface, error) {
	//return a.sandbox.updateInterface(nil, req.Interface)
	return nil, nil
}

func (a *agentGRPC) UpdateRoutes(ctx context.Context, req *pb.UpdateRoutesRequest) (*pb.Routes, error) {
	//return a.sandbox.updateRoutes(nil, req.Routes)
	return nil, nil
}

func (a *agentGRPC) ListInterfaces(ctx context.Context, req *pb.ListInterfacesRequest) (*pb.Interfaces, error) {
	//return a.sandbox.listInterfaces(nil)
	return nil, nil
}

func (a *agentGRPC) ListRoutes(ctx context.Context, req *pb.ListRoutesRequest) (*pb.Routes, error) {
	//return a.sandbox.listRoutes(nil)
	return nil, nil
}

func (a *agentGRPC) OnlineCPUMem(ctx context.Context, req *pb.OnlineCPUMemRequest) (*gpb.Empty, error) {
	if !req.Wait {
		go a.onlineCPUMem(req)
		return emptyResp, nil
	}

	return emptyResp, a.onlineCPUMem(req)
}

func (a *agentGRPC) ReseedRandomDev(ctx context.Context, req *pb.ReseedRandomDevRequest) (*gpb.Empty, error) {
	//return emptyResp, reseedRNG(req.Data)
	return emptyResp, nil
}

func (a *agentGRPC) GetGuestDetails(ctx context.Context, req *pb.GuestDetailsRequest) (*pb.GuestDetailsResponse, error) {
	logrus.Infof("receive [GetGuestDetails] GuestDetailsRequest: %v", *req)
	var details pb.GuestDetailsResponse
	details.AgentDetails = a.getAgentDetails(ctx)

	return &details, nil
}

func (a *agentGRPC) MemHotplugByProbe(ctx context.Context, req *pb.MemHotplugByProbeRequest) (*gpb.Empty, error) {
	return emptyResp, nil
}

func (a *agentGRPC) haveSeccomp() bool {
	return false
}

func (a *agentGRPC) getAgentDetails(ctx context.Context) *pb.AgentDetails {
	details := pb.AgentDetails{
		Version:         version,
		InitDaemon:      os.Getpid() == 1,
		SupportsSeccomp: a.haveSeccomp(),
	}

	//for handler := range deviceHandlerList {
	//	details.DeviceHandlers = append(details.DeviceHandlers, handler)
	//}
	//
	//for handler := range storageHandlerList {
	//	details.StorageHandlers = append(details.StorageHandlers, handler)
	//}

	return &details
}

func (a *agentGRPC) SetGuestDateTime(ctx context.Context, req *pb.SetGuestDateTimeRequest) (*gpb.Empty, error) {
	//if err := syscall.Settimeofday(&syscall.Timeval{Sec: req.Sec, Usec: req.Usec}); err != nil {
	//	return nil, grpcStatus.Errorf(codes.Internal, "Could not set guest time: %v", err)
	//}
	return &gpb.Empty{}, nil
}

// CopyFile copies files form host to container's rootfs (guest). Files can be copied by parts, for example
// a file which size is 2MB, can be copied calling CopyFile 2 times, in the first call req.Offset is 0,
// req.FileSize is 2MB and req.Data contains the first half of the file, in the seconds call req.Offset is 1MB,
// req.FileSize is 2MB and req.Data contains the second half of the file. For security reason all write operations
// are made in a temporary file, once temporary file reaches the expected size (req.FileSize), it's moved to
// destination file (req.Path).
func (a *agentGRPC) CopyFile(ctx context.Context, req *pb.CopyFileRequest) (*gpb.Empty, error) {
	// get absolute path, to avoid paths like '/run/../sbin/init'
	path, err := filepath.Abs(req.Path)
	if err != nil {
		return emptyResp, err
	}

	// container's rootfs is mounted at /run, in order to avoid overwrite guest's rootfs files, only
	// is possible to copy files to /run
	//if !strings.HasPrefix(path, containersRootfsPath) {
	//	return emptyResp, fmt.Errorf("Only is possible to copy files into the %s directory", containersRootfsPath)
	//}

	if err := os.MkdirAll(filepath.Dir(path), os.FileMode(req.DirMode)); err != nil {
		return emptyResp, err
	}

	// create a temporary file and write the content.
	tmpPath := path + ".tmp"
	tmpFile, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return emptyResp, err
	}

	if _, err := tmpFile.WriteAt(req.Data, req.Offset); err != nil {
		tmpFile.Close()
		return emptyResp, err
	}
	tmpFile.Close()

	// get temporary file information
	st, err := os.Stat(tmpPath)
	if err != nil {
		return emptyResp, err
	}

	AgentLog.WithFields(logrus.Fields{
		"tmp-file-size": st.Size(),
		"expected-size": req.FileSize,
	}).Debugf("Checking temporary file size")

	// if file size is not equal to the expected size means that copy file operation has not finished.
	// CopyFile should be called again with new content and a different offset.
	if st.Size() != req.FileSize {
		return emptyResp, nil
	}

	if err := os.Chmod(tmpPath, os.FileMode(req.FileMode)); err != nil {
		return emptyResp, err
	}

	if err := os.Chown(tmpPath, int(req.Uid), int(req.Gid)); err != nil {
		return emptyResp, err
	}

	// At this point temoporary file has the expected size, atomically move it overwriting
	// the destination.
	AgentLog.WithFields(logrus.Fields{
		"tmp-path": tmpPath,
		"des-path": path,
	}).Debugf("Moving temporary file")

	if err := os.Rename(tmpPath, path); err != nil {
		return emptyResp, err
	}

	return emptyResp, nil
}

func (a *agentGRPC) StartTracing(ctx context.Context, req *pb.StartTracingRequest) (*gpb.Empty, error) {
	// We chould check 'tracing' too and error if already set. But
	// instead, we permit that scenario, making this call a NOP if tracing
	// is already enabled via traceModeFlag.
	if startTracingCalled {
		return nil, grpcStatus.Error(codes.FailedPrecondition, "tracing already enabled")
	}

	// The only trace type support for dynamic tracing is isolated.
	enableTracing(traceModeDynamic, traceTypeIsolated)
	startTracingCalled = true

	var err error

	// Ignore the provided context and recreate the root context.
	// Note that this call will not be traced, but all subsequent ones
	// will be.
	rootSpan, rootContext, err = setupTracing(AgentName)
	if err != nil {
		return nil, fmt.Errorf("failed to setup tracing: %v", err)
	}

	a.sandbox.ctx = rootContext
	grpcContext = rootContext

	return emptyResp, nil
}

func (a *agentGRPC) StopTracing(ctx context.Context, req *pb.StopTracingRequest) (*gpb.Empty, error) {
	// Like StartTracing(), this call permits tracing to be stopped when
	// it was originally started using traceModeFlag.
	if !tracing && !startTracingCalled {
		return nil, grpcStatus.Error(codes.FailedPrecondition, "tracing not enabled")
	}

	if stopTracingCalled {
		return nil, grpcStatus.Error(codes.FailedPrecondition, "tracing already disabled")
	}

	// Signal to the interceptors that tracing need to end.
	stopTracingCalled = true

	return emptyResp, nil
}

func (a *agentGRPC) GetUsers(ctx context.Context, req *pb.GetUsersRequest) (*pb.GetUsersResponse, error) {
	logrus.Infof("receive [GetUsers] GetUsersRequest: %v", *req)
	resp := pb.GetUsersResponse{}
	//get all activate users
	output, err := runCmd(getFnName(), `C:\Windows\System32\wbem\WMIC.exe`, "UserAccount", "where", "Status='OK'", "get", "Name", "/format:csv")
	logrus.Debugf("output:%s, err:%v", output, err)
	if err != nil {
		resp.Error = fmt.Sprintf("failed to get users, error:%v", err)
		return &resp, nil
	} else {
		for _, item := range strings.Split(string(output), "\r\r\n") {
			if item == "Node,Name" || item == "" {
				continue
			}
			u := strings.Split(item, ",")
			if len(u) == 2 {
				resp.Username = append(resp.Username, u[1])
			} else {
				logrus.Warnf("invalid user line: %v", u)
			}
		}
	}
	return &resp, nil
}

func (a *agentGRPC) GetHostname(ctx context.Context, req *pb.GetHostnameRequest) (*pb.GetHostnameResponse, error) {
	hostname, _ := os.Hostname()
	computerName, _ := windows.ComputerName()
	resp := pb.GetHostnameResponse{
		Hostname:     hostname,
		ComputerName: computerName,
	}
	return &resp, nil
}

func (a *agentGRPC) GetNetworkConfig(ctx context.Context, req *pb.GetNetworkConfigRequest) (*pb.GetNetworkConfigResponse, error) {
	logrus.Infof("receive [GetNetworkConfig] GetNetworkConfigRequest: %v", *req)
	resp := pb.GetNetworkConfigResponse{}
	mac := strings.ToUpper(strings.Join(strings.Split(req.MacAddress, "-"), ":"))
	resp.MacAddress = mac

	fieldAry := []string{"IPAddress", "IPSubnet", "DefaultIPGateway", "DNSServerSearchOrder"}

	output, err := runCmd(getFnName(), "wmic", "NICCONFIG", "WHERE", fmt.Sprintf("MACAddress='%s'", mac), "GET", strings.Join(fieldAry, ","), "/format:csv")
	if err != nil {
		resp.Error = fmt.Sprintf("failed to get network config, error:%v", convertByte2String([]byte(err.Error()), GB18030))
		return &resp, nil
	} else {
		ary := strings.Split(string(output), "\r\r\n")
		if len(ary) >= 4 {
			//remove { and }
			ary[1] = strings.Join(strings.Split(strings.Join(strings.Split(ary[1], "{"), ""), "}"), "")
			ary[2] = strings.Join(strings.Split(strings.Join(strings.Split(ary[2], "{"), ""), "}"), "")
			//split colume
			titles := strings.Split(ary[1], ",")
			values := strings.Split(ary[2], ",")
			if len(titles) != len(values) {
				resp.Error = fmt.Sprintf("failed to parse network config: %s", output)
				return &resp, nil
			} else {
				var (
					ipAry     []string
					subnetAry []string
				)
				for i, col := range titles {
					switch col {
					case "IPAddress":
						ipAry = strings.Split(values[i], ";")
					case "IPSubnet":
						subnetAry = strings.Split(values[i], ";")
					case "DefaultIPGateway":
						resp.Gateway = strings.Split(values[i], ";")[0]
					case "DNSServerSearchOrder":
						resp.DnsServer = strings.Split(values[i], ";")
					}
				}
				for i, item := range ipAry {
					ip := net.ParseIP(item)
					if ip.To4() != nil {
						addr := pb.Addrs{IpAddress: item, Subnet: subnetAry[i]}
						resp.Addrs = append(resp.Addrs, &addr)
					}
				}
			}
		}
	}
	return &resp, nil
}

func (a *agentGRPC) GetKMS(ctx context.Context, req *pb.GetKMSRequest) (*pb.GetKMSResponse, error) {
	logrus.Infof("receive [GetKMS] GetKMSRequest: %v", *req)
	resp := pb.GetKMSResponse{}

	output, err := runCmd(getFnName(), `C:\Windows\System32\reg.exe`, "query", `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform`, "/v", "KeyManagementServiceName")
	if err != nil {
		resp.Error = fmt.Sprintf("failed to get kms server, error:%v", convertByte2String([]byte(err.Error()), GB18030))
		return &resp, nil
	} else {
		for _, item := range strings.Split(string(output), "\r\n") {
			if strings.Contains(item, "REG_SZ") {
				ary := strings.Split(item, "REG_SZ")
				if len(ary) >= 2 {
					resp.Server = strings.TrimSpace(ary[1])
					break
				}
			}
		}
	}
	return &resp, nil
}

func (a *agentGRPC) SetUserPassword(ctx context.Context, req *pb.SetUserPasswordRequest) (*pb.SetUserPasswordResponse, error) {
	resp := pb.SetUserPasswordResponse{}
	if len(req.Password) < 8 {
		resp.Error = fmt.Sprintf("failed to set password of user %v, error: password length must be greater than or equal to 8", req.Username)
		return &resp, nil
	}

	password := req.Password
	req.Password = maskPassword(req.Password)
	logrus.Infof("receive [SetUserPassword] SetUserPasswordRequest: %v", *req)
	req.Password = password

	_, err := runCmd(getFnName(), "net", "user", req.Username, req.Password)
	if err != nil {
		resp.Error = fmt.Sprintf("failed to set password of user %v, error:%v", req.Username, err)
	}
	return &resp, nil
}

func (a *agentGRPC) SetHostname(ctx context.Context, req *pb.SetHostnameRequest) (*pb.SetHostnameResponse, error) {
	logrus.Infof("receive [SetHostname] SetHostnameRequest: %v", *req)
	resp := pb.SetHostnameResponse{}

	hostname, _ := windows.ComputerName()
	//use single quotes
	_, err := runCmd(getFnName(), "wmic", "computersystem", "where", fmt.Sprintf(`caption='%s'`, hostname), "rename", fmt.Sprintf(`'%s'`, req.Hostname))
	if err != nil {
		resp.Error = fmt.Sprintf("failed to set hostname to %v, error:%v", req.Hostname, err)
		return &resp, nil
	}

	//check NV Name
	output, err := runCmd(getFnName(), `C:\Windows\System32\reg.exe`, "query", `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters`, "/v", "NV Hostname")
	if err != nil {
		resp.Error = fmt.Sprintf("failed to get NV Hostname, error:%v", convertByte2String([]byte(err.Error()), GB18030))
		return &resp, nil
	} else {
		for _, item := range strings.Split(string(output), "\r\n") {
			if strings.Contains(item, "REG_SZ") {
				ary := strings.Split(item, "REG_SZ")
				if len(ary) >= 2 {
					if strings.TrimSpace(ary[1]) != hostname {
						resp.Restart = true
					}
					break
				}
			}
		}
	}

	if resp.Restart {
		_, err := runCmd(getFnName(), "shutdown.exe", "-r", "-t", "0")
		if err != nil {
			resp.Error = fmt.Sprintf("failed to restart to make the hostname take effect, error:%v", err)
			return &resp, nil
		}
	} else {
		logrus.Infof("hostname isn't changed, skip restart windows")
	}

	return &resp, nil
}

func (a *agentGRPC) SetNetworkConfig(ctx context.Context, req *pb.SetNetworkConfigRequest) (*pb.SetNetworkConfigResponse, error) {
	logrus.Infof("receive [SetNetworkConfig] SetNetworkConfigRequest: %v", *req)
	resp := pb.SetNetworkConfigResponse{}
	mac := strings.ToUpper(strings.Join(strings.Split(req.MacAddress, "-"), ":"))

	//set dns
	_, err := runCmd(getFnName(), "wmic", "nicconfig", "where", fmt.Sprintf("macaddress='%s'", mac), "call", fmt.Sprintf("SetDNSServerSearchOrder('%s')", strings.Join(req.DnsServer, "','")))
	if err != nil {
		resp.Error = fmt.Sprintf("failed to set dns to %v, error:%v", req.DnsServer, err)
		return &resp, nil
	}

	//set default gateway
	_, err = runCmd(getFnName(), "wmic", "nicconfig", "where", fmt.Sprintf("macaddress='%s'", mac), "call", fmt.Sprintf("SetGateways('%s'),(1)", req.Gateway))
	if err != nil {
		resp.Error = fmt.Sprintf("failed to set gateway to %v, error:%v", req.DnsServer, err)
		return &resp, nil
	}

	//set static ip
	addr := &pb.Addrs{}
	if len(req.Addrs) > 0 {
		addr = req.Addrs[0]
	}
	_, err = runCmd(getFnName(), "wmic", "nicconfig", "where", fmt.Sprintf("macaddress='%s'", mac), "call", fmt.Sprintf("EnableStatic('%s'),('%s')", addr.IpAddress, addr.Subnet))
	if err != nil {
		resp.Error = fmt.Sprintf("failed to set static ip to %v, error:%v", req.Addrs, err)
		return &resp, nil
	}

	return &resp, nil
}

func (a *agentGRPC) SetKMS(ctx context.Context, req *pb.SetKMSRequest) (*pb.SetKMSResponse, error) {
	logrus.Infof("receive [SetKMS] SetKMSRequest: %v", *req)
	resp := pb.SetKMSResponse{}

	_, err := runCmd(getFnName(), "cscript", "/Nologo", `C:\Windows\System32\slmgr.vbs`, "/skms", req.Server)
	if err != nil {
		resp.Error = fmt.Sprintf("failed to set kms server to %v, error:%v", req.Server, err)
	}
	return &resp, nil

}
