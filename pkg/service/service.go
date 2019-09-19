package service

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/grpc-ecosystem/grpc-opentracing/go/otgrpc"
	//"github.com/kata-containers/agent/pkg/uevent"
	pb "github.com/kata-containers/agent/protocols/grpc"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opentracing/opentracing-go"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	//"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcStatus "google.golang.org/grpc/status"

	"github.com/kardianos/service"
)

type Service struct {
	Logger *logrus.Entry
}

func (s *Service) Start(srv service.Service) error {
	s.Logger.Info("start kata-agent service")
	go s.run()
	return nil
}

func (s *Service) Stop(srv service.Service) error {
	s.Logger.Info("stop kata-agent service")
	srv.Stop()
	return nil
}

func (s *Service) run() {
	InitLog(LogFileApp, true)

	s.Logger = logrus.WithField("name", AgentName).
		WithField("pid", os.Getpid()).
		WithField("source", "agent")

	var err error

	// Initialize unique sandbox structure.
	sbox := &sandbox{
		Logger:     s.Logger,
		containers: make(map[string]*container),
		running:    false,
		// pivot_root won't work for initramfs, see
		// Documentation/filesystem/ramfs-rootfs-initramfs.txt
		noPivotRoot: false, //(fsType == typeRootfs),
		//subreaper:      r,
		pciDeviceMap:   make(map[string]string),
		deviceWatchers: make(map[string](chan string)),
		storages:       make(map[string]*sandboxStorage),
		stopServer:     make(chan struct{}),
	}

	//WriteLog(" s.initLogger()")
	if err = sbox.initLogger(); err != nil {
		s.Logger.Fatalf("failed to setup logger: %v", err)
	}

	// Set the sandbox context now that the context contains the tracing
	// information.
	sbox.ctx = rootContext

	s.Logger.Infof("s.setupSignalHandler()")
	if err = sbox.setupSignalHandler(); err != nil {
		s.Logger.Fatalf("failed to setup signal handler: %v", err)
	}

	// Check for vsock vs serial. This will fill the sandbox structure with
	// information about the channel.
	s.Logger.Infof("s.initChannel()")
	if err = sbox.initChannel(); err != nil {
		s.Logger.Fatalf("failed to setup channels: %v", err)
	}

	s.Logger.Infof("s.startGRPC()")
	// Start gRPC server.
	sbox.startGRPC()

	s.Logger.Infof("s.waitForStopServer()")
	go sbox.waitForStopServer()

	s.Logger.Infof("s.wg.Wait()")
	sbox.wg.Wait()

	s.Logger.Infof("%v exit", AgentName)
}

var (
	// Set to the context that should be used for tracing gRPC calls.
	grpcContext context.Context

	rootContext context.Context
)

var ServiceConfig = &service.Config{
	Name:        "kata-agent",
	DisplayName: "Kata-Agent Service",
	Description: "",
}

type process struct {
	sync.RWMutex

	id string
	//process     libcontainer.Process
	stdin       *os.File
	stdout      *os.File
	stderr      *os.File
	consoleSock *os.File
	termMaster  *os.File
	//epoller     *epoller
	exitCodeCh chan int
	sync.Once
	stdinClosed bool
}

type container struct {
	sync.RWMutex

	id          string
	initProcess *process
	//container       libcontainer.Container
	//config          configs.Config
	processes       map[string]*process
	mounts          []string
	useSandboxPidNs bool
	ctx             context.Context
}

type sandboxStorage struct {
	refCount int
}

type sandbox struct {
	sync.RWMutex
	ctx context.Context

	Logger *logrus.Entry

	id         string
	hostname   string
	containers map[string]*container
	channel    channel
	//network           network
	wg sync.WaitGroup
	//sharedPidNs       namespace
	mounts []string
	//subreaper         reaper
	server         *grpc.Server
	pciDeviceMap   map[string]string
	deviceWatchers map[string](chan string)
	//sharedUTSNs       namespace
	//sharedIPCNs       namespace
	//guestHooks        *specs.Hooks
	guestHooksPresent bool
	running           bool
	noPivotRoot       bool
	enableGrpcTrace   bool
	sandboxPidNs      bool
	storages          map[string]*sandboxStorage
	stopServer        chan struct{}
}

var agentFields = logrus.Fields{
	"name":   AgentName,
	"pid":    os.Getpid(),
	"source": "agent",
}

var AgentLog = logrus.WithFields(agentFields)

// version is the agent version. This variable is populated at build time.
var version = "unknown"
var Version = "unknown"

var debug = false

// tracing enables opentracing support
var tracing = false

// Associate agent traces with runtime traces. This can only be enabled using
// the traceModeFlag.
var collatedTrace = false

// if true, coredump when an internal error occurs or a fatal signal is received
var crashOnError = false

// if true, a shell (bash or sh) is started only if it's available in the rootfs.
var debugConsole = false

// commType is used to denote the communication channel type used.
type commType int

const (
	// virtio-serial channel
	serialCh commType = iota

	// vsock channel
	vsockCh

	// channel type not passed explicitly
	unknownCh
)

var commCh = unknownCh

func (c *container) trace(name string) (opentracing.Span, context.Context) {
	if c.ctx == nil {
		AgentLog.WithField("type", "bug").Error("trace called before context set")
		c.ctx = context.Background()
	}

	return trace(c.ctx, "container", name)
}

func (c *container) setProcess(process *process) {
	c.Lock()
	c.processes[process.id] = process
	c.Unlock()
}

func (c *container) deleteProcess(execID string) {
	span, _ := c.trace("deleteProcess")
	span.SetTag("exec-id", execID)
	defer span.Finish()
	c.Lock()
	delete(c.processes, execID)
	c.Unlock()
}

func (c *container) getProcess(execID string) (*process, error) {
	c.RLock()
	defer c.RUnlock()

	proc, exist := c.processes[execID]
	if !exist {
		return nil, grpcStatus.Errorf(codes.NotFound, "Process %s not found (container %s)", execID, c.id)
	}

	return proc, nil
}

func (s *sandbox) trace(name string) (opentracing.Span, context.Context) {
	if s.ctx == nil {
		AgentLog.WithField("type", "bug").Error("trace called before context set")
		s.ctx = context.Background()
	}

	span, ctx := trace(s.ctx, "sandbox", name)

	span.SetTag("sandbox", s.id)

	return span, ctx
}

// setSandboxStorage sets the sandbox level reference
// counter for the sandbox storage.
// This method also returns a boolean to let
// callers know if the storage already existed or not.
// It will return true if storage is new.
//
// It's assumed that caller is calling this method after
// acquiring a lock on sandbox.
func (s *sandbox) setSandboxStorage(path string) bool {
	if _, ok := s.storages[path]; !ok {
		sbs := &sandboxStorage{refCount: 1}
		s.storages[path] = sbs
		return true
	}
	sbs := s.storages[path]
	sbs.refCount++
	return false
}

// scanGuestHooks will search the given guestHookPath
// for any OCI hooks
func (s *sandbox) scanGuestHooks(guestHookPath string) {
	//span, _ := s.trace("scanGuestHooks")
	//span.SetTag("guest-hook-path", guestHookPath)
	//defer span.Finish()
	//
	//fieldLogger := AgentLog.WithField("oci-hook-path", guestHookPath)
	//fieldLogger.Info("Scanning guest filesystem for OCI hooks")
	//
	//s.guestHooks.Prestart = findHooks(guestHookPath, "prestart")
	//s.guestHooks.Poststart = findHooks(guestHookPath, "poststart")
	//s.guestHooks.Poststop = findHooks(guestHookPath, "poststop")
	//
	//if len(s.guestHooks.Prestart) > 0 || len(s.guestHooks.Poststart) > 0 || len(s.guestHooks.Poststop) > 0 {
	//	s.guestHooksPresent = true
	//} else {
	//	fieldLogger.Warn("Guest hooks were requested but none were found")
	//}
}

// addGuestHooks will add any guest OCI hooks that were
// found to the OCI spec
func (s *sandbox) addGuestHooks(spec *specs.Spec) {
	span, _ := s.trace("addGuestHooks")
	defer span.Finish()

	if spec == nil {
		return
	}

	if spec.Hooks == nil {
		spec.Hooks = &specs.Hooks{}
	}
}

// unSetSandboxStorage will decrement the sandbox storage
// reference counter. If there aren't any containers using
// that sandbox storage, this method will remove the
// storage reference from the sandbox and return 'true, nil' to
// let the caller know that they can clean up the storage
// related directories by calling removeSandboxStorage
//
// It's assumed that caller is calling this method after
// acquiring a lock on sandbox.
func (s *sandbox) unSetSandboxStorage(path string) (bool, error) {
	span, _ := s.trace("unSetSandboxStorage")
	span.SetTag("path", path)
	defer span.Finish()

	if sbs, ok := s.storages[path]; ok {
		sbs.refCount--
		// If this sandbox storage is not used by any container
		// then remove it's reference
		if sbs.refCount < 1 {
			delete(s.storages, path)
			return true, nil
		}
		return false, nil
	}
	return false, grpcStatus.Errorf(codes.NotFound, "Sandbox storage with path %s not found", path)
}

// removeSandboxStorage removes the sandbox storage if no
// containers are using that storage.
//
// It's assumed that caller is calling this method after
// acquiring a lock on sandbox.
func (s *sandbox) removeSandboxStorage(path string) error {
	span, _ := s.trace("removeSandboxStorage")
	span.SetTag("path", path)
	defer span.Finish()

	return nil
}

// unsetAndRemoveSandboxStorage unsets the storage from sandbox
// and if there are no containers using this storage it will
// remove it from the sandbox.
//
// It's assumed that caller is calling this method after
// acquiring a lock on sandbox.
func (s *sandbox) unsetAndRemoveSandboxStorage(path string) error {
	span, _ := s.trace("unsetAndRemoveSandboxStorage")
	span.SetTag("path", path)
	defer span.Finish()

	removeSbs, err := s.unSetSandboxStorage(path)
	if err != nil {
		return err
	}

	if removeSbs {
		if err := s.removeSandboxStorage(path); err != nil {
			return err
		}
	}

	return nil
}

func (s *sandbox) getContainer(id string) (*container, error) {
	s.RLock()
	defer s.RUnlock()

	ctr, exist := s.containers[id]
	if !exist {
		return nil, grpcStatus.Errorf(codes.NotFound, "Container %s not found", id)
	}

	return ctr, nil
}

func (s *sandbox) setContainer(ctx context.Context, id string, ctr *container) {
	// Update the context. This is required since the function is called
	// from by gRPC functions meaning we must use the latest context
	// available.
	s.ctx = ctx

	span, _ := s.trace("setContainer")
	span.SetTag("id", id)
	span.SetTag("container", ctr.id)
	defer span.Finish()

	s.Lock()
	s.containers[id] = ctr
	s.Unlock()
}

func (s *sandbox) deleteContainer(id string) {
	span, _ := s.trace("deleteContainer")
	span.SetTag("container", id)
	defer span.Finish()

	s.Lock()

	// Find the sandbox storage used by this container
	ctr, exist := s.containers[id]
	if !exist {
		AgentLog.WithField("container-id", id).Debug("Container doesn't exist")
	} else {
		// Let's go over the mounts used by this container
		for _, k := range ctr.mounts {
			// Check if this mount is used from sandbox storage
			if _, ok := s.storages[k]; ok {
				if err := s.unsetAndRemoveSandboxStorage(k); err != nil {
					AgentLog.WithError(err).Error()
				}
			}
		}
	}

	delete(s.containers, id)
	s.Unlock()
}

func (s *sandbox) getProcess(cid, execID string) (*process, *container, error) {
	if !s.running {
		return nil, nil, grpcStatus.Error(codes.FailedPrecondition, "Sandbox not started")
	}

	ctr, err := s.getContainer(cid)
	if err != nil {
		return nil, nil, err
	}

	// A container being in stopped state is not a valid reason for not
	// accepting a call to getProcess(). Indeed, we want to make sure a
	// shim can connect after the process has already terminated. Some
	// processes have a very short lifetime and the shim might end up
	// calling into WaitProcess() after this happened. This does not mean
	// we cannot retrieve the output and the exit code from the shim.
	proc, err := ctr.getProcess(execID)
	if err != nil {
		return nil, nil, err
	}

	return proc, ctr, nil
}

func (s *sandbox) readStdio(cid, execID string, length int, stdout bool) ([]byte, error) {
	proc, _, err := s.getProcess(cid, execID)
	if err != nil {
		return nil, err
	}

	var file *os.File
	if proc.termMaster != nil {
		// The process's epoller's run() will return a file descriptor of the process's
		// terminal or one end of its exited pipe. If it returns its terminal, it means
		// there is data needed to be read out or it has been closed; if it returns the
		// process's exited pipe, it means the process has exited and there is no data
		// needed to be read out in its terminal, thus following read on it will read out
		// "EOF" to terminate this process's io since the other end of this pipe has been
		// closed in reap().
		//file, err = proc.epoller.run()
		if err != nil {
			return nil, err
		}
	} else {
		if stdout {
			file = proc.stdout
		} else {
			file = proc.stderr
		}
	}

	buf := make([]byte, length)

	bytesRead, err := file.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:bytesRead], nil
}

func (s *sandbox) waitForStopServer() {
	span, _ := s.trace("waitForStopServer")
	defer span.Finish()

	fieldLogger := AgentLog.WithField("subsystem", "stopserverwatcher")

	fieldLogger.Info("Waiting for stopServer signal...")

	// Wait for DestroySandbox() to signal this thread about the need to
	// stop the server.
	<-s.stopServer

	fieldLogger.Info("stopServer signal received")

	if s.server == nil {
		fieldLogger.Info("No server initialized, nothing to stop")
		return
	}

	defer fieldLogger.Info("gRPC server stopped")

	// Try to gracefully stop the server for a minute
	timeout := time.Minute
	done := make(chan struct{})
	go func() {
		s.server.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		s.server = nil
		return
	case <-time.After(timeout):
		fieldLogger.WithField("timeout", timeout).Warn("Could not gracefully stop the server")
	}

	fieldLogger.Info("Force stopping the server now")

	span.SetTag("forced", true)
	s.stopGRPC()
}

// This loop is meant to be run inside a separate Go routine.
func (s *sandbox) signalHandlerLoop(sigCh chan os.Signal, errCh chan error) {
	s.Logger.Infof("signalHandlerLoop - begin")
	defer logrus.Infof("signalHandlerLoop - end")
	// Lock OS thread as subreaper is a thread local capability
	// and is not inherited by children created by fork(2) and clone(2).
	runtime.LockOSThread()
	s.Logger.Infof("close(errCh)")
	close(errCh)

	for sig := range sigCh {
		logger := AgentLog.WithField("signal", sig)

		logger.Infof("signalHandlerLoop - 1")
		nativeSignal, ok := sig.(syscall.Signal)
		if !ok {
			err := errors.New("unknown signal")
			logger.WithError(err).Error("failed to handle signal")
			continue
		}

		logger.Infof("signalHandlerLoop - 2")
		if fatalSignal(nativeSignal) {
			logger.Error("received fatal signal")
			die(s.ctx)
		}

		logger.Infof("signalHandlerLoop - 3")
		if debug && nonFatalSignal(nativeSignal) {
			logger.Debug("handling signal")
			backtrace()
			continue
		}

		logger.Info("ignoring unexpected signal")
	}
}

func (s *sandbox) setupSignalHandler() error {
	span, _ := s.trace("setupSignalHandler")
	defer span.Finish()

	s.Logger.Infof("setupSignalHandler - begin")
	defer logrus.Infof("setupSignalHandler - end")

	sigCh := make(chan os.Signal, 512)
	signal.Notify(sigCh, syscall.SIGTERM)

	for _, sig := range handledSignals() {
		signal.Notify(sigCh, sig)
	}

	errCh := make(chan error, 1)
	go s.signalHandlerLoop(sigCh, errCh)
	return <-errCh
}

func getMemory() (int, error) {
	return 0, nil
}

func getAnnounceFields() (logrus.Fields, error) {
	memTotal, err := getMemory()
	if err != nil {
		return logrus.Fields{}, err
	}
	return logrus.Fields{
		"version":       version,
		"system-memory": memTotal,
	}, nil
}

// formatFields converts logrus Fields (containing arbitrary types) into a string slice.
func formatFields(fields logrus.Fields) []string {
	var results []string

	for k, v := range fields {
		value, ok := v.(string)
		if !ok {
			// convert non-string value into a string
			value = fmt.Sprint(v)
		}
		results = append(results, fmt.Sprintf("%s=%q", k, value))
	}
	return results
}

// announce logs details of the agents version and capabilities.
func announce() error {
	announceFields, err := getAnnounceFields()
	if err != nil {
		return err
	}

	if os.Getpid() == 1 {
		fields := formatFields(agentFields)
		extraFields := formatFields(announceFields)

		fields = append(fields, extraFields...)

		fmt.Printf("announce: %s\n", strings.Join(fields, ","))
	} else {
		AgentLog.WithFields(announceFields).Info("announce")
	}

	return nil
}

func (s *sandbox) initLogger() error {
	//AgentLog.Logger.Formatter = &logrus.TextFormatter{DisableColors: true, TimestampFormat: time.RFC3339Nano}
	//
	//config := newConfig(defaultLogLevel)
	////if err := config.getConfig(kernelCmdlineFile); err != nil {
	////	AgentLog.WithError(err).Warn("Failed to get config from kernel cmdline")
	////}
	//
	//AgentLog.Logger.SetLevel(config.logLevel)

	AgentLog = s.Logger

	return announce()
}

func (s *sandbox) initChannel() error {
	span, ctx := s.trace("initChannel")
	defer span.Finish()

	c, err := newChannel(ctx)
	if err != nil {
		return err
	}

	s.channel = c

	return nil
}

func makeUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(origCtx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		var start time.Time
		var elapsed time.Duration
		var message proto.Message

		grpcCall := info.FullMethod
		var ctx context.Context
		var span opentracing.Span

		if tracing {
			ctx = getGRPCContext()
			span, _ = trace(ctx, "gRPC", grpcCall)
			span.SetTag("grpc-method-type", "unary")

			if strings.HasSuffix(grpcCall, "/ReadStdout") || strings.HasSuffix(grpcCall, "/WriteStdin") {
				// Add a tag to allow filtering of those calls dealing
				// input and output. These tend to be very long and
				// being able to filter them out allows the
				// performance of "core" calls to be determined
				// without the "noise" of these calls.
				span.SetTag("api-category", "interactive")
			}
		} else {
			// Just log call details
			message = req.(proto.Message)

			AgentLog.WithFields(logrus.Fields{
				"request": grpcCall,
				"req":     message.String()}).Debug("new request")
			start = time.Now()
		}

		// Use the context which will provide the correct trace
		// ordering, *NOT* the context provided to the function
		// returned by this function.
		resp, err = handler(getGRPCContext(), req)

		if !tracing {
			// Just log call details
			elapsed = time.Since(start)
			message = resp.(proto.Message)

			logger := AgentLog.WithFields(logrus.Fields{
				"request":  info.FullMethod,
				"duration": elapsed.String(),
				"resp":     message.String()})
			logger.Debug("request end")
		}

		// Handle the following scenarios:
		//
		// - Tracing was (and still is) enabled.
		// - Tracing was enabled but the handler (StopTracing()) disabled it.
		// - Tracing was disabled but the handler (StartTracing()) enabled it.
		if span != nil {
			span.Finish()
		}

		//if stopTracingCalled {
		//	stopTracing(ctx)
		//}

		return resp, err
	}
}

func (s *sandbox) startGRPC() {
	span, _ := s.trace("startGRPC")
	defer span.Finish()

	// Save the context for gRPC calls. They are provided with a different
	// context, but we need them to use our context as it contains trace
	// metadata.
	grpcContext = s.ctx

	grpcImpl := &agentGRPC{
		sandbox: s,
		version: version,
	}

	var grpcServer *grpc.Server

	var serverOpts []grpc.ServerOption

	if collatedTrace {
		// "collated" tracing (allow agent traces to be
		// associated with runtime-initiated traces.
		tracer := span.Tracer()

		serverOpts = append(serverOpts, grpc.UnaryInterceptor(otgrpc.OpenTracingServerInterceptor(tracer)))
	} else {
		// Enable interceptor whether tracing is enabled or not. This
		// is necessary to support StartTracing() and StopTracing()
		// since they require the interceptors to change their
		// behaviour depending on whether tracing is enabled.
		//
		// When tracing is enabled, the interceptor handles "isolated"
		// tracing (agent traces are not associated with runtime-initiated
		// traces).
		serverOpts = append(serverOpts, grpc.UnaryInterceptor(makeUnaryInterceptor()))
	}

	grpcServer = grpc.NewServer(serverOpts...)

	pb.RegisterAgentServiceServer(grpcServer, grpcImpl)
	pb.RegisterHealthServer(grpcServer, grpcImpl)
	pb.RegisterWindowsServiceServer(grpcServer, grpcImpl)

	s.server = grpcServer

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		var err error
		var servErr error
		for {
			AgentLog.Info("agent grpc server starts")

			err = s.channel.setup()
			if err != nil {
				AgentLog.WithError(err).Warn("Failed to setup agent grpc channel")
				return
			}

			err = s.channel.wait()
			if err != nil {
				AgentLog.WithError(err).Warn("Failed to wait agent grpc channel ready")
				return
			}

			var l net.Listener
			l, err = s.channel.listen()
			if err != nil {
				AgentLog.WithError(err).Warn("Failed to create agent grpc listener")
				return
			}

			// l is closed when Serve() returns
			servErr = grpcServer.Serve(l)
			if servErr != nil {
				AgentLog.WithError(servErr).Warn("agent grpc server quits")
			}

			err = s.channel.teardown()
			if err != nil {
				AgentLog.WithError(err).Warn("agent grpc channel teardown failed")
			}

			// Based on the definition of grpc.Serve(), the function
			// returns nil in case of a proper stop triggered by either
			// grpc.GracefulStop() or grpc.Stop(). Those calls can only
			// be issued by the chain of events coming from DestroySandbox
			// and explicitly means the server should not try to listen
			// again, as the sandbox is being completely removed.
			if servErr == nil {
				AgentLog.Info("agent grpc server has been explicitly stopped")
				return
			}
		}
	}()
}

func getGRPCContext() context.Context {
	if grpcContext != nil {
		return grpcContext
	}

	AgentLog.Warn("Creating gRPC context as none found")

	return context.Background()
}

func (s *sandbox) stopGRPC() {
	if s.server != nil {
		s.server.Stop()
		s.server = nil
	}
}
