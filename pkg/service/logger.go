package service

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lestrrat-go/file-rotatelogs"
	"github.com/sirupsen/logrus"
)

const (
	logPath    = `C:\Program Files\Kata\log`
	LogFileApp = "agent.log"
)

func InitLog(logfile string, debug bool) {
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}
	logpath := fmt.Sprintf(`%s\%s`, logPath, logfile)

	writer, err := rotatelogs.New(
		logpath+".%Y%m%d%H%M",
		rotatelogs.WithLinkName(logpath),
		rotatelogs.WithMaxAge(time.Hour*24*30),
		rotatelogs.WithRotationTime(time.Hour*24),
	)
	if err != nil {
		logrus.Fatal("Init log failed, err:", err)
	}

	////write to console and log file
	//mw := io.MultiWriter(os.Stdout, writer)
	//logrus.SetOutput(mw)

	//fix output log in windows service
	logrus.SetOutput(writer)

	logrus.Info(strings.Repeat("==========", 4))
	logrus.Infof("pid:%v", os.Getpid())
	logrus.Infof("write log to %v", logpath)
	logrus.Infof("set log level to %v", logrus.GetLevel().String())
}
