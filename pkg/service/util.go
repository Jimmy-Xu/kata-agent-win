package service

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/text/encoding/simplifiedchinese"
)

type Charset string

const (
	UTF8    = Charset("UTF-8")
	GB18030 = Charset("GB18030")
	GBK     = Charset("GBK")
	GB2312  = Charset("GB2312")
)

func convertByte2String(byte []byte, charset Charset) string {
	var str string
	switch charset {
	case GB18030:
		var decodeBytes, _ = simplifiedchinese.GB18030.NewDecoder().Bytes(byte)
		str = string(decodeBytes)
	case GBK:
		var decodeBytes, _ = simplifiedchinese.GBK.NewDecoder().Bytes(byte)
		str = string(decodeBytes)
	case GB2312:
		var decodeBytes, _ = simplifiedchinese.HZGB2312.NewDecoder().Bytes(byte)
		str = string(decodeBytes)

	case UTF8:
		fallthrough
	default:
		str = string(byte)
	}

	return str
}

func runCmd(action string, cmd string, args ...string) (string, error) {
	cmdLine := exec.Command(cmd, args...)
	buf, err := cmdLine.CombinedOutput()
	out := convertByte2String(buf, GBK)
	logrus.Debugf("action: %v", action)
	if strings.Contains(action, "SetUserPassword") {
		cmdLine.Args[3] = maskPassword(args[2])
	}
	logrus.Debugf("runCmd: %v, output: %v", cmdLine.Args, out)
	if err != nil {
		if len(out) != 0 {
			return "", fmt.Errorf("%s failed: %v: %s", args[0], err, out)
		}

		if len(out) != 0 {
			return "", fmt.Errorf("%s failed: %v: %s", args[0], err, out)
		}
		return "", fmt.Errorf("%s failed: %v", args[0], err)
	}
	return out, nil
}

func maskPassword(password string) string {
	l := len(password)
	return fmt.Sprintf("%s%s%s", password[0:1], strings.Repeat("*", l-2), password[l-1:l])
}

func getFnName() string {
	pc, _, _, _ := runtime.Caller(1)
	return runtime.FuncForPC(pc).Name()
}
