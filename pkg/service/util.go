package service

import (
	"fmt"
	"os/exec"

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

func runCmd(cmd string, args ...string) (string, error) {
	cmdLine := exec.Command(cmd, args...)
	logrus.Debugf("runCmd: %v", cmdLine.Args)
	buf, err := cmdLine.CombinedOutput()
	out := convertByte2String(buf, GBK)
	logrus.Infof("output:%s", out)
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
