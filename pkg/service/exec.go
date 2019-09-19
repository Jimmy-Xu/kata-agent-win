package service

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"os/exec"
)

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
