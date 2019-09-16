package service

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"os/exec"
)

func runCmd(cmd string, args ...string) ([]byte, error) {
	removeUTF8BOM := func(b []byte) []byte {
		if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
			return b[3:]
		}
		return b
	}
	cmdLine := exec.Command(cmd, args...)
	logrus.Debugf("runCmd: %v", cmdLine.Args)
	out, err := cmdLine.CombinedOutput()
	if err != nil {
		if len(out) != 0 {
			return nil, fmt.Errorf("%s failed: %v: %q", args[0], err, string(removeUTF8BOM(out)))
		}

		if len(out) != 0 {
			return nil, fmt.Errorf("%s failed: %v: %q", args[0], err, string(removeUTF8BOM(out)))
		}
		return nil, fmt.Errorf("%s failed: %v", args[0], err)
	}
	return removeUTF8BOM(out), nil
}
