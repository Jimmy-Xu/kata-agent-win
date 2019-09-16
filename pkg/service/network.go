package service

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
)

func netshInterfaceIPv4ShowAddress(macAddr string, netshOutput []byte, lang string) []string {
	// Address information is listed like:
	//
	//Configuration for interface "Local Area Connection"
	//    DHCP enabled:                         Yes
	//    IP Address:                           10.0.0.2
	//    Subnet Prefix:                        10.0.0.0/24 (mask 255.255.255.0)
	//    IP Address:                           10.0.0.3
	//    Subnet Prefix:                        10.0.0.0/24 (mask 255.255.255.0)
	//    Default Gateway:                      10.0.0.254
	//    Gateway Metric:                       0
	//    InterfaceMetric:                      10
	//
	//Configuration for interface "Loopback Pseudo-Interface 1"
	//    DHCP enabled:                         No
	//    IP Address:                           127.0.0.1
	//    Subnet Prefix:                        127.0.0.0/8 (mask 255.0.0.0)
	//    InterfaceMetric:                      50
	//
	addrs := make([]string, 0)
	var addr, subnetprefix string
	var processingOurInterface bool
	lines := bytes.Split(netshOutput, []byte{'\r', '\n'})
	for _, line := range lines {
		if !processingOurInterface {
			if !bytes.HasPrefix(line, []byte("Configuration for interface")) {
				continue
			}
			if !bytes.Contains(line, []byte(`"`+macAddr+`"`)) {
				continue
			}
			processingOurInterface = true
			continue
		}
		if len(line) == 0 {
			break
		}
		if bytes.Contains(line, []byte("Subnet Prefix:")) {
			f := bytes.Split(line, []byte{':'})
			if len(f) == 2 {
				f = bytes.Split(f[1], []byte{'('})
				if len(f) == 2 {
					f = bytes.Split(f[0], []byte{'/'})
					if len(f) == 2 {
						subnetprefix = string(bytes.TrimSpace(f[1]))
						if addr != "" && subnetprefix != "" {
							addrs = append(addrs, addr+"/"+subnetprefix)
						}
					}
				}
			}
		}
		addr = ""
		if bytes.Contains(line, []byte("IP Address:")) {
			f := bytes.Split(line, []byte{':'})
			if len(f) == 2 {
				addr = string(bytes.TrimSpace(f[1]))
			}
		}
	}
	return addrs
}

func getMacAddrs() (macAddrs []string, err error) {
	netInterfaces, err := net.Interfaces()
	if err != nil {
		return macAddrs, fmt.Errorf("fail to get net interfaces: %v", err)
	}
	for _, netInterface := range netInterfaces {
		macAddr := netInterface.HardwareAddr.String()
		if len(macAddr) == 0 {
			continue
		}

		macAddrs = append(macAddrs, macAddr)
	}
	return macAddrs, nil
}

func getIP() (addr *net.IPNet, err error) {
	interfaceAddr, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("fail to get net interface addrs: %v", err)
	}
	for _, addr := range interfaceAddr {
		ipNet, isValidIpNet := addr.(*net.IPNet)
		if isValidIpNet && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			return ipNet, nil
		}

	}
	return nil, fmt.Errorf("ipv4 not found")
}

func mask2Subnet(mask net.IPMask) string {
	m := mask.String()
	var subnet []string
	for i := 0; i < 8; i = i + 2 {
		b, _ := strconv.ParseInt(m[i:i+2], 16, 16)
		subnet = append(subnet, fmt.Sprintf("%v", b))
	}
	return strings.Join(subnet, ".")
}
