package portscan

import (
	"testing"
)

func Test(t *testing.T) {
	ipRange := "8.8.8.8/32"
	scan := make(map[string]PortACK)
	result := ScanCIDR(ScanConfig{Timeout: 10}, ipRange)
	for ack := range result {
		key := ack.Host + ack.Port
		if _, present := scan[key]; !present {
			scan[key] = ack
		}
	}
	if len(scan) == 0 {
		t.Error("The scan result is expected to be non-empty")
	}
}

func TestGetRouterHW(t *testing.T) {
	_, err := determineRouterHardwareAddress(ScanConfig{})
	if err != nil {
		t.Error(err.Error())
	}
}
