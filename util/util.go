package util

import (
	"fmt"
	"math/big"
	"net"
)

const InterfaceNameTemplate = "G%09s%03s%s"

func ParseIP(ip string) (net.IP, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, fmt.Errorf("cannot parse IP: %v", ip)
	}
	return parsed, nil
}

func ParseSegments(input []string) ([]net.IP, error) {
	var segments []net.IP
	for _, ipStr := range input {
		ip, err := ParseIP(ipStr)
		if err != nil {
			return nil, fmt.Errorf("could not parse ip (%s): %v", ipStr, err)
		}
		if ip.To4() != nil {
			return nil, fmt.Errorf("not an ipv6 address: %s", ipStr)
		}
		segments = append([]net.IP{ip}, segments...)
	}
	if len(segments) == 0 {
		return nil, fmt.Errorf("no segments parsed: %v", input)
	}
	return segments, nil
}

func GenerateInterfaceNameVRF(vpc, vpcAttachment string) string {
	return fmt.Sprintf(InterfaceNameTemplate, vpc, vpcAttachment, "V")
}

func GenerateInterfaceNameHost(vpc, vpcAttachment string) string {
	return fmt.Sprintf(InterfaceNameTemplate, vpc, vpcAttachment, "H")
}

func GenerateInterfaceNameGuest(vpc, vpcAttachment string) string {
	return fmt.Sprintf(InterfaceNameTemplate, vpc, vpcAttachment, "G")
}

func ExtractVPCFromSRv6Endpoint(endpoint net.IP) (string, string, error) {
	if endpoint.To4() != nil {
		return "", "", fmt.Errorf("provided endpoint is not an IPv6 address: %s", endpoint)
	}

	endpointNum := new(big.Int).SetBytes(endpoint)
	vpcNum := new(big.Int).And(
		new(big.Int).Rsh(endpointNum, 16), // drop the vpcattachment bits
		big.NewInt(0xFFFFFFFFFFFF),        // mask the vpc bits
	)
	vpcAttachmentNum := new(big.Int).And(
		endpointNum,
		big.NewInt(0xFFFF), // mask the vpcattachment bits
	)

	return fmt.Sprintf("%012x", vpcNum), fmt.Sprintf("%04x", vpcAttachmentNum), nil
}

func IsHost(ipNet *net.IPNet) bool {
	ones, bits := ipNet.Mask.Size()
	// host if mask is full length: /32 for IPv4, /128 for IPv6
	return ones == bits
}
