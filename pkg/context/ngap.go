package context

import (
	"net"

	"github.com/free5gc/ngap/ie"
)

func transportLayerAddressToIPStrings(address *ie.TransportLayerAddress) (ipv4, ipv6 string) {
	if address == nil {
		return
	}

	addressBytes := address.Value.Bytes
	switch address.Value.BitLength {
	case 32:
		if len(addressBytes) < net.IPv4len {
			return
		}
		ipv4 = net.IPv4(addressBytes[0], addressBytes[1], addressBytes[2], addressBytes[3]).String()
	case 128:
		if len(addressBytes) < net.IPv6len {
			return
		}
		ipv6 = net.IP(addressBytes[:net.IPv6len]).String()
	case 160:
		if len(addressBytes) < net.IPv4len+net.IPv6len {
			return
		}
		ipv4 = net.IPv4(addressBytes[0], addressBytes[1], addressBytes[2], addressBytes[3]).String()
		ipv6 = net.IP(addressBytes[net.IPv4len : net.IPv4len+net.IPv6len]).String()
	}
	return
}
