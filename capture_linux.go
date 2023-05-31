package netflow_collector

import (
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func NewLivePackageSoruce(ifname string) (*PackageSoruce, error) {
	handle, err := pcapgo.NewEthernetHandle(ifname)
	if err != nil {
		return nil, err
	}
	return &PackageSoruce{pcapgoHandle: handle}, nil
}

type PackageSoruce struct {
	pcapgoHandle *pcapgo.EthernetHandle
}

func (p *PackageSoruce) Close() {
	if p.pcapgoHandle != nil {
		p.pcapgoHandle.Close()
	}
}

func (p *PackageSoruce) LinkType() layers.LinkType {
	return layers.LinkTypeEthernet
}

func (p *PackageSoruce) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	if p.pcapgoHandle != nil {
		return p.pcapgoHandle.ReadPacketData()
	}
	err = errors.New("no valid handle")
	return
}
