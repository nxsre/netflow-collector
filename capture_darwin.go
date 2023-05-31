package netflow_collector

import (
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"time"
)

func NewLivePackageSoruce(ifname string) (*PackageSoruce, error) {
	handle, err := pcap.OpenLive(ifname, 65535 /*每个数据包读取的最大值*/, false /*是否开启混杂模式*/, time.Second /*读包超时时长*/)
	if err != nil {
		return nil, err
	}
	return &PackageSoruce{pcapHandle: handle}, nil
}

type PackageSoruce struct {
	pcapHandle *pcap.Handle
}

func (p *PackageSoruce) Close() {
	if p.pcapHandle != nil {
		p.pcapHandle.Close()
	}
}

func (p *PackageSoruce) LinkType() layers.LinkType {
	if p.pcapHandle != nil {
		return p.pcapHandle.LinkType()
	}
	return layers.LinkTypeEthernet
}

func (p *PackageSoruce) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	if p.pcapHandle != nil {
		return p.pcapHandle.ReadPacketData()
	}
	err = errors.New("no valid handle")
	return
}

func (p *PackageSoruce) WritePacketData(data []byte) (err error) {
	return p.pcapHandle.WritePacketData(data)
}
