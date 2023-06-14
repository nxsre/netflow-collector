package netflow_collector

import (
	"context"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/node_exporter/collector"
	ext "github.com/reugn/go-streams/extension"
	"github.com/reugn/go-streams/flow"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// 流式计算
	flowIn  = make(chan interface{})
	flowOut = make(chan interface{})
	sink    *ext.ChanSink
)

func init() {
	source := ext.NewChanSource(flowIn)
	// flow.NewSlidingWindow 的两个入参 windowsize 和 slidingInterval 相等时，两个窗口数据无交集
	slidingWindow, err := flow.NewSlidingWindow(1000*time.Millisecond, 1000*time.Millisecond)
	if err != nil {
		log.Fatal(err)
	}
	sink = ext.NewChanSink(flowOut)
	go func() {
		// 连接数据源,
		source.
			Via(slidingWindow).
			To(sink)
	}()
}

// localAddrs = map[string]map[string]{"en0":map[string]string{"mac":"ip":{},"ip":"mac":{}}
var localAddrs = map[string]map[string]map[string]struct{}{}

// 增加本地接口地址（用来标记流量方向）
func InsertLocalAddresses(ifname, ip, mac string) {
	if _, ok := localAddrs[ifname]; !ok {
		localAddrs[ifname] = map[string]map[string]struct{}{ip: {mac: {}}, mac: {ip: {}}}
	} else {
		if _, ok := localAddrs[ifname][ip]; !ok {
			localAddrs[ifname][ip] = map[string]struct{}{mac: {}}
		} else {
			localAddrs[ifname][ip][mac] = struct{}{}
		}
		if _, ok := localAddrs[ifname][mac]; !ok {
			localAddrs[ifname][mac] = map[string]struct{}{ip: {}}
		} else {
			localAddrs[ifname][mac][ip] = struct{}{}
		}
	}
}

// 删除本地接口地址（用来标记流量方向）
func DeleteLocalAddresses(ifname, ip, mac string) {
	if _, ok := localAddrs[ifname]; !ok {
		return
	}
	if ip == "" && mac == "" {
		delete(localAddrs, ifname)
	}

	if ip != "" {
		delete(localAddrs[ifname], ip)
		for k, v := range localAddrs[ifname] {
			if _, ok := v[ip]; ok {
				delete(localAddrs[ifname][k], ip)
			}
		}
	}

	if mac != "" {
		delete(localAddrs[ifname], mac)
		for k, v := range localAddrs[ifname] {
			if _, ok := v[ip]; ok {
				delete(localAddrs[ifname][k], mac)
			}
		}
	}
}

// 获取本地接口列表
func GetLocalAddresses() map[string]map[string]map[string]struct{} {
	return localAddrs
}

func GetCollector(ctx context.Context, ifname, assetTag string) (collector.Collector, error) {
	if ifname == "all" {
		interfaces, err := net.Interfaces()
		if err != nil {
			return nil,err
		}
		for _, iface := range interfaces {
			log.Println("cap", iface.Name)
			go capture(ctx, iface.Name, flowIn)
		}
	} else {
		_, err := net.InterfaceByName(ifname)
		if err != nil {
			return nil, err
		}
		go capture(ctx, ifname, flowIn)
	}
	var col = &Collector{
		Metrics: map[string]ColMetric{},
	}

	go func() {
		// 清理垃圾指标
		ticker := time.NewTicker(5 * time.Second)
		for {
			select {
			case <-ticker.C:
				col.Lock()
				for k, v := range col.Metrics {
					if time.Now().Sub(v.timeStamp).Seconds() >= 5 {
						delete(col.Metrics, k)
					}
				}
				col.Unlock()
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		// 实时读出窗口中的数据
		for {
			select {
			case <-ctx.Done():
				return
			case e := <-sink.Out:
				ts := calcTraffic(e.([]interface{}))
				for key, v := range ts {
					// TODO: 经过统计的流量监控数据写入到 kafka
					desc := prometheus.NewDesc(v.Meta.Protocol.String(), "netflow-collector details metric",
						[]string{"Protocol", "Version", "Direction", "LocalIP", "LocalPort", "PeerIP", "PeerPort"},
						prometheus.Labels{"owner": "netflow-collector@odv", "assetTag": assetTag, "ifName": ifname},
					)

					labels := []string{}
					switch v.Meta.Direction {
					case InDirection:
						labels = []string{v.Meta.Protocol.String(),
							v.Meta.IPver,
							string(v.Meta.Direction),
							v.Meta.DstIP.String(),
							strconv.FormatUint(uint64(v.Meta.DstPort), 10),
							v.Meta.SrcIP.String(),
							strconv.FormatUint(uint64(v.Meta.SrcPort), 10)}
					case OutDirection:
						labels = []string{v.Meta.Protocol.String(),
							v.Meta.IPver,
							string(v.Meta.Direction),
							v.Meta.SrcIP.String(),
							strconv.FormatUint(uint64(v.Meta.SrcPort), 10),
							v.Meta.DstIP.String(),
							strconv.FormatUint(uint64(v.Meta.DstPort), 10)}
					}
					metric, err := prometheus.NewConstMetric(desc, prometheus.GaugeValue, float64(*v.Val), labels...)
					if err != nil {
						log.Println(err)
					}
					col.Lock()
					col.Metrics[key] = ColMetric{metric, time.Now()}
					col.Unlock()
				}
			}
		}

	}()

	return col,nil
}

type Collector struct {
	sync.RWMutex
	Metrics map[string]ColMetric
}

type ColMetric struct {
	prometheus.Metric
	timeStamp time.Time
}

func (c *Collector) Update(ch chan<- prometheus.Metric) error {
	for _, metric := range c.Metrics {
		//fmt.Println("k, metric", k, metric)
		ch <- metric
	}
	return nil
}

type Metric struct {
	Val  *uint64
	Meta LogPacket
}
type Traffics map[string]Metric

func calcTraffic(elements []interface{}) Traffics {
	//values := map[string]{}
	traffics := make(Traffics)
	for _, e := range elements {
		switch v := e.(type) {
		case LogPacket:
			// 如果入站 MAC 是本机网卡 MAC ,则标记流量为入站 ->
			if _, ok := localAddrs[v.IfName][v.DstMAC.String()]; ok {
				key := fmt.Sprintf("%s_%v_local@%s@%d%speer@%s@%d", v.IfName, v.Protocol, v.DstIP.String(), v.DstPort, "<-", v.SrcIP.String(), v.SrcPort)
				//log.Println(i, "入站", v)
				meta := e.(LogPacket)
				meta.Direction = "receive"
				if val, ok := traffics[key]; !ok {
					v := uint64(v.Length)
					traffics[key] = Metric{
						Val:  &v,
						Meta: meta,
					}
				} else {
					atomic.AddUint64(val.Val, uint64(v.Length))
				}

			} else {
				//log.Println(i, "出站", v)
				key := fmt.Sprintf("%s_%v_local@%s@%d%speer@%s@%d", v.IfName, v.Protocol, v.SrcIP.String(), v.SrcPort, "->", v.DstIP.String(), v.DstPort)
				meta := e.(LogPacket)
				meta.Direction = "send"
				if val, ok := traffics[key]; !ok {
					v := uint64(v.Length)
					traffics[key] = Metric{
						Val:  &v,
						Meta: meta,
					}
				} else {
					atomic.AddUint64(val.Val, uint64(v.Length))
				}
			}
		}
	}
	//log.Println(values)
	return traffics
}

func capture(ctx context.Context, ifname string, flowIn chan interface{}) {
	// 判断是否 Loopback 网卡，parser.DecodeLayers 无法解析 loopback 设备的包，需要 packet.Layer 逐包断言
	loopback := false
	if iface, err := net.InterfaceByName(ifname); err == nil {
		if iface.Flags&net.FlagLoopback != 0 {
			loopback = true
		}
		if _, ok := localAddrs[iface.Name]; !ok {
			localAddrs[iface.Name] = map[string]map[string]struct{}{}
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if _, ok := localAddrs[iface.Name][addr.String()]; !ok {
				localAddrs[iface.Name][addr.String()] = map[string]struct{}{}
			}
			if _, ok := localAddrs[iface.Name][iface.HardwareAddr.String()]; !ok {
				localAddrs[iface.Name][iface.HardwareAddr.String()] = map[string]struct{}{}
			}

			localAddrs[iface.Name][addr.String()][iface.HardwareAddr.String()] = struct{}{}
			localAddrs[iface.Name][iface.HardwareAddr.String()][addr.String()] = struct{}{}
		}
	}

	handle, err := NewLivePackageSoruce(ifname)
	if err != nil {
		log.Fatalf("OpenEthernet: %v", err)
	}
	defer handle.Close()
	var (
		eth   layers.Ethernet
		ip4   layers.IPv4
		ip6   layers.IPv6
		tcp   layers.TCP
		udp   layers.UDP
		dns   layers.DNS
		icmp4 layers.ICMPv4
		icmp6 layers.ICMPv6
	)

	// 用于检测到违禁流量时阻断流量，旁路部署时的阻断流量的方法
	//{
	//	//创建缓冲区
	//	buf := gopacket.NewSerializeBuffer()
	//
	//	//后面需要的参数，这个一般不用变
	//	option := gopacket.SerializeOptions{}
	//
	//	//创建层
	//	ethernetLayer := &layers.Ethernet{
	//		SrcMAC:       net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
	//		DstMAC:       net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
	//		EthernetType: layers.EthernetTypeIPv4,
	//	}
	//
	//	ipLayer := &layers.IPv4{
	//		SrcIP:   net.IP{127, 0, 0, 1},
	//		DstIP:   net.IP{1, 1, 1, 1},
	//		Version: 4,
	//	}
	//
	//	tcpLayer := &layers.TCP{
	//		SrcPort: layers.TCPPort(11111),
	//		DstPort: layers.TCPPort(80),
	//	}
	//
	//	payload := []byte{1, 2, 3, 4, 5}
	//
	//	//先清空缓冲区，再把数据写入缓存区
	//	gopacket.SerializeLayers(buf, option,
	//		ethernetLayer,
	//		ipLayer,
	//		tcpLayer,
	//		gopacket.Payload(payload),
	//	)
	//	handle.WritePacketData(buf.Bytes())
	//}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true
	for {
		select {
		case <-ctx.Done():
			return
		case packet := <-packetSource.Packets():
			{
				var foundLayerTypes []gopacket.LayerType
				parser := gopacket.NewDecodingLayerParser(
					layers.LayerTypeEthernet,
					&eth,
					&ip4,
					&ip6,
					&tcp,
					&udp,
					&dns,
					&icmp4,
					&icmp6,
				)
				parser.IgnoreUnsupported = true
				// parser.DecodeLayers 无法解析 loopback 网卡的包
				err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)
				if err != nil {
					//解析到无法识别到数据包(如果是ARP等不支持等报文则记录下就离开)
					//log.Println("xxxxxxxxxxxxxxxx", err)
					for _, a := range packet.Layers() {
						log.Println(a.LayerType())
					}
				}

				var logPacket LogPacket
				logPacket.IfName = ifname
				logPacket.Time = time.Now()
				logPacket.Length = packet.Metadata().Length
				for _, layerType := range foundLayerTypes {
					logPacket.Type = append(logPacket.Type, layerType)
					switch layerType {
					case layers.LayerTypeIPv4, layers.LayerTypeICMPv4:
						logPacket.Protocol = ip4.Protocol
						logPacket.IPver = ip4.LayerType().String()
						logPacket.SrcIP = ip4.SrcIP
						logPacket.DstIP = ip4.DstIP
					case layers.LayerTypeIPv6, layers.LayerTypeICMPv6:
						logPacket.Protocol = ip6.NextHeader
						logPacket.IPver = ip6.LayerType().String()
						logPacket.SrcIP = ip6.SrcIP
						logPacket.DstIP = ip6.DstIP
					case layers.LayerTypeEthernet:
						logPacket.SrcMAC = eth.SrcMAC
						logPacket.DstMAC = eth.DstMAC
					case layers.LayerTypeARP: //处理ARP报文
						//logPacket.Type = append(logPacket.Type, layerType)
						//TODO 检测ARP泛洪
						continue
					case layers.LayerTypeTCP: // 处理TCP
						logPacket.SrcPort = uint16(tcp.SrcPort)
						logPacket.DstPort = uint16(tcp.DstPort)
					case layers.LayerTypeUDP: // 处理UDP
						logPacket.SrcPort = uint16(tcp.SrcPort)
						logPacket.DstPort = uint16(tcp.DstPort)
					}
				}

				//printEthInfo(packet)
				// loopback 网卡需要单独解析包
				if loopback {
					parseNetworkInfo(packet, &logPacket)
					parseTransportInfo(packet, &logPacket)
				}

				//log.Printf("%+v", logPacket)
				flowIn <- logPacket
			}
		}
	}
}

type Direction string

var (
	InDirection  Direction = "receive"
	OutDirection Direction = "send"
)

type LogPacket struct {
	IfName           string
	SrcIP, DstIP     net.IP
	SrcPort, DstPort uint16
	SrcMAC, DstMAC   net.HardwareAddr
	Protocol         layers.IPProtocol
	Type             []gopacket.LayerType //7层应用识别、TCP、UDP识别、传输协议方法识别
	Time             time.Time
	IPver            string    // IPv4 or  IPv6
	Direction        Direction // 数据流向，receive 或者 send
	Length           int
}

func parseNetworkInfo(packet gopacket.Packet, logPacket *LogPacket) {
	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		//fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)
		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, , FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		//fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		//fmt.Println("Protocol: ", ip.Protocol)
		//fmt.Println()

		logPacket.DstIP = ip.DstIP
		logPacket.SrcIP = ip.SrcIP
		logPacket.Protocol = ip.Protocol
		logPacket.IPver = ip.LayerType().String()
		return
	}

	ipLayer6 := packet.Layer(layers.LayerTypeIPv6)
	if ipLayer6 != nil {
		//fmt.Println("IPv6 layer detected.")
		ip6, _ := ipLayer6.(*layers.IPv6)
		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, , FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		//fmt.Printf("From %s to %s\n", ip6.SrcIP, ip6.DstIP)
		//fmt.Println("Protocol: ", ip6.NextHeader)
		//fmt.Println()
		//return &NetworkInfo{
		//	Version:  ip6.Version,
		//	SrcIP:    ip6.SrcIP,
		//	DstIP:    ip6.DstIP,
		//	Length:   ip6.Length,
		//	Protocol: ip6.NextHeader,
		//}
		logPacket.DstIP = ip6.DstIP
		logPacket.SrcIP = ip6.SrcIP
		logPacket.Protocol = ip6.NextHeader
		logPacket.IPver = ip6.LayerType().String()
	}
}

func parseTransportInfo(packet gopacket.Packet, logPacket *LogPacket) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		//fmt.Println("TCP layer detected.")
		tcp, _ := tcpLayer.(*layers.TCP)
		// TCP layer variables:
		// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		//fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
		//fmt.Println("Sequence number: ", tcp.Seq)
		//fmt.Println()
		logPacket.SrcPort = uint16(tcp.SrcPort)
		logPacket.DstPort = uint16(tcp.DstPort)
		return
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		//fmt.Println("UDP layer detected.")
		udp, _ := udpLayer.(*layers.UDP)
		// TCP layer variables:
		// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		//fmt.Printf("From port %d to %d\n", udp.SrcPort, udp.DstPort)
		//fmt.Println()
		logPacket.SrcPort = uint16(udp.SrcPort)
		logPacket.DstPort = uint16(udp.DstPort)
	}
}
