package api

import (
	"bytes"
	"encoding/json"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/netrack/openflow"
	"github.com/netrack/openflow/ofp"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"net/http/httptest"
	"testing"
)

type DeviceList struct {
	Devices []string `json:"devices"`
}

func TestPacketOutNoDPID(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	api := NewAPI(":4242")

	resp := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://example.com/oftee", nil)
	req.Header.Add("Content-type", "application/octet-stream")
	api.serveMux.ServeHTTP(resp, req)
	log.Debugf("%+v\n", resp)
	if resp.Code != 405 {
		t.Errorf("Incorrect response code, expected 405, got %d", resp.Code)
	}
}

func TestPacketOutUnknownDPID(t *testing.T) {
	api := NewAPI(":4242")

	resp := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://example.com/oftee/0x1", nil)
	req.Header.Add("Content-type", "application/octet-stream")
	api.serveMux.ServeHTTP(resp, req)
	if resp.Code != 404 {
		t.Errorf("Incorrect response code, expected 404, got %d", resp.Code)
	}
}

type MockInjector struct {
	DPID     uint64
	Messages [][]byte
}

func (*MockInjector) Stop() {}
func (m *MockInjector) Inject(message []byte) {
	m.Messages = append(m.Messages, message)
}
func (m *MockInjector) SetDPID(dpid uint64) {
	m.DPID = dpid
}
func (*MockInjector) GetDPID() uint64 {
	return 0
}
func (*MockInjector) Copy(w io.Writer, r io.Reader) (int64, error) {
	return 0, nil
}

func TestPacketOutKnownDPID(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	api := NewAPI(":4242")

	go api.dpidMappingUpdates()

	mock := &MockInjector{
		DPID: 0x1,
	}

	api.DPIDMappingListener <- DPIDMapping{
		Action: MapActionAdd,
		DPID:   0x1,
		Inject: mock,
	}

	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		SourceProtAddress: []byte{0x0, 0x0, 0x0, 0x0},
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}
	arpBuf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(arpBuf, opts,
		&eth,
		&arp)
	if err != nil {
		log.WithError(err).Error("serializing layers")
		t.Error(err)
	}
	log.Printf("ARP: %02x", arpBuf.Bytes())

	message := &bytes.Buffer{}
	packet := &bytes.Buffer{}
	po := ofp.PacketOut{
		Buffer:  ofp.NoBuffer,
		InPort:  2,
		Actions: ofp.Actions{&ofp.ActionOutput{2, ofp.ContentLenNoBuffer}},
	}
	ofReq := openflow.NewRequest(openflow.TypePacketOut, packet)
	_, err = po.WriteTo(packet)
	if err != nil {
		log.WithError(err).Error("writing packet to OFP")
		t.Error(err)
	}

	_, err = packet.Write(arpBuf.Bytes())
	if err != nil {
		log.WithError(err).Error("writing arp to packet")
		t.Error(err)
	}

	_, err = ofReq.WriteTo(message)
	if err != nil {
		log.WithError(err).Error("writing OF req to bytes")
		t.Error(err)
	}

	resp := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://example.com:4242/oftee/0x0000000000000001", message)
	req.Header.Add("Content-type", "application/octet-stream")
	api.serveMux.ServeHTTP(resp, req)
	log.Debugf("+%v\n", resp)
	if resp.Code != 200 {
		t.Errorf("Incorrect response code, expected 200, got %d", resp.Code)
	}
	if len(mock.Messages) != 1 {
		t.Errorf("Expected 1 message, found %d", len(mock.Messages))
	}
}

func TestPacketOutShortPacket(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	api := NewAPI(":4242")

	go api.dpidMappingUpdates()

	mock := &MockInjector{
		DPID: 0x1,
	}

	api.DPIDMappingListener <- DPIDMapping{
		Action: MapActionAdd,
		DPID:   0x1,
		Inject: mock,
	}

	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		SourceProtAddress: []byte{0x0, 0x0, 0x0, 0x0},
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}
	arpBuf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(arpBuf, opts,
		&eth,
		&arp)
	if err != nil {
		log.WithError(err).Error("serializing layers")
		t.Error(err)
	}
	log.Printf("ARP: %02x", arpBuf.Bytes())

	message := &bytes.Buffer{}
	packet := &bytes.Buffer{}
	po := ofp.PacketOut{
		Buffer:  ofp.NoBuffer,
		InPort:  2,
		Actions: ofp.Actions{&ofp.ActionOutput{2, ofp.ContentLenNoBuffer}},
	}
	ofReq := openflow.NewRequest(openflow.TypePacketOut, packet)
	_, err = po.WriteTo(packet)
	if err != nil {
		log.WithError(err).Error("writing packet to OFP")
		t.Error(err)
	}

	_, err = packet.Write(arpBuf.Bytes())
	if err != nil {
		log.WithError(err).Error("writing arp to packet")
		t.Error(err)
	}

	_, err = ofReq.WriteTo(message)
	if err != nil {
		log.WithError(err).Error("writing OF req to bytes")
		t.Error(err)
	}

	resp := httptest.NewRecorder()
	req := httptest.NewRequest("POST",
		"http://example.com:4242/oftee/0x0000000000000001",
		io.LimitReader(message, 10))
	req.Header.Add("Content-type", "application/octet-stream")
	api.serveMux.ServeHTTP(resp, req)
	log.Debugf("+%v\n", resp)
	if resp.Code != 400 {
		t.Errorf("Incorrect response code, expected 400, got %d", resp.Code)
	}
}

func TestListDevicesEmpty(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	api := NewAPI(":4242")

	resp := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com:4242/oftee", nil)
	api.serveMux.ServeHTTP(resp, req)
	if resp.Code != 200 {
		t.Errorf("Incorrect response code, expected 200, got %d", resp.Code)
	}

	decoder := json.NewDecoder(resp.Body)
	list := &DeviceList{}
	if err := decoder.Decode(list); err != nil {
		t.Errorf("Failed to decode response : %s", err)
	}
	if len(list.Devices) != 0 {
		t.Errorf("Expected 0 devices, got %d", len(list.Devices))
	}
}

func TestListDevices(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	api := NewAPI(":4242")

	go api.dpidMappingUpdates()

	mock := &MockInjector{
		DPID: 0x1,
	}

	api.DPIDMappingListener <- DPIDMapping{
		Action: MapActionAdd,
		DPID:   0x1,
		Inject: mock,
	}

	resp := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com:4242/oftee", nil)
	api.serveMux.ServeHTTP(resp, req)
	log.Debugf("+%v\n", resp)
	if resp.Code != 200 {
		t.Errorf("Incorrect response code, expected 200, got %d", resp.Code)
	}

	decoder := json.NewDecoder(resp.Body)
	list := &DeviceList{}
	if err := decoder.Decode(list); err != nil {
		t.Errorf("Failed to decode response : %s", err)
	}
	if len(list.Devices) != 1 {
		t.Errorf("Expected 1 devices, got %d", len(list.Devices))
	}
}
