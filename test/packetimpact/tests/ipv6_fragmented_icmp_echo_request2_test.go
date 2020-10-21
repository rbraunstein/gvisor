// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipv6_fragmented_icmp_echo_request2_test

import (
	"bytes"
	"encoding/hex"
	"flag"
	"net"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

const (
	data              = "IPV6_PROTOCOL_TESTER_FOR_FRAGMENT"
	fragmentID        = 1
	reassemblyTimeout = 61 * time.Second
)

func init() {
	testbench.RegisterFlags(flag.CommandLine)
}

func createFragmentedICMPEchoRequest(t *testing.T, conn *testbench.Connection, firstPayloadLength uint16, payload []byte, secondFragmentOffset uint16) ([]testbench.Layers, [][]byte) {
	t.Helper()

	icmpv6Header := header.ICMPv6(make([]byte, header.ICMPv6EchoMinimumSize))
	icmpv6Header.SetType(header.ICMPv6EchoRequest)
	icmpv6Header.SetCode(header.ICMPv6UnusedCode)
	icmpv6Header.SetIdent(0)
	icmpv6Header.SetSequence(0)
	cksum := header.ICMPv6Checksum(
		icmpv6Header,
		tcpip.Address(net.ParseIP(testbench.LocalIPv6).To16()),
		tcpip.Address(net.ParseIP(testbench.RemoteIPv6).To16()),
		buffer.NewVectorisedView(len(payload), []buffer.View{payload}),
	)
	icmpv6Header.SetChecksum(cksum)
	icmpv6Bytes := append([]byte(icmpv6Header), payload...)

	icmpv6ProtoNum := header.IPv6ExtensionHeaderIdentifier(header.ICMPv6ProtocolNumber)

	firstFragment := conn.CreateFrame(t, testbench.Layers{&testbench.IPv6{}},
		&testbench.IPv6FragmentExtHdr{
			NextHeader:     &icmpv6ProtoNum,
			FragmentOffset: testbench.Uint16(0),
			MoreFragments:  testbench.Bool(true),
			Identification: testbench.Uint32(fragmentID),
		},
		&testbench.Payload{
			Bytes: icmpv6Bytes[:header.ICMPv6PayloadOffset+firstPayloadLength],
		},
	)
	firstIPv6 := firstFragment[1:]
	firstIPv6Bytes, err := firstIPv6.ToBytes()
	if err != nil {
		t.Fatalf("can't convert first %s to bytes: %s", firstIPv6, err)
	}

	secondFragment := conn.CreateFrame(t, testbench.Layers{&testbench.IPv6{}},
		&testbench.IPv6FragmentExtHdr{
			NextHeader:     &icmpv6ProtoNum,
			FragmentOffset: testbench.Uint16(secondFragmentOffset),
			MoreFragments:  testbench.Bool(false),
			Identification: testbench.Uint32(fragmentID),
		},
		&testbench.Payload{
			Bytes: icmpv6Bytes[header.ICMPv6PayloadOffset+firstPayloadLength:],
		},
	)
	secondIPv6 := secondFragment[1:]
	secondIPv6Bytes, err := secondIPv6.ToBytes()
	if err != nil {
		t.Fatalf("can't convert second %s to bytes: %s", secondIPv6, err)
	}

	return []testbench.Layers{firstFragment, secondFragment}, [][]byte{firstIPv6Bytes, secondIPv6Bytes}
}

func TestIPv6FragmentReassemblyTimeout(t *testing.T) {
	type errorDetail struct {
		typ                header.ICMPv6Type
		code               header.ICMPv6Code
		typeSpecificIsUsed bool
		typeSpecific       uint32
		payloadFragment    int // 1: first fragment, 2: second fragnemt.
	}

	tests := []struct {
		name                 string
		firstPayloadLength   uint16
		payload              []byte
		secondFragmentOffset uint16
		sendFrameOrder       []int
		expectReply          bool
		expectErrorDetail    errorDetail
	}{
		{
			name:                 "reassembly timeout (first fragment only)",
			firstPayloadLength:   8,
			payload:              []byte(data)[:20],
			secondFragmentOffset: (header.ICMPv6EchoMinimumSize + 8) / 8,
			sendFrameOrder:       []int{1},
			expectReply:          true,
			expectErrorDetail: errorDetail{
				typ:             header.ICMPv6TimeExceeded,
				code:            header.ICMPv6ReassemblyTimeout,
				payloadFragment: 1,
			},
		},
		{
			name:                 "reassembly timeout (second fragment only)",
			firstPayloadLength:   8,
			payload:              []byte(data)[:20],
			secondFragmentOffset: (header.ICMPv6EchoMinimumSize + 8) / 8,
			sendFrameOrder:       []int{2},
			expectReply:          false,
			expectErrorDetail: errorDetail{
				typ:             header.ICMPv6TimeExceeded,
				code:            header.ICMPv6ReassemblyTimeout,
				payloadFragment: 1,
			},
		},
		{
			name:                 "reassembly timeout (two fragments with a gap)",
			firstPayloadLength:   8,
			payload:              []byte(data)[:20],
			secondFragmentOffset: (header.ICMPv6EchoMinimumSize + 16) / 8,
			sendFrameOrder:       []int{1, 2},
			expectReply:          true,
			expectErrorDetail: errorDetail{
				typ:             header.ICMPv6TimeExceeded,
				code:            header.ICMPv6ReassemblyTimeout,
				payloadFragment: 1,
			},
		},
		{
			name:                 "reassembly timeout (two fragments with a gap in reverse order)",
			firstPayloadLength:   8,
			payload:              []byte(data)[:20],
			secondFragmentOffset: (header.ICMPv6EchoMinimumSize + 16) / 8,
			sendFrameOrder:       []int{2, 1},
			expectReply:          true,
			expectErrorDetail: errorDetail{
				typ:             header.ICMPv6TimeExceeded,
				code:            header.ICMPv6ReassemblyTimeout,
				payloadFragment: 1,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dut := testbench.NewDUT(t)
			defer dut.TearDown()
			ipv6Conn := testbench.NewIPv6Conn(t, testbench.IPv6{}, testbench.IPv6{})
			conn := (*testbench.Connection)(&ipv6Conn)
			defer ipv6Conn.Close(t)

			fragments, ipv6Bytes := createFragmentedICMPEchoRequest(t, conn, test.firstPayloadLength, test.payload, test.secondFragmentOffset)

			for _, i := range test.sendFrameOrder {
				conn.SendFrame(t, fragments[i-1])
			}

			gotErrorMessage, err := ipv6Conn.ExpectFrame(t, testbench.Layers{
				&testbench.Ether{},
				&testbench.IPv6{},
				&testbench.ICMPv6{
					Type: testbench.ICMPv6Type(test.expectErrorDetail.typ),
					Code: testbench.ICMPv6Code(test.expectErrorDetail.code),
				},
			}, reassemblyTimeout)
			if !test.expectReply {
				if err == nil {
					t.Fatalf("unexpected an ICMPv6 Error Message")
				}
				return
			}
			if err != nil {
				t.Fatalf("expected an ICMPv6 Error Message, but got none: %s", err)
			}
			gotPayload, err := gotErrorMessage[len(gotErrorMessage)-1].ToBytes()
			if err != nil {
				t.Fatalf("failed to convert ICMPv6 to bytes: %s", err)
			}
			if test.expectErrorDetail.typeSpecificIsUsed {
				gotTypeSpecific := header.ICMPv6(gotPayload).TypeSpecific()
				wantTypeSpecific := test.expectErrorDetail.typeSpecific
				if gotTypeSpecific != wantTypeSpecific {
					t.Fatalf("received unexpected type specific value, got: %s, want: %s", gotTypeSpecific, wantTypeSpecific)
				}
			}
			icmpPayload := gotPayload[header.ICMPv6ErrorHeaderSize:]
			wantPayload := ipv6Bytes[test.expectErrorDetail.payloadFragment-1]
			if !bytes.Equal(icmpPayload, wantPayload) {
				t.Fatalf("received unexpected payload, got: %s, want: %s",
					hex.Dump(icmpPayload),
					hex.Dump(wantPayload))
			}
		})
	}
}
