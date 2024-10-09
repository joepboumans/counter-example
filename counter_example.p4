/*******************************************************************************
 *  INTEL CONFIDENTIAL
 *
 *  Copyright (c) 2021 Intel Corporation
 *  All Rights Reserved.
 *
 *  This software and the related documents are Intel copyrighted materials,
 *  and your use of them is governed by the express license under which they
 *  were provided to you ("License"). Unless the License provides otherwise,
 *  you may not use, modify, copy, publish, distribute, disclose or transmit
 *  this software or the related documents without Intel's prior written
 *  permission.
 *
 *  This software and the related documents are provided as is, with no express
 *  or implied warranties, other than those that are expressly stated in the
 *  License.
 ******************************************************************************/

#include <core.p4>
#if __TARGET_TOFINO__ == 3
#include <t3na.p4>
#elif __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "common/headers.p4"
#include "common/util.p4"

#define COUNTER_WIDTH 16
#define COUNTER_BIT_WIDTH 4 // 2^COUNTER_BIT_WIDTH = COUNTER_WIDTH

struct metadata_t {
  bit<32> count;
  bit<COUNTER_BIT_WIDTH> idx;
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(packet_in pkt, out header_t hdr, out metadata_t ig_md,
                    out ingress_intrinsic_metadata_t ig_intr_md) {

  TofinoIngressParser() tofino_parser;

  state start {
    tofino_parser.apply(pkt, ig_intr_md);
    transition parse_ethernet;
  }

  state parse_ethernet {
    pkt.extract(hdr.ethernet);
    transition select(hdr.ethernet.ether_type) {
    ETHERTYPE_IPV4:
      parse_ipv4;
    default:
      reject;
    }
  }

  state parse_ipv4 {
    pkt.extract(hdr.ipv4);
    transition select(hdr.ipv4.protocol) {
    IP_PROTOCOLS_UDP:
      parse_udp;
    IP_PROTOCOLS_TCP:
      parse_tcp;
    default:
      accept;
    }
  }

  state parse_tcp {
    pkt.extract(hdr.tcp);
    transition accept;
  }

  state parse_udp {
    pkt.extract(hdr.udp);
    transition accept;
  }
}
// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser( packet_out pkt, inout header_t hdr, in metadata_t ig_md,
    in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
  apply {
    pkt.emit(hdr);
  }
}

control SwitchIngress(inout header_t hdr, inout metadata_t ig_md,
              in ingress_intrinsic_metadata_t ig_intr_md,
              in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
              inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
              inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

  Hash<bit<COUNTER_BIT_WIDTH>>(HashAlgorithm_t.CRC16) hash16;
  Register<bit<32>, bit<COUNTER_BIT_WIDTH>>(COUNTER_WIDTH, 0) counter;

  RegisterAction<bit<32>, bit<COUNTER_BIT_WIDTH>, bit<32>>(counter) inc_counter_write = {
    void apply(inout bit<32> val, out bit<32> out_val) {
      val = val + 1;
      out_val = val;
    }
  };

  action get_hash() {
    ig_md.idx = hash16.get({hdr.ipv4.src_addr, 
                            hdr.ipv4.dst_addr, 
                            hdr.udp.src_port, 
                            hdr.udp.dst_port,
                            hdr.ipv4.protocol});
  }

  action increment_counter() {
    ig_md.count = inc_counter_write.execute(ig_md.idx);
  }

  action hit(PortId_t port) {
    ig_intr_tm_md.ucast_egress_port = port;
    hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    ig_intr_dprsr_md.drop_ctl = 0x0;
  }

  action miss() {
    ig_intr_dprsr_md.drop_ctl = 0x1; // Drop packet
  }
  table forward {
    key = { 
      hdr.ipv4.dst_addr : exact;
  }
  actions = { 
    hit;
    miss;
  }

  const default_action = miss;
  size = 1024;
 }

  apply { 
    get_hash();
    increment_counter();

    forward.apply(); 
    ig_intr_tm_md.bypass_egress = 1w1;
  }
}

Pipeline(SwitchIngressParser(), SwitchIngress(), SwitchIngressDeparser(),
         EmptyEgressParser(), EmptyEgress(), EmptyEgressDeparser()) pipe;

Switch(pipe) main;
