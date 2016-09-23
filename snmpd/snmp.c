/**
  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.

 *******************************************************************************
 * @license This project is delivered under Apache 2.0 license.
 * @file snmp.c
 * @brief Main functions of SNMP port
 * @author Ânderson Ignácio da Silva
 * @date 12 Sept 2016
 * @see http://www.aignacio.com
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "snmp.h"
#include "mibii.h"
#include "net/rpl/rpl.h"
#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "simple-udp.h"
#include "list.h"
#include "sys/ctimer.h"
#include "sys/etimer.h"
#include "net/ip/uip-debug.h"
#if CONTIKI_TARGET_SRF06_CC26XX
#include "core/net/ipv6/uip-ds6-route.h"
#include "core/net/ipv6/sicslowpan.h"
#include "lib/newlib/syscalls.c" // Used on heap function, like malloc, free, calloc..
#endif

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[uip_l2_l3_hdr_len])

#if CONTIKI_TARGET_SRF06_CC26XX
static struct etimer              update_snmp;
#endif
static struct uip_udp_conn        *server_conn;
uint16_t test = 0;

PROCESS(snmp_main, "[SNMP] SNMPD - Agent V1");

void snmp_cb_data(void){
  static uint16_t len;
  static char buf[MAX_UDP_SNMP];
  memset(buf, 0, MAX_UDP_SNMP);

  if(uip_newdata()) {
    len = uip_datalen();
    memcpy(buf, uip_appdata, len);
    debug_snmp("%u bytes from [", len);
    uip_debug_ipaddr_print(&UIP_IP_BUF->srcipaddr);
    printf("]:%u", UIP_HTONS(UIP_UDP_BUF->srcport));
    uip_ipaddr_copy(&server_conn->ripaddr, &UIP_IP_BUF->srcipaddr);
    server_conn->rport = UIP_UDP_BUF->srcport;
    snmp_t snmp_handle;
    if (snmp_decode_message(buf, &snmp_handle)){
      debug_snmp("New SNMP Request received!");
      len = snmp_encode_message(&snmp_handle, buf);
      uip_udp_packet_send(server_conn, buf, len);
      uip_create_unspecified(&server_conn->ripaddr);
      server_conn->rport = 0;
    }
    else
      debug_snmp("Problem on SNMP Request received!");
  }
}

void snmp_init(void){
  process_start(&snmp_main, NULL);
}

int ipaddr_sprintf(char *buf, uint8_t buf_len, const uip_ipaddr_t *addr) {
  uint16_t a;
  uint8_t len = 0;
  int i, f;
  for(i = 0, f = 0; i < sizeof(uip_ipaddr_t); i += 2) {
    a = (addr->u8[i] << 8) + addr->u8[i + 1];
    if(a == 0 && f >= 0) {
      if(f++ == 0) {
        len += snprintf(&buf[len], buf_len - len, "::");
      }
    } else {
      if(f > 0) {
        f = -1;
      } else if(i > 0) {
        len += snprintf(&buf[len], buf_len - len, ":");
      }
      len += snprintf(&buf[len], buf_len - len, "%x", a);
    }
  }

  return len;
}

void update_snmp_mib(void){
  test++;

  uint8_t oid_tree;
  char dado[MAX_STRINGS_LENGTH];

  /******************************* Hearbeat ***********************************/
  oid_tree = 11;
  sprintf(dado,"heartbeat_%d",test);
  debug_os("Dado de update: %s",dado);
  mib_ii_update_list(oid_tree,dado);

  /******************************** RSSI **************************************/
  oid_tree = 12;
  int  def_rt_rssi = sicslowpan_get_last_rssi();
  sprintf(dado,"RSSI:%d",def_rt_rssi);
  mib_ii_update_list(oid_tree,dado);

  /*************************** Prefered IPv6 **********************************/
  char def_rt_str[64];
  oid_tree = 13;
  memset(def_rt_str, 0, sizeof(def_rt_str));
  ipaddr_sprintf(def_rt_str, sizeof(def_rt_str), uip_ds6_defrt_choose());
  sprintf(dado,"Pref. route:%s",def_rt_str);
  mib_ii_update_list(oid_tree,dado);

}

PROCESS_THREAD(snmp_main, ev, data){
  PROCESS_BEGIN();

  server_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  udp_bind(server_conn, UIP_HTONS(DEFAULT_SNMP_PORT));
  debug_snmp("Listen port: %d, TTL=%u",DEFAULT_SNMP_PORT,server_conn->ttl);
  debug_snmp("Agent SNMPv1 active");

  #if CONTIKI_TARGET_SRF06_CC26XX
  etimer_set(&update_snmp, TIME_UPDATE_SNMP);
  #endif

  while(1){
    PROCESS_YIELD();
    if(ev == tcpip_event)
      snmp_cb_data();
    #if CONTIKI_TARGET_SRF06_CC26XX
    if (etimer_expired(&update_snmp)){
      etimer_reset(&update_snmp);
      update_snmp_mib();
    }
    #endif
  }
  PROCESS_END();
}
