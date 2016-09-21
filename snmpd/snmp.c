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
#include "net/rpl/rpl.h"
#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "simple-udp.h"
#include "list.h"
#include "sys/ctimer.h"
#include "sys/etimer.h"
#include "net/ip/uip-debug.h"
#if CONTIKI_TARGET_SRF06_CC26XX
#include "lib/newlib/syscalls.c" // Used on heap function, like malloc, free, calloc..
#endif

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[uip_l2_l3_hdr_len])

static struct uip_udp_conn        *server_conn;

PROCESS(snmp_main, "[SNMP] SNMPD - Agent V1");

void snmp_cb_data(void){
  debug_snmp("New SNMP Request: ");

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
    snmp_decode_message(buf, &snmp_handle);
    len = snmp_encode_message(&snmp_handle, buf);
    uip_udp_packet_send(server_conn, buf, len);
    uip_create_unspecified(&server_conn->ripaddr);
    server_conn->rport = 0;
  }
}

void snmp_init(void){
  process_start(&snmp_main, NULL);
}

PROCESS_THREAD(snmp_main, ev, data){
  PROCESS_BEGIN();

  server_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  udp_bind(server_conn, UIP_HTONS(DEFAULT_SNMP_PORT));
  debug_snmp("Listen port: %d, TTL=%u",DEFAULT_SNMP_PORT,server_conn->ttl);
  debug_snmp("Agent SNMPv1 active");

  while(1){
    PROCESS_YIELD();
    if(ev == tcpip_event)
      snmp_cb_data();
  }
  PROCESS_END();
}
