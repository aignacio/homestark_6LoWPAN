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
 * @license This project is delivered under APACHE 2.0.
 * @file main_core.c
 * @author Ânderson Ignácio da Silva
 * @date 19 Ago 2016
 * @brief Main file for HomeStark devices - 6LoWPAN
 * @see http://www.aignacio.com
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "rest-engine.h"
#include "coap-server.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ip/uip.h"
#include "net/rpl/rpl.h"
#include "snmp.h"
#include "mibii.h"

static char     device_id[17];
// static struct etimer   test_contiki;

/*---------------------------------------------------------------------------*/
PROCESS(init_system_process, "[Contiki-OS] Starting the OS");
AUTOSTART_PROCESSES(&init_system_process);
/*---------------------------------------------------------------------------*/

PROCESS_THREAD(init_system_process, ev, data)
{
  PROCESS_BEGIN();

  sprintf(device_id,"%02X%02X%02X%02X%02X%02X%02X%02X",
          linkaddr_node_addr.u8[0],linkaddr_node_addr.u8[1],
          linkaddr_node_addr.u8[2],linkaddr_node_addr.u8[3],
          linkaddr_node_addr.u8[4],linkaddr_node_addr.u8[5],
          linkaddr_node_addr.u8[6],linkaddr_node_addr.u8[7]);


  //#if RESOLV_CONF_SUPPORTS_MDNS
  // resolv_set_hostname("anderson");
  //#endif

  snmp_init(); // Init SNMP Agent
  process_start(&coap_server_process, NULL); // Init CoAP Server Restfull

  // Init the MIB II Structure to fill another time
  #if CONTIKI_TARGET_SRF06_CC26XX
    size_t i = 0;
    uint8_t tree[2];
    const char demo[] = "cc2650_snmp\0";
    char device_address[30];

    sprintf(device_address,"Device:%s",device_id);
    tree[0] = 4;
    tree[1] = 1;
    mib_ii_fill_list(tree, device_address);

    for (i=2; i < MAX_OIDS; i++) {
      tree[0] = 4;
      tree[1] = i;
      mib_ii_fill_list(tree, demo);
    }
    // mib_ii_show();
  #endif

  debug_os(" ");

  // etimer_set(&test_contiki, 2*CLOCK_SECOND);

  while(1) {
      PROCESS_WAIT_EVENT();
      // if (etimer_expired(&test_contiki)){
      //   etimer_reset(&test_contiki);
      //   // rpl_print_neighbor_list();
      // }
  }
  PROCESS_END();
}
