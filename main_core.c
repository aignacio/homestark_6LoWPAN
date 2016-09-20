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
#include "contiki-net.h"
#include "rest-engine.h"
#include "coap-server.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ip/uip.h"
#include "snmp.h"

static char     device_id[17];

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

  snmp_init();
  //process_start(&coap_server_process, NULL);
  debug_os(" ");

  while(1) {
      PROCESS_WAIT_EVENT();
  }
  PROCESS_END();
}
