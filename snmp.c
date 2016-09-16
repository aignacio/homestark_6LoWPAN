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

 #include "contiki.h"
 #include "net/ip/uip.h"
 #include "net/ipv6/uip-ds6.h"
 #include "simple-udp.h"
 #include <stdio.h>
 #include <string.h>
 #include <snmp.h>
 #include "sys/timer.h"
 #include "list.h"
 #include "sys/ctimer.h"
 #include "sys/etimer.h"
 #include "stdint.h"
 #include <stdlib.h>
 #include <stdbool.h>
 #include "net/ipv6/uip-ds6.h"
 #include "net/rpl/rpl.h"
 #include "ber.h"

 #if CONTIKI_TARGET_SRF06_CC26XX
 #include "lib/newlib/syscalls.c" //Utilizado quando se usa malloc
 #endif

static snmp_con_t nms_con;
static process_event_t            request_event;          // Evento de processo de requisições SNMP

PROCESS(snmp_main, "[SNMP] SNMPD - Agente V1");

void snmp_cb_data(struct simple_udp_connection *c,
                  const uip_ipaddr_t *sender_addr,
                  uint16_t sender_port,
                  const uip_ipaddr_t *receiver_addr,
                  uint16_t receiver_port,
                  const uint8_t *data,
                  uint16_t datalen){
  debug_snmp("Recebida requisicao:");

  process_post(&snmp_main,request_event,NULL);

  // debug_snmp("%s",data);
  // if (*data == 'G')
  // send_ping();
}

resp_con_t snmp_init(snmp_con_t snmp_struct){
  static uip_ipaddr_t nms_addr;

  nms_con = snmp_struct;
  uip_ip6addr(&nms_addr, *nms_con.ipv6_nms,
                          *(nms_con.ipv6_nms+1),
                          *(nms_con.ipv6_nms+2),
                          *(nms_con.ipv6_nms+3),
                          *(nms_con.ipv6_nms+4),
                          *(nms_con.ipv6_nms+5),
                          *(nms_con.ipv6_nms+6),
                          *(nms_con.ipv6_nms+7));

  if (nms_con.keep_alive >= 200){
    debug_snmp("Erro, execido tempo maximo de keep alive");
    return FAIL_CON;
  }

  debug_snmp("Endereco broker: ");
  uip_debug_ipaddr_print(&nms_addr);
  debug_snmp("Endereco da porta: %d ",nms_con.udp_port);

  if(!simple_udp_register(&nms_con.udp_con,
                          nms_con.udp_port,
                          &nms_addr,
                          nms_con.udp_port,
                          snmp_cb_data))
    return FAIL_CON;
  else{
    request_event = process_alloc_event();
    process_start(&snmp_main, NULL);
    return SUCCESS_CON;
  }
}

// resp_con_t send_ping(void){
//     debug_snmp("Enviando pacote de @PING");
//     ping_req_t packet;
//
//     // uip_ipaddr_t *node_address;
//     // node_address = rpl_get_parent_ipaddr(dag->preferred_parent);
//     rpl_dag_t *dag;
//     dag = rpl_get_any_dag();
//     rpl_parent_t *p = nbr_table_head(rpl_parents);
//     rpl_instance_t *default_instance;
//     default_instance = rpl_get_default_instance();
//     while(p != NULL)
//       if (p == default_instance->current_dag->preferred_parent) {
//         sprintf(packet.message,"No:[%3u]",rpl_get_parent_ipaddr(p)->u8[15]);
//         debug_snmp("Endereco do NO:%3u",rpl_get_parent_ipaddr(p)->u8[15]);
//         break;
//       }
//       else
//         p = nbr_table_next(rpl_parents, p);
//
//     debug_snmp("RETORNO PARENTE:%d\n",rpl_parent_is_fresh(dag->preferred_parent));
//     rpl_print_neighbor_list();
//     packet.length = strlen(packet.message);
//     simple_udp_send(&nms_con.udp_con,&packet.message, packet.length);
//     return SUCCESS_CON;
// }

PROCESS_THREAD(snmp_main, ev, data){
  PROCESS_BEGIN();

  debug_snmp("Agente SNMPv1 ativo");

  while(1){
    PROCESS_WAIT_EVENT();
    /*************************** CONNECT MQTT-SN ****************************/
    if (ev == request_event){
      debug_snmp("Requisicao a ser processada!");
    }
  }
  PROCESS_END();
}
