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
 * @file snmp.h
 * @brief Header data about SNMP implementation
 * @author Ânderson Ignácio da Silva
 * @date 12 Sept 2016
 * @see http://www.aignacio.com
 */

#ifndef __SNMP_H__
#define __SNMP_H__

#include "simple-udp.h"
#include "clock.h"
#include "etimer.h"
#include "ctimer.h"
#include "list.h"
#include "net/ip/uip-debug.h"
#include "sys/ctimer.h"
#include <stdbool.h>

#define DEBUG_SNMP

#ifdef DEBUG_SNMP
#define debug_snmp(fmt, args...) printf("\n[SNMP] "fmt, ##args)
#else
#define debug_snmp(fmt, ...)
#endif

/** @struct snmp_con_t
 *  @brief Struct of SNMP Connection
 *  @var snmp_con_t::udp_port
 *    Port of UDP NMS Connection
 *  @var snmp_con_t::udp_con
 *    Handle of UDP connection
 *  @var snmp_con_t::ipv6_nms
 *    Address IPV6 of NMS
 *  @var snmp_con_t::keep_alive
 *    Time of resend messages
 */
typedef struct {
  struct simple_udp_connection udp_con;
  uint16_t udp_port;
  uint16_t *ipv6_nms;
  uint16_t keep_alive;
} snmp_con_t;

/** @typedef resp_con_t
 *  @brief Tipo de erros de funções
 *  @var SUCCESS_CON::FAIL_CON
 *    Erro ao processar algo
 *  @var SUCCESS_CON::SUCCESS_CON
 *    Sucesso ao processar algo
 *  @todo Implementar mais tipos de erros
 */
typedef enum resp_con{
   FAIL_CON,
   SUCCESS_CON,
} resp_con_t;

/** @struct ping_req_t
 *  @brief Estrutura de pacote de desconexão do broker MQTT-SN
 *  @var ping_req_t::length
 *    Comprimento do pacote
 *  @var ping_req_t::msg_type
 *    Tipo de mensagem
 *  @var ping_req_t::message
 *    Message of ID
 */
typedef struct __attribute__((packed)){
  uint8_t length;
  uint8_t  msg_type;
  char message[50];
} ping_req_t;

/** @struct snmp_t
 *  @brief Struct for the SNMP PDU
 *  @var snmp_t:request_type
 *    Type of the request
 *  @var snmp_t:response_type
 *    Type of the request response
 *  @var snmp_t:request_id
 *    ID to identify the transaction
 *  @var snmp_t:error_status
 *    Error of status request
 *  @var snmp_t:error_index
 *    Error of index of request
 *  @var snmp_t:var_name
 *    Name of var of request
 *  @var snmp_t:var_value
 *    Value of var of request
 *  @TODO Expand the number of variables in the request
 */
typedef struct {
    uint8_t         request_type;
    uint8_t         response_type;
    uint32_t        request_id;
    uint8_t         error_status;
    uint8_t         error_index;
    uint16_t        var_name;
    uint16_t        var_value;
} snmp_t;

/** @struct request
 *  @brief Struct for request of SNMP Packets
 *  @var snmp_t::pdu_request
 *    Request to be processed
 *  @var request::link
 *    Link to the next request
 */
struct request {
    snmp_t pdu_request;
    struct request *link;
}*request_first, *request_last;

/** @brief SNMP Callback receive
 *
 * 		Receive in callback mode, any data from NSM of SNMP protocol.
 *
 *  @param [in] various Various arguments from callback of UDP connection
 *
 *  @retval void Doesn't return anything
 **/
void snmp_cb_data(struct simple_udp_connection *c,
                  const uip_ipaddr_t *sender_addr,
                  uint16_t sender_port,
                  const uip_ipaddr_t *receiver_addr,
                  uint16_t receiver_port,
                  const uint8_t *data,
                  uint16_t datalen);

/** @brief SNMP Init function
 *
 * 		Init SNMP connection with NMS
 *
 *  @param [in] snmp_struct Struct of SNMP connection with the NMS
 *
 *  @retval SUCCESS_CON Connection with the NMS is done with sucessful
 *  @retval FAIL_CON    Connection with the NMS is failed
 **/
resp_con_t snmp_init(snmp_con_t snmp_struct);

// resp_con_t send_ping(void);
#endif
