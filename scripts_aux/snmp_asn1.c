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
 * @license This project is under APACHE 2.0 license.
 * @file snmp_asn1.c
 * @brief Encoding and decoding functions to SNMP agent
 * @author Ânderson Ignácio da Silva
 * @date 19 Sept 2016
 * @see http://www.aignacio.com
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "snmp_asn1.h"
#include "mibii.h"

int pow(int base, int exp){
  if(exp < 0)
    return -1;

    int result = 1;
    while (exp)
    {
        if (exp & 1)
            result *= base;
        exp >>= 1;
        base *= base;
    }

    return result;
}

resp_con_t encode_asn1_oct_str(unsigned char *data_to_encode, uint8_t *encoded_str){
  size_t i = 0;

  // printf("\n");
  for (i = 0; i < MAX_OCTET_STRING; i++){
    // printf(" %c ",*(data_to_encode+i));
    if (*(data_to_encode+i) == 0xff || *(data_to_encode+i) == '\0')
      break;
  }

  if (i >= MAX_OCTET_STRING) {
    debug_snmp("There's not an 0xFF end on string to be encoded!");
    return FAIL_CON;
  }

  uint8_t length = i,
          index = 0;

  *encoded_str     = ASN1_PRIM_OCT_STR;
  *(encoded_str+1) = length;

  while (length) {
    *(encoded_str+2+index) = *(data_to_encode+index);
    length--;
    index++;
    // printf("\n%x / len=%d",*(encoded_str+2+index),length);
  }
  return SUCCESS_CON;
}

resp_con_t decode_asn1_oct_str(unsigned char *data_encoded[], uint8_t *oct_str){
  if (*data_encoded != ASN1_PRIM_OCT_STR) {
    debug_snmp("The type of value passed is not an octet string!");
    return FAIL_CON;
  }

  uint8_t length = *(data_encoded+1),
          index = 0;
  while (length) {
    *(oct_str+index) = *(data_encoded+2+index);
    length--;
    index++;
  }

  *(oct_str+index) = '\0';
  // printf("\nEndereco----:> %d\n",oct_str);
  return SUCCESS_CON;
}

resp_con_t encode_asn1_oid(uint8_t *data_to_encode, uint8_t *oid_encoded){
  size_t i = 0;
  if (*data_to_encode != 0x01 || *(data_to_encode+1) != 0x03){ // Acoording to SID1*40+SID2 = 1*40+3 = 43 = 0x2b then always start with 1.3.... iso
    debug_snmp("The Start of OID does not begin with 1.3 or 0x2b like iso.!:[%x][%x]",*data_to_encode,*(data_to_encode+1));
    return FAIL_CON;
  }
  // [ASN1_PRIM_OID] [LEN] [OID-1]....
  *oid_encoded = ASN1_PRIM_OID;
  *(oid_encoded+2) = *(data_to_encode)*40+*(data_to_encode+1);

  for (i = 0; i < MAX_OID_STRING; i++)
    if (*(data_to_encode+i) == 0xff)
      break;

  if (i >= MAX_OID_STRING) {
    debug_snmp("There's not an 0xFF end on oid to be encoded!");
    return FAIL_CON;
  }

  uint8_t index = 0;
  while (*(data_to_encode+index) != 0xFF) {
    *(oid_encoded+3+index) = *(data_to_encode+index+2);
    index ++;
  }
  // Length
  *(oid_encoded+1) = index-1;
  return SUCCESS_CON;
}

resp_con_t decode_asn1_oid(unsigned char *oid_encoded[], uint8_t *oid_data){
  uint8_t length = *(oid_encoded+1);
  uint8_t *oid_value;
  size_t i;

  if (*oid_encoded != ASN1_PRIM_OID){
    debug_snmp("The value is not OID type!");
    return FAIL_CON;
  }

  if (*(oid_encoded+2) != 0x2b){ // Acoording to SID1*40+SID2 = 1*40+3 = 43 = 0x2b then always start with 1.3.... iso
    debug_snmp("The Start of OID does not begin with 1.3 or 0x2b like iso.!");
    return FAIL_CON;
  }
  // 1.3...
  *oid_data = 0x01;
  *(oid_data+1) = 0x03;
  for (i = 0; i < length; i++) {
    *(oid_data+i+2) = *(oid_encoded+3+i);
  }
  *(oid_data+i+1) =  0xFF;


  return SUCCESS_CON;
}

resp_con_t encode_asn1_integer(uint32_t *integer_data, uint8_t *encoded_value){
  size_t i;
  uint8_t aux_encoding[100];
  uint8_t index = 2; // First and second, type and length, we start frame from three
  uint32_t data_for_enc = *integer_data;

  // First number to alloc is the type - BER encoding
  *encoded_value = ASN1_PRIM_INTEGER;
  while (data_for_enc != 0){
    aux_encoding[index] = data_for_enc % 256;
    data_for_enc = data_for_enc / 256;
    index++;
  }
  if (index == 2){
    *(encoded_value+1) = 0x01;
    *(encoded_value+2) = 0x00;
  }
  else{
    *(encoded_value+1) = index-2;
    for (i = 0; i < *(encoded_value+1); i++)
      *(encoded_value+2+i) = aux_encoding[index-1-i];
  }

  // Then we need to put the length in the char*
  return SUCCESS_CON;
}

resp_con_t decode_asn1_integer(unsigned char *data_encoded[], uint32_t *integer_value){
  uint8_t length = *(data_encoded+1);
  // uint32_t integer_value;
  size_t i = 0;
  uint32_t aux;

  // Test if it's an integer value to be decoded
  if (*data_encoded != ASN1_PRIM_INTEGER){
    debug_snmp("The value is not integer!");
    return FAIL_CON;
  }

  for (i=1, *integer_value = 0; i <= length; i++){
    aux = *(data_encoded+1+i);
    *integer_value += aux*(pow(256,(length-i)));
    // debug_snmp("%x * 256^%d = %d",aux,(length-i),integer_value);
  }
  return SUCCESS_CON;
}

resp_con_t error_check_snmp(unsigned char *error_data[]){
    uint32_t error_status;

    decode_asn1_integer(error_data,&error_status);
    if (error_status != ERROR_NONE) {
      debug_snmp("There's some error STATUS in packet");
      return FAIL_CON;
    }
    decode_asn1_integer(error_data+3,&error_status);
    if (error_status != ERROR_NONE) {
      debug_snmp("There's some error INDEX in packet");
      return FAIL_CON;
    }
    return SUCCESS_CON;
}

resp_con_t snmp_decode_message(unsigned char *data[], snmp_t *snmp_handle){
  size_t i = 0;
  // First let's check the sequence first byte
  if (!check_seq(*data)){
    debug_snmp("Sequence initial of SNMP message error");
    return FAIL_CON;
  }
  // Check the SNMP version
  uint32_t SNMPv = 0;
  if (!decode_asn1_integer((data+2),&SNMPv)) return FAIL_CON;
  if (SNMPv != SNMP_VERSION_1) {
    debug_snmp("SNMP version is different from v1:%d",SNMPv);
    return FAIL_CON;
  }

  snmp_handle->snmp_version = SNMPv;
  // Get the community string
  uint8_t community_string[MAX_OCTET_STRING];
  if (!decode_asn1_oct_str((data+5),&community_string)) return FAIL_CON;
  #ifdef DEBUG_SNMP_DECODING
  debug_snmp("Community String: %s",community_string);
  #endif
  for (i=0; i < MAX_OCTET_STRING; i++)
    snmp_handle->community[i] = community_string[i];


  // Get the PDU type
  uint8_t com_string_len = *(data+6)+7;
  uint8_t pdu_type = *(data+com_string_len);

  // Get request ID
  uint32_t req_id;
  if (!decode_asn1_integer((data+com_string_len+2),&req_id)) return FAIL_CON;
  #ifdef DEBUG_SNMP_DECODING
  debug_snmp("Request ID: %d",req_id);
  #endif

  // Check for errors in SNMP Message
  uint8_t req_id_len = com_string_len+*(data+com_string_len+3)+4;
  if (!error_check_snmp(data+req_id_len)) return FAIL_CON;

  uint16_t oid_start = req_id_len+10;
  uint8_t oid_encoded[MAX_OID_STRING];
  uint8_t oid_len = *(data+oid_start+1);
  uint16_t oct_start = oid_start+oid_len+2;
  uint8_t oct_encoded[MAX_OCTET_STRING];

  switch (pdu_type) {
    case ASN1_CPX_SEQUENCE:
    break;
    case ASN1_CPX_GET_REQ:
      if (!decode_asn1_oid(data+oid_start,&oid_encoded)) return FAIL_CON;
      #ifdef DEBUG_SNMP_DECODING
      debug_snmp("GET Request PDU Type");
      debug_snmp("OID: ");
      for (i=0; oid_encoded[i] != 0xFF; i++)
        printf("%x.",oid_encoded[i]);
      #endif
      snmp_handle->request_type = ASN1_CPX_GET_REQ;
      snmp_handle->response_type = ASN1_CPX_GET_RESP;
      snmp_handle->request_id = req_id;
      for (i=0; i < MAX_OID_STRING; i++)
        snmp_handle->oid_encoded[i] = oid_encoded[i];
    break;
    case ASN1_CPX_NEXT_REQ:
      if (!decode_asn1_oid(data+oid_start,&oid_encoded)) return FAIL_CON;
      #ifdef DEBUG_SNMP_DECODING
      debug_snmp("GET NEXT Request PDU Type");
      debug_snmp("OID: ");
      for (i=0; oid_encoded[i] != 0xFF; i++)
        printf("%x.",oid_encoded[i]);
      #endif
      snmp_handle->request_type = ASN1_CPX_NEXT_REQ;
      snmp_handle->response_type = ASN1_CPX_GET_RESP;
      snmp_handle->request_id = req_id;
      for (i=0;  i < MAX_OID_STRING; i++)
        snmp_handle->oid_encoded[i] = oid_encoded[i];
    break;
    case ASN1_CPX_GET_RESP:
      if (!decode_asn1_oct_str((data+oct_start),&oct_encoded)) return FAIL_CON;
      if (!decode_asn1_oid(data+oid_start,&oid_encoded)) return FAIL_CON;
      #ifdef DEBUG_SNMP_DECODING
      debug_snmp("GET RESP Request PDU Type");
      debug_snmp("OID: ");
      for (i=0; oid_encoded[i] != 0xFF; i++)
        printf("%x.",oid_encoded[i]);
      debug_snmp("Valor da String: %s",oct_encoded);
      #endif
      snmp_handle->request_type = ASN1_CPX_GET_RESP;
      snmp_handle->response_type = ASN1_CPX_GET_RESP;
      snmp_handle->request_id = req_id;
      for (i=0; i < MAX_OID_STRING; i++)
        snmp_handle->oid_encoded[i] = oid_encoded[i];
    break;
    case ASN1_CPX_SET_REQ:
    break;
    default:
      #ifdef DEBUG_SNMP_DECODING
      debug_snmp("The PDU type is not know");
      #endif
      return FAIL_CON;
    break;
  }

  return SUCCESS_CON;
}

uint8_t *snmp_encode_message(snmp_t *snmp_handle){
  size_t i;
  uint8_t udp_pkt[MAX_UDP_SNMP],
          aux_1 = 0,
          aux_2 = 0,
          aux_3 = 0;
  uint16_t len = 0;

  uint8_t string_value[MAX_OCTET_STRING];
  uint8_t status_mib2 = mib_ii_get_oid(&snmp_handle->oid_encoded,&string_value);

  udp_pkt[0] = ASN1_CPX_SEQUENCE;

  // SNMP Version
  if (!encode_asn1_integer(&snmp_handle->snmp_version,&udp_pkt[2])) return FAIL_CON;
  len = 5;
  // Community string
  if (!encode_asn1_oct_str(&snmp_handle->community,&udp_pkt[len])) return FAIL_CON;
  len = len+udp_pkt[len+1]+2;
  // PDU Type
  udp_pkt[len++] = ASN1_CPX_GET_RESP;
  uint8_t len_pdu_type = len++;
  udp_pkt[len_pdu_type] = 0x00;

  uint8_t encoded_req[MAX_OID_STRING];
  // Request ID
  if (!encode_asn1_integer(&snmp_handle->request_id,&encoded_req)) return FAIL_CON;
  aux_2 = *(encoded_req+1)+2;
  aux_3 = len;
  for (i = 0; i < *(encoded_req+1)+2; i++)
    udp_pkt[len++] = *(encoded_req+i);

  if (status_mib2) {
    // Error status
    if (!encode_asn1_integer(&snmp_handle->snmp_version,&udp_pkt[len])) return FAIL_CON;
    len = len+udp_pkt[len+1]+2;

    // Error index
    if (!encode_asn1_integer(&snmp_handle->snmp_version,&udp_pkt[len])) return FAIL_CON;
    len = len+udp_pkt[len+1]+2;
  }
  else{
    // If we dont find MIB2 value, generate errors
    udp_pkt[len++] = ASN1_PRIM_INTEGER;
    udp_pkt[len++] = 0x01;
    udp_pkt[len++] = ERROR_REQ_OID_NOT_FOUND;

    udp_pkt[len++] = ASN1_PRIM_INTEGER;
    udp_pkt[len++] = 0x01;
    udp_pkt[len++] = ERROR_RESP_TOO_LARGE;
  }

  // Var bind list
  udp_pkt[len++] = ASN1_CPX_SEQUENCE;
  uint8_t len_seq_1 = len++;
  udp_pkt[len_seq_1] = 0x00;
  // Var bind type
  udp_pkt[len++] = ASN1_CPX_SEQUENCE;
  uint8_t len_seq_2 = len++;
  udp_pkt[len_seq_2] = 0x00;

  // OID String
  if (!encode_asn1_oid(&snmp_handle->oid_encoded,&encoded_req)) return FAIL_CON;
  aux_1 = *(encoded_req+1) + 2;

  for (i = 0; i < *(encoded_req+1)+2; i++)
    udp_pkt[len++] = *(encoded_req+i);

  uint8_t error_string = 0x05;
  // String of octet
  if (status_mib2) {
    if (!encode_asn1_oct_str(&string_value,&encoded_req)) return FAIL_CON;
    aux_1 = aux_1 + *(encoded_req+1) + 2;
    for (i = 0; i < *(encoded_req+1)+2; i++)
      udp_pkt[len++] = *(encoded_req+i);
  }
  else{
    udp_pkt[len++] = 0x05;
    udp_pkt[len++] = 0x00;
  }

  udp_pkt[len_seq_2]    = aux_1;
  udp_pkt[len_seq_1]    = aux_1+2;
  udp_pkt[len_pdu_type] = len-aux_3;

  udp_pkt[1] = len-2;
  #ifdef DEBUG_SNMP_DECODING
  debug_snmp(" Pacote codificado:\n\t");
  size_t j = 0;
  for (i = 0; i < udp_pkt[1]+2; j++, i++){
    if (j > 7){
      j = 0;
      printf("\n\t");
    }
    printf("[%02x] ",*(udp_pkt+i));
  }
  #endif
  return SUCCESS_CON;
}

void test_ber_func(void){
  snmp_t test,test2,test3;

  // Three pointers from wireshark
  unsigned char *pkt_get[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, /* ......E. */
    0x00, 0x47, 0x4e, 0x4b, 0x40, 0x00, 0x40, 0x11, /* .GNK@.@. */
    0xee, 0x58, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, /* .X...... */
    0x00, 0x01, 0x8a, 0xe9, 0x00, 0xa1, 0x00, 0x33, /* .......3 */
    0xfe, 0x46, 0x30, 0x29, 0x02, 0x01, 0x00, 0x04, /* .F0).... */
    0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, /* .public. */
    0x1c, 0x02, 0x04, 0x43, 0xda, 0x25, 0xed, 0x02, /* ...C.%.. */
    0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, /* .....0.0 */
    0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, /* ...+.... */
    0x01, 0x05, 0x00, 0x05, 0x00                    /* ..... */
  };

  unsigned char *pkt_resp[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, /* ......E. */
    0x00, 0x4f, 0x4e, 0x4c, 0x40, 0x00, 0x40, 0x11, /* .ONL@.@. */
    0xee, 0x4f, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, /* .O...... */
    0x00, 0x01, 0x00, 0xa1, 0x8a, 0xe9, 0x00, 0x3b, /* .......; */
    0xfe, 0x4e, 0x30, 0x31, 0x02, 0x01, 0x00, 0x04, /* .N01.... */
    0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa2, /* .public. */
    0x24, 0x02, 0x04, 0x43, 0xda, 0x25, 0xed, 0x02, /* $..C.%.. */
    0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x16, 0x30, /* .....0.0 */
    0x14, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, /* ...+.... */
    0x01, 0x05, 0x00, 0x04, 0x08, 0x61, 0x69, 0x67, /* .....aig */
    0x6e, 0x61, 0x63, 0x69, 0x6f                    /* nacio */
  };

  unsigned char *pkt_get_next[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, /* ......E. */
    0x00, 0x47, 0x48, 0x87, 0x40, 0x00, 0x40, 0x11, /* .GH.@.@. */
    0xf4, 0x1c, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, /* ........ */
    0x00, 0x01, 0xd5, 0x03, 0x00, 0xa1, 0x00, 0x33, /* .......3 */
    0xfe, 0x46, 0x30, 0x29, 0x02, 0x01, 0x00, 0x04, /* .F0).... */
    0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa1, /* .public. */
    0x1c, 0x02, 0x04, 0x31, 0xad, 0x1e, 0x96, 0x02, /* ...1.... */
    0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, /* .....0.0 */
    0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, /* ...+.... */
    0x01, 0x03, 0x00, 0x05, 0x00                    /* ..... */
  };

  unsigned char *pkt[] = {
    0x02, 0x03, 0x7f, 0xff, 0xff, 0xbb
  };

  uint32_t  valor = 0;
  uint32_t decodificado;
  uint8_t  codificado[10];
  size_t i;

  /********* CODE FOR TEST DECODE AND ENCODE INTEGER FUNCTIONS ****************/
  // decode_asn1_integer(pkt,&decodificado);
  // encode_asn1_integer(&decodificado, &codificado);
  // debug_snmp("Decodificado inteiro:%d",decodificado);
  // debug_snmp("Codificado inteiro:");
  // for (i =0; i < codificado[1]+2; i++)
  //   printf("[%x]",codificado[i]);
  // printf("\n");
  /********* CODE FOR TEST DECODE AND ENCODE INTEGER FUNCTIONS ****************/

  /********* CODE FOR TEST DECODE AND ENCODE OID VALUES ***********************/
  // size_t k = 0;
  // uint8_t oid_received[100];
  // if (decode_asn1_oid((pkt_get+73),&oid_received)) {
  //   debug_snmp("OID Decodificado: ");
  //   for (k = 0; oid_received[k] != 0xFF ; k++)
  //   printf("%d.",oid_received[k]);
  // }
  //
  // uint8_t oid_to_encode[] = {0x01,0x03,0x06,0x01,0x02,0x01,0x01,0x05,0x00,0xFF};
  // uint8_t oid_encoded[100];
  //
  // if (encode_asn1_oid(&oid_to_encode,&oid_encoded)){
  //   debug_snmp("OID Codificado: ");
  //   for (k = 0; k <= oid_encoded[1]+1 ; k++)
  //     printf("[%x]",oid_encoded[k]);
  // }
  //
  // printf("\n");
  /********* CODE FOR TEST DECODE AND ENCODE OID VALUES ***********************/

  /********* CODE FOR TEST DECODE AND ENCODE OCT STRINGS **********************/
  // uint8_t string_octet[100];
  // decode_asn1_oct_str((pkt_resp+83),&string_octet);
  // debug_snmp("Octet string decodificada: %s",string_octet);
  //
  // uint8_t z_string[] = "aignacio\0";
  // debug_snmp("Octet string codificada: ");
  // uint8_t string_octet2[100];
  // if (encode_asn1_oct_str(&z_string,&string_octet2)) {
  //   for (i = 0; i < string_octet2[1]+2; i++) {
  //     printf("[%x]",string_octet2[i]);
  //   }
  // }
  // printf("\n");
  /********* CODE FOR TEST DECODE AND ENCODE OCT STRINGS **********************/

  // error_check_snmp(pkt_cmp+63);

  snmp_decode_message(pkt_get_next+42,&test) ? debug_snmp("Decodificacao bem sucedida") : debug_snmp("Erro decodificacao");
  snmp_decode_message(pkt_get+42,&test2) ? debug_snmp("Decodificacao bem sucedida") : debug_snmp("Erro decodificacao");
  snmp_decode_message(pkt_resp+42,&test3) ? debug_snmp("Decodificacao bem sucedida") : debug_snmp("Erro decodificacao");

  snmp_encode_message(&test2) ? debug_snmp("Codificacao bem sucedida") : debug_snmp("Erro codificacao");
  // uint8_t *udp_pkt;
  // debug_snmp("Pacote SNMP codificado: ");
  // for (i = 0; i < *(udp_pkt+1); i++)
  //   printf("[%x] ",*(udp_pkt+i));
  // printf("\n");

  // printf("\nTipo de requisicao:%x \
  //         \nTipo de resposta:%x \
  //         \nNumero da requisicao:%d",
  //         test3.request_type,
  //         test3.response_type,
  //         test3.request_id);
  // printf("\nOID: ");
  // for (i=0; test3.oid_encoded[i] != 0xFF; i++)
  // printf("%x.",test3.oid_encoded[i]);
  // printf("\n");
  //
  // printf("\nTipo de requisicao:%x \
  //         \nTipo de resposta:%x \
  //         \nNumero da requisicao:%d",
  //         test2.request_type,
  //         test2.response_type,
  //         test2.request_id);
  // printf("\nOID: ");
  // for (i=0; test2.oid_encoded[i] != 0xFF; i++)
  // printf("%x.",test2.oid_encoded[i]);
  // printf("\n");
  //
  // printf("\nTipo de requisicao:%x \
  //         \nTipo de resposta:%x \
  //         \nNumero da requisicao:%d",
  //         test.request_type,
  //         test.response_type,
  //         test.request_id);
  // printf("\nOID: ");
  // for (i=0; test.oid_encoded[i] != 0xFF; i++)
  //   printf("%x.",test.oid_encoded[i]);
  // printf("\n");
}

void main(){
  test_ber_func();
}
