#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "snmp_ber_asn1.h"

uint16_t decode_asn1_integer(unsigned char *snmp_int[], uint8_t length){
  size_t i;
  uint16_t integer = 0;
  uint8_t first = *snmp_int;
  uint8_t second = *(snmp_int+1);

  if(length > 1)
      integer += (first - 0x80)*0x80+second;
  else
    integer = *snmp_int;
  return integer;
}

void decode_asn1_oct(unsigned char *snmp_oct[], uint8_t length, char *com_string){
  size_t i;
  for (i=0; i < length; i++)
    *(com_string+i) = *(snmp_oct+i);
}

resp_con_t decode_ber_asn1(unsigned char *data[]){
  uint8_t offset = 42;
  uint8_t length_total;
  uint8_t length_com_string;
  uint8_t community_string[MAX_COMMUNITY_STRING];
  uint8_t pdu_type_request;

  // First Sequence of SNMP Message, must be 0x30 type
  debug_snmp("Valor do offset:%d",offset);
  if(!check_seq(*(data+offset))){
    debug_snmp("Erro seq. inicial:%x",*(data+offset));
    return FAIL_CON;
  }

  // Length of SNMP Message in bytes
  length_total = *(data+offset+1);
  debug_snmp("Comprimento do pacote SNMP: %d bytes",length_total);

  // SNMP Version - Until this momment just supports v1.0
  if (*(data+offset+4) == SNMP_VERSION_1)
    debug_snmp("Versao SNMP: %d",decode_asn1_integer((data+offset+4),*(data+offset+3)));
  else{
    debug_snmp("Erro ver. SNMP nao suportada!");
    return FAIL_CON;
  }

  // Community String - Check if we have community string right allocatted
  if (*(data+offset+5) != ASN1_PRIM_OCT_STR) {
    debug_snmp("Erro community string pos:%d",*(data+offset+5));
  }
  length_com_string = *(data+offset+6);
  decode_asn1_oct((data+offset+7),length_com_string,&community_string);
  debug_snmp("Community String:%s",community_string);

  // SNMP PDU, test type and get data
  pdu_type_request = *(data+offset+7+length_com_string);
  debug_snmp("Tipo de PDU SNMP:%x",pdu_type_request);
  switch (pdu_type_request) {
    case ASN1_CPX_GET_REQ:
      debug_snmp("Req. do tipo [GET-REQ]");
      if(!generate_snmp_task((data+offset+8+length_com_string),ASN1_CPX_GET_REQ))
        return FAIL_CON;
    break;
    case ASN1_CPX_GET_RESP:
      debug_snmp("Req. do tipo [GET-RESP]");
      if(!generate_snmp_task((data+offset+8+length_com_string),ASN1_CPX_GET_RESP))
        return FAIL_CON;
    break;
    case ASN1_CPX_NEXT_REQ:
      debug_snmp("Req. do tipo [GET-RESP]");
      if(!generate_snmp_task((data+offset+8+length_com_string),ASN1_CPX_NEXT_REQ))
        return FAIL_CON;
    break;
    case ASN1_CPX_SET_REQ:
      debug_snmp("Req. do tipo [SET-REQ]");
      if(!generate_snmp_task((data+offset+8+length_com_string),ASN1_CPX_SET_REQ))
        return FAIL_CON;
    break;
    case ASN1_CPX_SEQUENCE:
      debug_snmp("Req. do tipo [SEQUENCE]");
    break;
    default:
      debug_snmp("Tipo desconhecido de requisicao SNMP");
      return FAIL_CON;
    break;
  }
  return SUCCESS_CON;
}

void decode_req_id(unsigned char *pdu_snmp[], char *req_id){
  size_t i,j;
  for (j = 0; j < 5; j++) {
    *(req_id+j) = 0x00;
  }
  for ( i = 0; i <= *pdu_snmp; i++) {
    *(req_id+i) = *(pdu_snmp+i);
  }
}

resp_con_t decode_asn1_errors(unsigned char *pdu_snmp[], uint8_t pdu_type){

}

resp_con_t generate_snmp_task(unsigned char *pdu_snmp[], uint8_t pdu_type){
  //Check for errors in SNMP Message
  uint8_t  length_pdu = *(pdu_snmp);
  size_t i;
  debug_snmp("Tamanho do PDU:%d",length_pdu);
  uint8_t req_id[5];

  // Get the request ID
  if(*(pdu_snmp+2) != ASN1_PRIM_INTEGER)
    decode_req_id((pdu_snmp+2),req_id);
  else
    return FAIL_CON;
  debug_snmp("Request ID LEN[%d]:[%x][%x][%x][%x]",req_id[0],req_id[1],req_id[2],req_id[3],req_id[4]);

  decode_asn1_errors((pdu_snmp+5));

  return SUCCESS_CON;
  // if (decode_asn1_errors(pdu_snmp))
  //   return FAIL_CON;
  //
  // switch (pdu_type) {
  //   case ASN1_CPX_GET_REQ:
  //   break;
  //   case ASN1_CPX_GET_RESP:
  //   break;
  //   case ASN1_CPX_NEXT_REQ:
  //   break;
  //   case ASN1_CPX_SET_REQ:
  //   break;
  //   case ASN1_CPX_SEQUENCE:
  //   break;
  //   default:
  //     debug_snmp("Tipo desconhecido de requisicao SNMP");
  //     return FAIL_CON;
  //   break;
  // }
}

void main(){
  unsigned char *pkt[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, /* ......E. */
    0x00, 0x47, 0x28, 0x06, 0x40, 0x00, 0x40, 0x11, /* .G(.@.@. */
    0x14, 0x9e, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, /* ........ */
    0x00, 0x01, 0xcd, 0xe2, 0x00, 0xa1, 0x00, 0x33, /* .......3 */
    0xfe, 0x46, 0x30, 0x29, 0x02, 0x01, 0x00, 0x04, /* .F0).... */
    0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, /* .public. */
    0x1c, 0x02, 0x04, 0x59, 0x79, 0xb3, 0x59, 0x02, /* ...Yy.Y. */
    0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, /* .....0.0 */
    0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, /* ...+.... */
    0x01, 0x05, 0x00, 0x05, 0x00
  };

  snmp_t test;
  decode_ber_asn1(pkt) ? debug_snmp("\nDecodificacao bem sucedida") : debug_snmp("\nErro decodificacao");
  printf("\nTipo de requisicao:%d \
          \nTipo de resposta:%d \
          \nNumero da requisicao:%d \
          \nErro Status:%d \
          \nErro Index:%d \
          \nOID Var Name:%d \
          \nOID Var Value:%d \n",
          test.request_type,
          test.response_type,
          test.request_id,
          test.error_status,
          test.error_index,
          test.var_name,
          test.var_value);
}
