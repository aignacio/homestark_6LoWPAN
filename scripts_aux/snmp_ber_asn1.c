#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "snmp_ber_asn1.h"

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
  for (i = 0; i < MAX_OCTECT_STRING; i++){
    // printf(" %c ",*(data_to_encode+i));
    if (*(data_to_encode+i) == 0xff || *(data_to_encode+i) == '\0')
      break;
  }

  if (i >= MAX_OCTECT_STRING) {
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
  if ((index-2)<= 0)
    *(encoded_value+1) = 0x01;
  else
    *(encoded_value+1) = index-2;

  for (i = 0; i < *(encoded_value+1); i++)
    *(encoded_value+2+i) = aux_encoding[index-1-i];

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

resp_con_t snmp_decode_message(unsigned char *data, snmp_t *snmp_handle){
  return SUCCESS_CON;
}

void test_ber_func(void){
  snmp_t test;

  // Two pointers from wireshark
  unsigned char *pkt_cmp[] = {
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
    0x01, 0x05, 0x00, 0x05, 0x00
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
    0x6e, 0x61, 0x63, 0x69, 0x6f
  };

  /********* CODE FOR TEST DECODE AND ENCODE INTEGER FUNCTIONS ****************/
  // unsigned char *pkt[] = {
  //   0x02, 0x03, 0x7f, 0xff, 0xff, 0xbb
  // };
  //
  // uint32_t  valor = 0;
  // uint32_t decodificado;
  // uint8_t  codificado[10];
  // size_t i;
  //
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
  // if (decode_asn1_oid((pkt_cmp+73),&oid_received)) {
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


  snmp_decode_message(pkt_cmp,&test) ? debug_snmp("\nDecodificacao bem sucedida") : debug_snmp("\nErro decodificacao");
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

void main(){
  test_ber_func();
}
