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

uint8_t *encode_asn1_integer(uint32_t *integer_data){
  size_t i;
  uint8_t encoded_value[100],
          aux_encoding[100];
  uint8_t index = 2; // First and second, type and length, we start frame from three

  // First number to alloc is the type - BER encoding
  encoded_value[0] = ASN1_PRIM_INTEGER;
  while (*integer_data != 0){
    aux_encoding[index] = *integer_data % 256;
    *integer_data = *integer_data / 256;
    index++;
  }
  encoded_value[1] = index-2;
  for (i = 0; i < encoded_value[1]; i++)
    encoded_value[2+i] = aux_encoding[index-1-i];

  // Then we need to put the length in the char*
  return &encoded_value;
}

uint32_t decode_asn1_integer(unsigned char *data_encoded[]){
  uint8_t length = *(data_encoded+1);
  uint32_t integer_value;
  size_t i = 0;
  uint32_t aux;

  // Test if it's an integer value to be decoded
  if (*data_encoded != ASN1_PRIM_INTEGER){
    debug_snmp("The value is not integer!");
    return 0;
  }

  for (i=1, integer_value = 0; i <= length; i++){
    aux = *(data_encoded+1+i);
    integer_value += aux*(pow(256,(length-i)));
    // debug_snmp("%x * 256^%d = %d",aux,(length-i),integer_value);
  }
  return integer_value;
}

void main(void){
  snmp_t test;

  unsigned char *pkt[] = {
    0x02, 0x03, 0x7f, 0xff, 0xff, 0xbb
  };

  uint32_t  valor = 1501147993;

  uint32_t decodificado;
  uint8_t  *codificado = malloc(10*sizeof(uint8_t));

  decodificado = decode_asn1_integer(pkt);
  codificado = encode_asn1_integer(&valor);

  size_t i;
  // debug_snmp("Codificado:%d",codificado);
  // for (i =0; i < *(codificado+1)+2; i++)
  //   printf("[%x]",*(codificado+i));
  // debug_snmp("Codificado:%d",codificado);
  // for (i =0; i < *(codificado+1)+2; i++)
  //   printf("[%x]",*(codificado+i));

  debug_snmp("Decodificado:%d",decodificado);
  debug_snmp("Codificado:");
  for (i =0; i < *(codificado+1)+2; i++)
    printf("[%x]",*(codificado+i));

  printf("\n");
  // decode_snmp(pkt) ? debug_snmp("\nDecodificacao bem sucedida") : debug_snmp("\nErro decodificacao");
  // printf("\nTipo de requisicao:%d \
  //         \nTipo de resposta:%d \
  //         \nNumero da requisicao:%d \
  //         \nErro Status:%d \
  //         \nErro Index:%d \
  //         \nOID Var Name:%d \
  //         \nOID Var Value:%d \n",
  //         test.request_type,
  //         test.response_type,
  //         test.request_id,
  //         test.error_status,
  //         test.error_index,
  //         test.var_name,
  //         test.var_value);
}
