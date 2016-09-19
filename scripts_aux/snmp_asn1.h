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
 * @file snmp_asn1.h
 * @brief Headers and macros about SNMP ASN.1 encoding, decoding rules
 * @author Ânderson Ignácio da Silva
 * @date 19 Sept 2016
 * @see http://www.aignacio.com
 */
#ifndef __SNMP_BER_ASN1_H__
#define __SNMP_BER_ASN1_H__

#include <stdbool.h>
/**
 * @brief Types of errors in SNMP PDU
 *
 */
#define ERROR_NONE              0x00 /**  @brief No error occurred */
#define ERROR_RESP_TOO_LARGE    0x01 /**  @brief Response message too large to transpor */
#define ERROR_REQ_OID_NOT_FOUND 0x02 /**  @brief The name of the requested object was not found */
#define ERROR_DATA_TYPE_MATCH   0x03 /**  @brief A data type in the request did not match the data type in the SNMP agent */
#define ERROR_MAN_READ_ONLY     0x04 /**  @brief The SNMP manager attempted to set a read-only parameter */
#define ERROR_GENERAL           0x05 /**  @brief General Error (some error other than the ones listed above) */

/**
 * @brief Primitives data types of ANS.1 encoding
 *
 */
#define ASN1_PRIM_INTEGER    0x02
#define ASN1_PRIM_OCT_STR    0x04
#define ASN1_PRIM_NULL       0x05
#define ASN1_PRIM_OID        0x06

/**
 * @brief Max data types in each kind of variable
 *
 */
// #define MAX_COMMUNITY_STRING 0x80 // 128 bytes
#define MAX_OCTET_STRING     0xFA // 250 bytes
#define MAX_OID_STRING       20 // 20 bytes - 20 levels in tree
#define MAX_UDP_SNMP         300
/**
 * @brief Complex data types of ANS.1 encoding
 *
 */
#define ASN1_CPX_SEQUENCE 0x30
#define ASN1_CPX_GET_REQ  0xA0
#define ASN1_CPX_NEXT_REQ 0xA1
#define ASN1_CPX_GET_RESP 0xA2
#define ASN1_CPX_SET_REQ  0xA3

/** @brief value of the version field for the SNMPv1 */
#define SNMP_VERSION_1					0
/** @brief value of the version field for the SNMPv2c */
#define SNMP_VERSION_2C					1
/** @brief value of the version field for the SNMPv3 */
#define SNMP_VERSION_3					3
/** @brief Decode the initial sequence type */
#define check_seq(x) (x == ASN1_CPX_SEQUENCE ? 1 : 0)

#define DEBUG_SNMP_DECODING /** @brief If defined, show decode SNMP messages*/

/************************************************************************************************************/

#define DEBUG_SNMP
#ifdef DEBUG_SNMP
#define debug_snmp(fmt, args...) printf("\n[SNMP] "fmt, ##args)
#else
#define debug_snmp(fmt, ...)
#endif

typedef enum resp_con{
   FAIL_CON,
   SUCCESS_CON,
} resp_con_t;

typedef struct {
    uint32_t        snmp_version;
    uint8_t         request_type;
    uint8_t         response_type;
    uint32_t        request_id;
    uint8_t         community[MAX_OCTET_STRING];
    uint8_t         oid_encoded[MAX_OID_STRING];
    bool            error;
} snmp_t;

// typedef struct __attribute__((packed)){
//   uint8_t master_seq;
//   uint8_t master_length;
//   uint8_t snmp_version[3];
//   uint8_t *snmp_community_string;
//   uint8_t snmp_pdu_type[2];
//   uint8_t *request_id;
//   uint8_t error_status[3];
//   uint8_t error_index[3];
//   uint8_t var_bind_list[2];
//   uint8_t var_bind_type[2];
//   uint8_t *oid_vaue;
//   uint8_t *value;
// } snmp_pck_t;

#endif

/************************************************************************************************************/
int pow(int base, int exp);

/** @brief Decode integer into ASN.1
 *
 * 		Decode an integer value into ASN.1 format acordding to BER rules
 *
 *  @param [in]  data_encoded Pointer to start the data to be decoded
 *  @param [in]  integer_value Pointer to variable that'll receive the integer decoded
 *
 *  @retval FAIL_CON Error on decoding the integer
 *  @retval SUCCESS_CON Sucess to decode the integer
 *
 **/
resp_con_t decode_asn1_integer(unsigned char *data_encoded[], uint32_t *integer_value);

/** @brief Encode integer into ASN.1
 *
 * 		Encode an integer value into ASN.1 format acordding to BER rules
 *
 *  @param [in]  integer_data Integer 32-bit value to be encoded
 *  @param [in]  encoded_value Pointer to the value that'll receive the encoded data
 *
 *  @retval FAIL_CON Error on encoding the integer
 *  @retval SUCCESS_CON Sucess to encode the integer
 *
 **/
resp_con_t encode_asn1_integer(uint32_t *integer_data, uint8_t *encoded_value);

/** @brief Decode OID into ASN.1
 *
 * 		Decode an OID value acoording to ASN.1 and BER rules. Limited to address values less than 255 (0xFF).
 *    Decode an OID and set the value to vector passed (oid_data) with 0xFF in the end.
 *
 *  @param [in]  oid_encoded Pointer to the start of data to be decoded
 *  @param [in]  oid_data Pointer to the data that'll receive the OID decoded
 *
 *  @retval FAIL_CON Error on decoding the OID, can be different errors
 *  @retval SUCCESS_CON Sucess to decode the OID passed
 *
 **/
resp_con_t decode_asn1_oid(unsigned char *oid_encoded[], uint8_t *oid_data);

/** @brief Encode OID into ASN.1
 *
 * 		Encode an Object Identifier value into ASN.1 format acordding to BER rules
 *
 *  @param [in]  data_to_encode Pointer to the start of the vector of OID to encode, must be 0xFF value in the end of vector
 *  @param [in]  oid_encoded Pointer to the value encoded
 *
 *  @retval FAIL_CON Error on encoding the OID
 *  @retval SUCCESS_CON Sucess to encode the OID
 *
 **/
resp_con_t encode_asn1_oid(uint8_t *data_to_encode, uint8_t *oid_encoded);

/** @brief Decode octet string into ASN.1
 *
 * 		Decode an octet string value acordding to BER rules
 *
 *  @param [in]  data_encoded Pointer to the start of data to be decoded
 *  @param [in]  oct_str Pointer to the data that'll receive the string decoded
 *
 *  @retval FAIL_CON Error on decoding the octet string
 *  @retval SUCCESS_CON Sucess to decode the octet string passed
 *
 **/
resp_con_t decode_asn1_oct_str(unsigned char *data_encoded[], uint8_t *oct_str);

/** @brief Encode octet string into ASN.1
 *
 * 		Encode a string into octet string acordding to BER rules
 *
 *  @param [in]  data_to_encode String to encode with 0xFF ou '\0' in the end
 *  @param [in]  encoded_str Pointer to the data that'll receive the octet string encoded
 *
 *  @retval FAIL_CON Error on encoding the string
 *  @retval SUCCESS_CON Sucess to encode the string passed
 *
 **/
resp_con_t encode_asn1_oct_str(unsigned char data_to_encode[], uint8_t *encoded_str);

/** @brief Check if there's some error in SNMP message
 *
 * 		Check error status and error index in SNMP PDU
 *
 *  @param [in]  error_data Pointer to the begin of error bytes to check [error_status][error_index]
 *
 *  @retval FAIL_CON Error on PDU
 *  @retval SUCCESS_CON None error in PDU
 *
 **/
resp_con_t error_check_snmp(unsigned char *error_data[]);
