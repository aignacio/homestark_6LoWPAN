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
 * @file mibii.c
 * @brief MIB II Implementation of homestark network
 * @author Ânderson Ignácio da Silva
 * @date 19 Sept 2016
 * @see http://www.aignacio.com
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "snmp.h"
#include "mibii.h"

void *mibii_tree[] = {"1.1","1.2","1.3","1.4","1.5","1.6","1.7",
                      "4.1","4.2","4.3","4.4","4.5","4.6","4.7",
                      "25.1","25.2","25.3","25.4","25.5","25.6"};

void *mibii_list[] = {"1.1-aignacio\0",
                      "1.2-aignacio\0",
                      "1.3-aignacio\0",
                      "1.4-aignacio\0",
                      "1.5-aignacio\0",
                      "1.5-aignacio\0",
                      "1.7-aignacio\0",
                      "4.1-aignacio\0",
                      "4.2-aignacio\0",
                      "4.3-aignacio\0",
                      "4.4-aignacio\0",
                      "4.5-aignacio\0",
                      "4.6-aignacio\0",
                      "4.7-aignacio\0",
                      "25.1-aignacio\0",
                      "25.2-aignacio\0",
                      "25.3-aignacio\0",
                      "25.4-aignacio\0",
                      "25.5-aignacio\0",
                      "25.6-aignacio\0"};

resp_con_t mib_ii_check_oid(uint8_t *mib_oid, uint8_t *index){
  uint8_t i;
  char  oid_tree[4];
  int mib_1 = *(mib_oid);
  int mib_2 = *(mib_oid+1);
  int mib_3 = *(mib_oid+2);
  int mib_4 = *(mib_oid+3);

  // debug_snmp("MIB_Third_bit:%d",mib_3);
  if (mib_3 != 0 || mib_4 != 0)
    return FAIL_CON;
  sprintf(oid_tree,"%d.%d",mib_1,mib_2);
  #ifdef DEBUG_SNMP_DECODING
  debug_snmp("MIB to search:%s",oid_tree);
  #endif
  for (i = 0; i < sizeof(mibii_tree)/sizeof(*mibii_tree); i++){
    if (!strcmp(mibii_tree[i],oid_tree)){
      *index = i;
      return SUCCESS_CON;
    }
    // debug_snmp("%s",mibii_tree[i]);
  }
  #ifdef DEBUG_SNMP_DECODING
  // debug_snmp("MIB2 - There isn't OID mapped!");
  #endif
  return FAIL_CON;
}

resp_con_t mib_ii_get_oid(uint8_t *oid, uint8_t *oid_string){
  uint8_t index;

  if (!mib_ii_check_oid(oid+7,&index)) return FAIL_CON;

  char data[MAX_OCTET_STRING];
  sprintf(data,"%s",(char *)mibii_list[index]);

  uint8_t len = strlen(data),
          index2 = 0;
  while (index2 <= len) {
    *(oid_string+index2) = data[index2];
    index2++;
  }
  *(oid_string+index2) = '\0';
  #ifdef DEBUG_SNMP_DECODING
  // debug_snmp("MIB2 Decode OID received:%s",data);
  #endif
  return SUCCESS_CON;
}
