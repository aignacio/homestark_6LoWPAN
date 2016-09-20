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

void *mibii_tree[] = {"1.1",
                      "1.2",
                      "1.3",
                      "1.4",
                      "1.5",
                      "1.6",
                      "1.7"};

void *mibii_list[] = {"1.1-aignacio\0",
                      "1.2-aignacio\0",
                      "1.3-aignacio\0",
                      "1.4-aignacio\0",
                      "1.5-aignacio\0",
                      "1.6-aignacio\0",
                      "1.7-aignacio\0"};

resp_con_t mib_ii_check_oid(uint8_t *mib_oid, uint8_t *index){
  uint8_t i;
  uint8_t oid_tree[4];

  sprintf(oid_tree,"%d.%d",*(mib_oid),*(mib_oid+1));
  // debug_snmp("MIB to search:%s\n",oid_tree);
  for (i = 0; i < sizeof(mibii_tree)/sizeof(*mibii_tree); i++){
    if (!strcmp(mibii_tree[i],oid_tree)){
      *index = i;
      return SUCCESS_CON;
    }
    // debug_snmp("%s",mibii_tree[i]);
  }
  #ifdef DEBUG_SNMP_DECODING
  debug_snmp("There isn't OID mapped!");
  #endif
  return FAIL_CON;
}

resp_con_t mib_ii_get_oid(uint8_t *oid, uint8_t *oid_string){
  size_t i;
  uint8_t index;
  if (!mib_ii_check_oid(oid+6,&index)) return FAIL_CON;

  uint8_t data[MAX_OCTET_STRING];
  sprintf(data,"%s",mibii_list[index]);

  uint8_t len = strlen(data),
          index2 = 0;
  while (index2 <= len) {
    *(oid_string+index2) = data[index2];
    index2++;
  }
  #ifdef DEBUG_SNMP_DECODING
  debug_snmp("MIB2 Decode OID received:");
  for (i = 0; *(oid+i) != 0xFF; i++)
    printf("%x.",*(oid+i));
  printf(" ---> %s",data);
  #endif
  return SUCCESS_CON;
}
