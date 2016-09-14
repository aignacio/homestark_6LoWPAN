/**
 * @file main_core.c
 * @author Ânderson Ignácio da Silva
 * @date 19 Ago 2016
 * @brief Arquivo principal do código fonte da rede mesh 6LoWPAN
 * \n Para compilar este código, execute o makefile com o target desejado,
 * por exemplo:
 * \n \b "make TARGET=srf06-cc26xx"
 * \n Caso não reconheça qual o TARGET correto, utiliza o comando
 * \n \b "make targets"
 * \n para listar os tags disponíveis
 * @see http://www.aignacio.com
 */

// #include "contiki.h"
// #include "lib/random.h"
// #include "clock.h"
// #include "sys/ctimer.h"
// #include "dev/leds.h"
// #include "net/rime/rime.h"
// #include "simple-udp.h"
// #include <stdio.h>
// #include <string.h>
// #include <stdlib.h>
// #include "net/ipv6/uip-ds6.h"
// #include "net/ip/uip-udp-packet.h"
// #include "net/ip/uip.h"
// #include "net/rpl/rpl.h"
// #include "dev/serial-line.h"
// #include "coap-server.h"

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

static uint16_t udp_port = 161;
static uint16_t keep_alive = 5;
static char     device_id[17];
static uint16_t nms_ip[] = {0xaaaa, 0, 0, 0, 0, 0, 0, 0x1};

/*---------------------------------------------------------------------------*/
PROCESS(init_system_process, "[Contiki-OS] Iniciando sistema operacional");
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

  snmp_con_t snmp_con;
  snmp_con.udp_port = udp_port;
  snmp_con.ipv6_nms = nms_ip;
  snmp_con.keep_alive = keep_alive;

  //snmp_init(snmp_con);

  process_start(&coap_server_process, NULL);

  while(1) {
      PROCESS_WAIT_EVENT();
  }
  PROCESS_END();
}
