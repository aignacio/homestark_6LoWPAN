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

#include "contiki.h"
#include "lib/random.h"
#include "clock.h"
#include "sys/ctimer.h"
#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "mqtt_sn.h"
#include "dev/leds.h"
#include "net/rime/rime.h"
#include "simple-udp.h"
#include <stdio.h>
#include <string.h>

static char     mqtt_client_id[] = "anderson";
static uint16_t udp_port = 1884;
static uint16_t keep_alive = 2;
static uint16_t broker_address[] = {0xaaaa, 0, 0, 0, 0, 0, 0, 0x1};
static struct   etimer time_poll;
static uint16_t tick_process = 0;
static char     pub_test[20];
//Estes tópicos pré-registrados serão mais rápidos de publicar/receber publicações
static char *topics_mqtt[] = {"/topic_1",
                              "/topic_2",
                              "/topic_3",
                              "/topic_4",
                              "/topic_5",
                              "/topic_6"};

mqtt_sn_con_t mqtt_sn_connection;

/*---------------------------------------------------------------------------*/
PROCESS(init_system_process, "[Contiki-OS] Iniciando sistema operacional");
AUTOSTART_PROCESSES(&init_system_process);
/*---------------------------------------------------------------------------*/

PROCESS_THREAD(init_system_process, ev, data)
{
  PROCESS_BEGIN();

  debug_os("Inicio do processo Homestark");

  mqtt_sn_connection.client_id   = mqtt_client_id;
  mqtt_sn_connection.udp_port    = udp_port;
  mqtt_sn_connection.ipv6_broker = broker_address;
  mqtt_sn_connection.keep_alive  = keep_alive;

  mqtt_sn_init();   // Inicializa alocação de eventos e a principal PROCESS_THREAD do MQTT-SN
  mqtt_sn_create_sck(mqtt_sn_connection, topics_mqtt, ss(topics_mqtt));

  etimer_set(&time_poll, CLOCK_SECOND);

  while(1) {
      PROCESS_WAIT_EVENT();
      debug_os("Execucao[%d]",tick_process++);
      tick_process++;
      sprintf(pub_test,"Execucao %d",tick_process);
      //mqtt_sn_pub("/teste",pub_test,true,0);

      mqtt_sn_pub("/topic_1","TOPICO 1",true,0);
      mqtt_sn_pub("/topic_2","TOPICO 2",true,0);
      mqtt_sn_pub("/topic_3","TOPICO 3",true,0);
      mqtt_sn_pub("/topic_4","TOPICO 4",true,0);
      // mqtt_sn_pub("/topic_5","TOPICO 5",true,0);
      // mqtt_sn_pub("/topic_6","TOPICO 6",true,0);

      //if (tick_process == 20) {
      mqtt_sn_sub("/topic_1",0);
      mqtt_sn_sub("/topic_2",0);
      mqtt_sn_sub("/topic_3",0);
      mqtt_sn_sub("/topic_4",0);
      // mqtt_sn_sub("/topic_5",0);
      // mqtt_sn_sub("/topic_6",0);
      // //}

      //mqtt_sn_sub("/topico_wild/#",0);

      mqtt_sn_check_queue();
      // print_g_topics();
      //debug_os("Estado do MQTT:%s",mqtt_sn_check_status_string());
      if (etimer_expired(&time_poll))
        etimer_reset(&time_poll);
  }
  PROCESS_END();
}
