#include "contiki.h"
#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "simple-udp.h"
#include <stdio.h>
#include <string.h>
#include <mqtt_sn.h>
#include "sys/timer.h"
#include "list.h"
#include "sys/ctimer.h"

// static process_event_t mqttsn_poll;
static struct ctimer   poll_timer;

// PROCESS(mqtt_sn_main, "[MQTT-SN] Processo de controle");
//
// PROCESS_THREAD(mqtt_sn_main, ev, data)
// {
//   PROCESS_BEGIN();
//   if (ev == mqttsn_poll) {
//     debug_mqtt("\n[MQTT-SN] Evento de poll esta funcionando parabens Anderson!");
//   }
//   else{
//     debug_mqtt("\n[MQTT-SN] Outro evento esta ocorrendo!");
//   }
//   //
//   // debug_mqtt("\n[MQTT-SN] Execucao do processo de controle");
//   //
//   // const char* client_id = "TESTE";
//   // uint16_t keepalive=23;
//   // connect_packet_t packet;
//   //
//   // // Check that it isn't too long
//   // if (client_id && strlen(client_id) > 23) {
//   //     printf("Error: client id is too long\n");
//   //     // return;
//   // }
//   //
//   // // Create the CONNECT packet
//   // packet.type = MQTT_SN_TYPE_CONNECT;
//   // packet.flags = MQTT_SN_FLAG_CLEAN;
//   // packet.protocol_id = MQTT_SN_PROTOCOL_ID;
//   // packet.duration = uip_htons(keepalive); //Realiza a conversão para network byte order
//   //
//   // strncpy(packet.client_id, client_id, sizeof(packet.client_id)-1);
//   // packet.client_id[sizeof(packet.client_id) - 1] = '\0';
//   //
//   // packet.length = 0x06 + strlen(packet.client_id);
//   //
//   // debug_mqtt("\n[MQTT-SN] Enviando o pacote @CONNECT");
//   //
//   // // static unsigned int message_number;
//   // // sprintf(message_number, "%x",MQTT_SN_TYPE_CONNECT);
//   // // debug_mqtt("Valor enviado ao broker:%x\n",packet);
//   // simple_udp_send(&udp_con,&packet, packet.length);
//
//   PROCESS_END();
// }

static void mqtt_udp_rec_cb(struct simple_udp_connection *c,
                            const uip_ipaddr_t *sender_addr,
                            uint16_t sender_port,
                            const uip_ipaddr_t *receiver_addr,
                            uint16_t receiver_port,
                            const uint8_t *data,
                            uint16_t datalen)
{
  uip_debug_ipaddr_print(sender_addr);
  debug_mqtt("\n[UDP] Dado recebido na porta %d atraves da porta %d com comprimento %d: '%s'\n",\
              receiver_port, sender_port, datalen, data);

  // simple_udp_send(&udp_con,"datdsfgsdfgdfsgsdfga", sizeof("datdsfgsdfgdfsgsdfga"));
}

static void mqttControlInit(void *ptr)
{
  // process_post(&mqtt_sn_main, mqttsn_poll, NULL);
  // process_poll(&mqtt_sn_main);
  ctimer_reset(&poll_timer);
  printf("POLL2\n");
}

void mqtt_create_sck(mqtt_sn_t mqtt_sn_connection){
  static uip_ipaddr_t broker_addr;

  uip_ip6addr(&broker_addr, *mqtt_sn_connection.ipv6_broker,
                            *(mqtt_sn_connection.ipv6_broker+1),
                            *(mqtt_sn_connection.ipv6_broker+2),
                            *(mqtt_sn_connection.ipv6_broker+3),
                            *(mqtt_sn_connection.ipv6_broker+4),
                            *(mqtt_sn_connection.ipv6_broker+5),
                            *(mqtt_sn_connection.ipv6_broker+6),
                            *(mqtt_sn_connection.ipv6_broker+7));

  debug_mqtt("\n[MQTT-SN] Endereco do broker IPv6: ");
  uip_debug_ipaddr_print(&broker_addr);
  debug_mqtt("\n[MQTT-SN] Endereco da porta:%d ",mqtt_sn_connection.udp_port);
  debug_mqtt("\n[MQTT-SN] Client ID:%s ",mqtt_sn_connection.client_id);

  simple_udp_register(&mqtt_sn_connection.udp_con,
                      mqtt_sn_connection.udp_port,
                      &broker_addr,
                      mqtt_sn_connection.udp_port,
                      mqtt_udp_rec_cb);

  debug_mqtt("\n[MQTT-SN] Conexao UDP estabelecida com sucesso! ");
  debug_mqtt("\n[MQTT-SN] Iniciando fila de servicos MQTT ");

  // mqttsn_poll = process_alloc_event(); //Aloca endereço de evento para "mqttsn_poll"
  // process_start(&mqtt_sn_main, NULL); //Inicia o processo mqtt_sn_main

  // ctimer_set(&poll_timer, TIME_MQTT_STACK, mqttControlInit, NULL);

  // process_post(&mqtt_sn_main, mqttsn_event, NULL);
  // etimer_set(&tempo_envio,4*CLOCK_SECOND);
  // PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&tempo_envio));
  /* Reset the etimer to trig again in 1 second */
  // ctimer_set(&timer, CLOCK_SECOND, callback, NULL);
  // process_post(&mqtt_sn_main, mqttsn_event, NULL);
  // process_poll(&mqttsn_event);
  // etimer_reset(&tempo_envio);

}
