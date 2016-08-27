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
#include "stdint.h"
#include <stdlib.h>

static struct ctimer    mqtt_connect_msg; //Dispara o envio de mensagens CONNECT
static struct ctimer    mqtt_stack_call;  //Dispara o inicio de processamento da fila MQTT-SN

static uint16_t         gTaskID = 0;
static uint8_t          gMQTTSNConnectTries = RETRY_CONNECT;
static mqtt_sn_status_t mqtt_status = MQTTSN_DISCONNECTED;
static mqtt_sn_t        gMQTTSN_con;

resp_con_t mqtt_sn_check_rc(uint8_t rc){
  switch (rc) {
    case ACCEPTED:
      return SUCCESS_CON;
    break;
    case REJECTED_CONGESTION:
      return FAIL_CON;
    break;
    case REJECTED_INVALID_TOPIC_ID:
      return FAIL_CON;
    break;
    case REJECTED_NOT_SUPPORTED:
      return FAIL_CON;
    break;
    default:
      return FAIL_CON;
    break;
  }
}

void mqtt_sn_recv_parser(const uint8_t *data){
    uint8_t msg_type = data[1],
            return_code = 0xFF;

    // Como o MsgType não se altera de posição, testamos primeiro ele antes do
    // returning code, já que este pode variar
      switch (msg_type) {
        case MQTT_SN_TYPE_CONNACK:
          return_code = data[2]; //No caso do CONNACK - RC[2]
          if (mqtt_sn_check_rc(return_code)){
            mqtt_status = MQTTSN_CONNECTED;
            debug_mqtt("Conectado ao broker MQTT-SN");
            debug_mqtt("Iniciando fila de servicos MQTT ");
            ctimer_set(&mqtt_stack_call,TIME_MQTT_POLL, mqtt_sn_state_ctrl, NULL);
          }
        break;
        case MQTT_SN_TYPE_REGACK:
        break;
        case MQTT_SN_TYPE_PUBACK:
        break;
        case MQTT_SN_TYPE_SUBACK:
        break;
        case MQTT_SN_TYPE_UNSUBACK:
        break;
        default:
        break;
      }
}

void mqtt_sn_udp_rec_cb(struct simple_udp_connection *c,
                            const uip_ipaddr_t *sender_addr,
                            uint16_t sender_port,
                            const uip_ipaddr_t *receiver_addr,
                            uint16_t receiver_port,
                            const uint8_t *data,
                            uint16_t datalen) {
  mqtt_sn_recv_parser(data);
}

void mqtt_sn_state_ctrl(void *ptr){
  switch (mqtt_status) {
    case MQTTSN_DISCONNECTED:
      debug_mqtt("Desconectado MQTT");
    break;
    case MQTTSN_CONNECTED:
    // mqtt_sn_check_queue();
    mqtt_sn_task_t pub_test;

    pub_test.msg_type_q = MQTT_SN_TYPE_PUBLISH;
    pub_test.short_topic = (uint8_t *)25;
    pub_test.long_topic = "demo";
    pub_test.message = "Velho";

      //mqtt_sn_insert_queue(pub_test);
      //mqtt_sn_delete_queue();
      //mqtt_sn_insert_queue(pub_test);

      //mqtt_sn_check_queue();

      // pub_test.msg_type_q = MQTT_SN_TYPE_PUBLISH;
      // pub_test.short_topic = (uint8_t *)25;
      // pub_test.long_topic = "demo";
      // pub_test.message = "Entrei agora recem";
      //
      // mqtt_sn_insert_queue(pub_test);
      // mqtt_sn_insert_queue(pub_test);
      // mqtt_sn_insert_queue(pub_test);
      // mqtt_sn_insert_queue(pub_test);
      // mqtt_sn_insert_queue(pub_test);
      //
      // mqtt_sn_check_queue();
      // mqtt_sn_delete_queue();
      //
      // debug_mqtt("Primeiro elemento da fila:");
      // debug_mqtt("%s",mqtt_queue_first->data.message);
      //
      // debug_mqtt("Mais novo inserido:");
      // debug_mqtt("%s",mqtt_queue_last->data.message);
    break;
    case MQTTSN_WAITING_CONNACK:
      if (!gMQTTSNConnectTries) {
        debug_mqtt("Numero de tentativas para @CONNACK estourou!");
        gMQTTSNConnectTries = RETRY_CONNECT;
        mqtt_status = MQTTSN_DISCONNECTED;
        debug_mqtt("Desconectado MQTT");
      }
      else{
        mqtt_sn_connect_request();
      }
      gMQTTSNConnectTries--;
      // ctimer_reset(&mqtt_connect_msg);
      // Ao invés de chamar novamente o temporizador para enviar o @CONNECT,
      // utiliza-se 10x do tempo do número de tentativa, evitando assim
      // diversos @CONNECT
      ctimer_set(&mqtt_connect_msg,10*(RETRY_CONNECT-gMQTTSNConnectTries)*TIME_MQTT_POLL, mqtt_sn_state_ctrl, NULL);
    break;
    case MQTTSN_IDDLE:
      debug_logic("MQTT em IDDLE");
    break;
    default:
      debug_logic("Estado desconhecido!");
    break;
  }
}

void mqtt_sn_connect_request(void){
  connect_packet_t packet;

  // Criação do pacote CONNECT
  packet.type = MQTT_SN_TYPE_CONNECT;
  packet.flags = MQTT_SN_FLAG_CLEAN;
  packet.protocol_id = MQTT_SN_PROTOCOL_ID;
  packet.duration = uip_htons(gMQTTSN_con.keep_alive); //Realiza a conversão para network byte order

  strncpy(packet.client_id, gMQTTSN_con.client_id, strlen(gMQTTSN_con.client_id));
  packet.client_id[strlen(gMQTTSN_con.client_id)] = '\0';
  packet.length = 0x06 + strlen(packet.client_id);

  // debug_logic("CLIENT_ID:%s, Tamanho:%d",packet.client_id,strlen(packet.client_id));
  debug_logic("Enviando o pacote @CONNECT...");
  simple_udp_send(&gMQTTSN_con.udp_con,&packet, packet.length);
  // debug_logic("enviado!");

  mqtt_status = MQTTSN_WAITING_CONNACK;
}

resp_con_t mqtt_sn_create_sck(mqtt_sn_t mqtt_sn_connection){
  static uip_ipaddr_t broker_addr;
  static uint8_t con_udp_status = 0;

  gMQTTSN_con = mqtt_sn_connection;
  uip_ip6addr(&broker_addr, *gMQTTSN_con.ipv6_broker,
                            *(gMQTTSN_con.ipv6_broker+1),
                            *(gMQTTSN_con.ipv6_broker+2),
                            *(gMQTTSN_con.ipv6_broker+3),
                            *(gMQTTSN_con.ipv6_broker+4),
                            *(gMQTTSN_con.ipv6_broker+5),
                            *(gMQTTSN_con.ipv6_broker+6),
                            *(gMQTTSN_con.ipv6_broker+7));

  if (strlen(gMQTTSN_con.client_id) > 23){
    debug_logic("Cli. ID SIZE:%d > 23!",strlen(gMQTTSN_con.client_id));
    return FAIL_CON;
  }

  debug_mqtt("Endereco do broker IPv6: ");
  uip_debug_ipaddr_print(&broker_addr);
  debug_mqtt("Endereco da porta:%d ",gMQTTSN_con.udp_port);
  debug_mqtt("Client ID:%s/%d",gMQTTSN_con.client_id,strlen(gMQTTSN_con.client_id));


  con_udp_status = simple_udp_register(&gMQTTSN_con.udp_con,
                                        gMQTTSN_con.udp_port,
                                        &broker_addr,
                                        gMQTTSN_con.udp_port,
                                        mqtt_sn_udp_rec_cb);
  if(!con_udp_status)
    return FAIL_CON;

  debug_mqtt("Alocada conexao UDP ");

  mqtt_status = MQTTSN_WAITING_CONNACK;
  ctimer_set(&mqtt_connect_msg,TIME_MQTT_POLL, mqtt_sn_state_ctrl, NULL);
  return SUCCESS_CON;
}

/************************** QUEUE MQTT-SN FUNCTIONS ***************************/

resp_con_t mqtt_sn_insert_queue(mqtt_sn_task_t new){
  struct node *temp,*temp2;

  temp2 = mqtt_queue_first;
  int cnt = 0;
  while (temp2) {
      temp2 = temp2->link;
      cnt++;
  }

  //Limita o número máximo de tarefas alocadas na fila
  if (cnt > MAX_QUEUE_MQTT_SN)
    return FAIL_CON;

  temp = (struct node*)malloc(sizeof(struct node));
  temp->data.msg_type_q  = new.msg_type_q;
  temp->data.short_topic = new.short_topic;
  temp->data.long_topic  = new.long_topic;
  temp->data.message     = new.message;
  temp->data.id_task     = (uint16_t *)gTaskID++;

  temp->link = NULL;
  if (mqtt_queue_last  ==  NULL) {
      mqtt_queue_first = mqtt_queue_last = temp;
  }
  else {
      mqtt_queue_last->link = temp;
      mqtt_queue_last = temp;
  }

  return SUCCESS_CON;
}

void mqtt_sn_delete_queue(){
  struct node *temp;

  temp = mqtt_queue_first;
  if (mqtt_queue_first == NULL) {
      debug_mqtt("A fila de tarefas esta vazia");
      mqtt_queue_first = mqtt_queue_last = NULL;
  }
  else {
      debug_mqtt("Tarefa:[%p] deletada", mqtt_queue_first->data.id_task);
      mqtt_queue_first = mqtt_queue_first->link;
      free(temp);
  }
}

void mqtt_sn_check_queue(){
  int cnt = 0;
  struct node *temp;

  temp = mqtt_queue_first;

  if (mqtt_queue_first  ==  NULL) {
      debug_mqtt("A fila de tarefas esta vazia");
  }

  while (temp) {
      printf("[%p]  ", temp->data.id_task);
      temp = temp->link;
      cnt++;
  }
  debug_mqtt("Tamanho da fila:[%d]\n", cnt);
}
