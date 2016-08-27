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
#include "sys/etimer.h"
#include "stdint.h"
#include <stdlib.h>
#include <stdbool.h>

static struct etimer              mqtt_timeout;     //Estrutura pricipal de temporização para envio de mensagens MQTT-SN
static process_event_t            mqtt_connect_req  //Evento de req CONNECT do nó ao broker

static bool                       gTopicRegistered = 0; //Flag que indica se o registro dos tópicos já foi realizado
static uint16_t                   gTaskID = 0;
static uint8_t                    gMQTTSNConnectTries = RETRY_CONNECT;
static mqtt_sn_status_t           mqtt_status = MQTTSN_DISCONNECTED;
static mqtt_sn_messages_status_t  mqtt_message_status = IDDLE;
static mqtt_sn_t                  gMQTTSN_con;
static mqtt_sn_task_t             mqtt_sn_topics[MAX_TOPIC_USED];

PROCESS(mqtt_sn_main, "[MQTT-SN] Processo inicial");

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
            debug_mqtt("Iniciando fila de servicos MQTT-SN");
            ////ctimer_set(&mqtt_init_register_call,TIME_MQTT_POLL, mqtt_sn_state_ctrl, NULL);
          }
        break;
        case MQTT_SN_TYPE_REGACK:
          return_code = data[6]; //No caso do REGACK - RC[6]
          uint8_t short_topic = data[3]; // Na verdade os bytes de short topic são o [2] e [3], porém
                                         // só estamos usa-se o [3] porque não consideramos mais do que
                                         // 15 tópicos
                                         /// @todo Rever o short topic para adequar bytes [2][3] juntos
          if (mqtt_sn_check_rc(return_code)){
            debug_mqtt("Recebido o REGACK - Msg. ID:[%d][%d]",data[4],data[5]);
            mqtt_sn_topics[data[1]].short_topic = &short_topic;
            debug_mqtt("Short Topic Correspondente:[%d][%d]",data[2],data[3]);
            mqtt_sn_delete_queue();
          }
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
      mqtt_message_status = IDDLE; //Resseta o estado das mensagens após conexão
    break;
    case MQTTSN_CONNECTED:
      mqtt_main_connected();
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
      ////ctimer_set(&mqtt_connect_msg,10*(RETRY_CONNECT-gMQTTSNConnectTries)*TIME_MQTT_POLL, mqtt_sn_state_ctrl, NULL);
    break;
    case MQTTSN_IDDLE:
      debug_logic("MQTT em IDDLE");
    break;
    default:
      debug_logic("Estado desconhecido!");
    break;
  }
}

void mqtt_main_connected(){
  // Esta é a função principal que se utiliza uma vez que estamos conectados ao broker
  if(!gTopicRegistered){
    // Se os tópicos não foram registrados ainda, só há esta opção
    // envia o REGISTER do tópico e aguarda antes de enviar outro
    mqtt_sn_reg_send();
    //ctimer_set(&mqtt_register_topics, 5*TIME_MQTT_POLL, mqtt_sn_state_ctrl, NULL); // Aguarda 5 segundos antes de enviar novamente o REGISTER do primeiro elemento na fila de processamentos
    // ctimer......
  }
  else
    switch (mqtt_message_status) {
      case MQTTSN_WAITING_REGACK:
      break;
      case MQTTSN_WAITING_PUBACK:
      break;
      case MQTTSN_WAITING_SUBACK:
      break;
      case MQTTSN_PUB_REQ:
      break;
      case MQTTSN_SUB_REQ:
      break;
      case MQTTSN_REG_REQ:
      break;
      case IDDLE:
        debug_mqtt("Todos os topicos foram registrados!");
      break;
    }
}

resp_con_t mqtt_sn_reg_send(){
  register_packet_t packet;

  /****************************************************************************/
  // REGISTRO DE TÓPICOS DEFINIDOS
  // Verifica-se se a fila está vazia,
  // caso contrário, ainda precisamos
  // registrar tópicos MQTT_SN

  struct node *verEMpty;
  int counter = 0;

  verEMpty = mqtt_queue_first;

  while (verEMpty) {
      verEMpty = verEMpty->link;
      counter++;
  }

  // Se vazio significa que registramos todos os tópicos
  if (!counter) {
      gTopicRegistered = 1;
      return SUCCESS_CON;
  }

  /****************************************************************************/

  size_t topic_name_len = strlen(mqtt_queue_first->data.long_topic); //Pega o primeiro da fila aguardando

  if (topic_name_len > MQTT_SN_MAX_TOPIC_LENGTH) {
      debug_mqtt("Erro: Nome do topico excede o limite maximo");
      return FAIL_CON;
  }

  packet.type = MQTT_SN_TYPE_REGISTER;
  packet.topic_id = 0x0000;
  // Quando o broker responder com o short topic ID,
  // ele utilizará como message id, o identificador único da task na
  // queue de serviços do MQTT-SN, logo se torna fácil saber como montar
  // a relação (short_topic/long_topic) no vetor global mqtt_sn_topics[]
  packet.message_id = uip_htons((int)mqtt_queue_first->data.id_task);

  strncpy(packet.topic_name, mqtt_queue_first->data.long_topic, topic_name_len);
  packet.length = 0x06 + topic_name_len;
  packet.topic_name[topic_name_len] = '\0';

  debug_mqtt("Topico a registrar:%s [%d][%d]",packet.topic_name,strlen(packet.topic_name),packet.length);

  debug_logic("Enviando o pacote @REGISTER...");
  simple_udp_send(&gMQTTSN_con.udp_con,&packet, packet.length);

  mqtt_message_status = MQTTSN_WAITING_REGACK;
  return SUCCESS_CON;
}

resp_con_t mqtt_sn_reg_task(char *topic_name){
  // Primeiro antes de qualquer processo MQTT-SN
  // registra-se todos os tópicos informados
  // pelo usuário, otimizando as funções de inscrição
  // e publicação
  mqtt_sn_task_t topic_reg;

  topic_reg.msg_type_q = MQTT_SN_TYPE_REGISTER;
  topic_reg.long_topic = topic_name;

  mqtt_sn_topics[gTaskID].long_topic = topic_name;

  // debug_mqtt("Criando task de registro de topico:%s",topic_name);
  if (!mqtt_sn_insert_queue(topic_reg))
    return FAIL_CON;
  return SUCCESS_CON;
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

  // debug_mqtt("CLIENT_ID:%s, Tamanho:%d",packet.client_id,strlen(packet.client_id));
  debug_mqtt("Enviando o pacote @CONNECT...");
  simple_udp_send(&gMQTTSN_con.udp_con,&packet, packet.length);
  // debug_logic("enviado!");

  mqtt_status = MQTTSN_WAITING_CONNACK;
}

resp_con_t mqtt_sn_create_sck(mqtt_sn_t mqtt_sn_connection, char *topics[], size_t topic_len){
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

  /****************************************************************************/
  //  Criando tarefa de CONNECT

  /****************************************************************************/

  /****************************************************************************/
  // Criando tarefas de REGISTER para cada tópico definido pelo usuário no código
  // principal. Inicia-se o processo de preenchimento de tarefas na fila de serv
  // iços MQT-SN

  size_t i;
  for(i = 0; i < topic_len; i++)
    if(!mqtt_sn_reg_task(topics[i])){
      break;
      return FAIL_CON;
    }

  // Printa fila atual de processos - comentar para não poluir tanto
  // mqtt_sn_check_queue();

  /****************************************************************************/

  // mqtt_status = MQTTSN_WAITING_CONNACK;
  // //ctimer_set(&mqtt_connect_msg,TIME_MQTT_POLL, mqtt_sn_state_ctrl, NULL);

  // Gera-se um evento de CONNECT
  process_post(&mqtt_sn_main, mqtt_connect_req, NULL);

  return SUCCESS_CON;
}

void parse_mqtt_type_string(uint8_t type, char **type_string){
  switch (type) {
    case MQTT_SN_TYPE_CONNECT:
      *type_string = "CONNECT";
    break;
    case MQTT_SN_TYPE_REGISTER:
      *type_string = "REGISTER";
    break;
    case MQTT_SN_TYPE_PUBLISH:
      *type_string = "PUBLISH";
    break;
    case MQTT_SN_TYPE_SUBSCRIBE:
      *type_string = "SUBSCRIBE";
    break;
    case MQTT_SN_TYPE_PINGREQ:
      *type_string = "PINGREQ";
    break;
    case MQTT_SN_TYPE_PINGRESP:
      *type_string = "PINGRESP";
    break;
    case MQTT_SN_TYPE_DISCONNECT:
      *type_string = "DISCONNECT";
    break;
  }
}

/************************** FUNÇÕES DE FILA MQTT-SN ***************************/
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
  temp->data.id_task     = (uint16_t *)(gTaskID++);

  temp->link = NULL;
  if (mqtt_queue_last  ==  NULL) {
      mqtt_queue_first = mqtt_queue_last = temp;
  }
  else {
      mqtt_queue_last->link = temp;
      mqtt_queue_last = temp;
  }

  char *task_type;
  parse_mqtt_type_string(temp->data.msg_type_q,&task_type);

  debug_mqtt("Task:[%s][%2.0d] adicionada a fila",task_type,(int)temp->data.id_task);
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
      debug_mqtt("Tarefa:[%2.0d] deletada",(int)mqtt_queue_first->data.id_task);
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
      debug_mqtt("[%2.0d]-%s", (int)temp->data.id_task,temp->data.long_topic);
      temp = temp->link;
      cnt++;
  }
  debug_mqtt("Tamanho da fila:[%d]\n", cnt);
}
/************************** FUNÇÕES DE FILA MQTT-SN ***************************/

void mqtt_sn_init(){
  process_start(&mqtt_sn_main, NULL);

  // Alocação de número de evento disponível para os eventos do MQTT-SN
  mqtt_connect_req = process_alloc_event();
}

PROCESS_THREAD(mqtt_sn_main, ev, data){
  PROCESS_BEGIN();

  debug_mqtt("Inicio do processo MQTT-SN");

  while(1) {
      PROCESS_WAIT_EVENT();
      /// Todo e QUALQUER temporizador deve ser SETADO nestes eventos, evitando descontrole do PC
      if (ev == mqtt_connect_req){
        debug_mqtt("Evento de CONNECT [%d]", ev);
        etimer_set(&mqtt_timeout, MQTT_SN_TIMEOUT);
      }
      else if(ev == mqtt_timeout){
        debug_mqtt("Evento de TIMEOUT [%d]", ev);

      }
  }
  PROCESS_END();
}
