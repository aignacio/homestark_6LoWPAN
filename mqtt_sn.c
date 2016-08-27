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
#include "net/ipv6/uip-ds6.h"

static struct etimer              mqtt_time_connect;       // Estrutura de temporização para envio de CONNECT
static struct etimer              mqtt_time_register;      // Estrutura de temporização para envio de REGISTER

static process_event_t            mqtt_event_connect;    // Evento de req CONNECT  [nó --> broker]
static process_event_t            mqtt_event_connack;    // Evento de req CONNACK  [broker --> nó]
static process_event_t            mqtt_event_register;   // Evento de req REGISTER [nó --> broker]
static process_event_t            mqtt_event_regack;     // Evento de req REGACK   [broker --> nó]
static process_event_t            mqtt_event_pub_qos_0;  // Evento de req PUBLISH - QoS - 0 [nó --> broker]
static process_event_t            mqtt_event_run_task;   // Evento de req qualquer, seja PUBLISH ou SUBSCRIBE [nó --> broker]
// Comentado por enquanto já que QoS - 0 não envia PUBACK
// static process_event_t            mqtt_event_puback;     // Evento de req PUBACK   [broker --> nó]

static uint16_t                   g_tries_send = 0;                  // Identificador de tentativas de envio
static uint16_t                   g_task_id = 0;                     // Identificador unitário de tarefa incremental
static short_topics_t             g_topic_bind[MAX_TOPIC_USED];      // Vetor que armazena a relação nome do tópico com short topic id
static mqtt_sn_con_t              g_mqtt_sn_con;                     // Estrutura principal da conexão MQTT
static mqtt_sn_status_t           mqtt_status = MQTTSN_DISCONNECTED; // ASM principal do MQTT-SN

PROCESS(mqtt_sn_main, "[MQTT-SN] Processo inicial");

/*********************** FUNÇÕES AUXILIARES MQTT-SN ***************************/
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

mqtt_sn_status_t mqtt_sn_check_status(void){
  return mqtt_status;
}

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

uint8_t mqtt_sn_get_qos_flag(int8_t qos){
    switch (qos) {
        case -1:
          return MQTT_SN_FLAG_QOS_N1;
        case 0:
          return MQTT_SN_FLAG_QOS_0;
        case 1:
          return MQTT_SN_FLAG_QOS_1;
        case 2:
          return MQTT_SN_FLAG_QOS_2;
        default:
          return 0;
    }
}

void mqtt_sn_pub(char *topic,char *message, bool retain_flag, uint8_t qos){
  mqtt_sn_task_t publish_task;

  size_t i = 0;
  for (i=0; i < g_task_id; i++)
    if (strcmp(g_topic_bind[i].topic_name,topic) == 0) {
      publish_task.short_topic = g_topic_bind[i].short_topic_id;
      break;
    }

  publish_task.msg_type_q = MQTT_SN_TYPE_PUBLISH;
  publish_task.long_topic = topic;
  publish_task.message    = message;
  publish_task.qos_level  = qos;
  publish_task.retain     = retain_flag;

  // Os campos não preenchidos na estrutura (mqtt_sn_task_t) serão preenchidos
  // pela própria função de adição na fila
  if (!mqtt_sn_insert_queue(publish_task))
    debug_mqtt("ERRO AO ADICIONAR NA FILA");

  process_post(&mqtt_sn_main, mqtt_event_run_task, NULL);
}

/******************** FUNÇÕES DE ENVIO DE PACOTES MQTT-SN *********************/
resp_con_t mqtt_sn_con_send(void){
  connect_packet_t packet;

  // Criação do pacote CONNECT
  packet.type = MQTT_SN_TYPE_CONNECT;
  packet.flags = MQTT_SN_FLAG_CLEAN;
  packet.protocol_id = MQTT_SN_PROTOCOL_ID;
  packet.duration = uip_htons(g_mqtt_sn_con.keep_alive); //Realiza a conversão para network byte order

  strncpy(packet.client_id, g_mqtt_sn_con.client_id, strlen(g_mqtt_sn_con.client_id));
  packet.client_id[strlen(g_mqtt_sn_con.client_id)] = '\0';
  packet.length = 0x06 + strlen(packet.client_id);

  // debug_mqtt("CLIENT_ID:%s, Tamanho:%d",packet.client_id,strlen(packet.client_id));
  debug_mqtt("Enviando o pacote @CONNECT ");
  simple_udp_send(&g_mqtt_sn_con.udp_con,&packet, packet.length);
  // debug_mqtt("enviado!");
  return SUCCESS_CON;
}

resp_con_t mqtt_sn_reg_send(void){
  register_packet_t packet;

  size_t topic_name_len = strlen(mqtt_queue_first->data.long_topic); //Pega o primeiro da fila aguardando

  if (topic_name_len > MQTT_SN_MAX_TOPIC_LENGTH) {
    debug_mqtt("Erro: Nome do topico excede o limite maximo");
    return FAIL_CON;
  }

  if (mqtt_queue_first->data.msg_type_q != MQTT_SN_TYPE_REGISTER) {
    debug_mqtt("Erro: Pacote a processar nao e do tipo REGISTER");
    return FAIL_CON;
  }

  packet.type = MQTT_SN_TYPE_REGISTER;
  packet.topic_id = 0x0000;

  // Quando o broker responder com o short topic ID,
  // ele utilizará como message id, o identificador único da task na
  // queue de serviços do MQTT-SN, logo se torna fácil saber como montar
  // a relação (short_topic/long_topic) no vetor global g_topic_bind[]
  packet.message_id = uip_htons((int)mqtt_queue_first->data.id_task);

  strncpy(packet.topic_name, mqtt_queue_first->data.long_topic, topic_name_len);
  packet.length = 0x06 + topic_name_len;
  packet.topic_name[topic_name_len] = '\0';

  // debug_mqtt("Topico a registrar:%s [%d][MSG_ID:%d]",packet.topic_name,strlen(packet.topic_name),(int)mqtt_queue_first->data.id_task);
  debug_mqtt("Enviando o pacote @REGISTER");
  simple_udp_send(&g_mqtt_sn_con.udp_con,&packet, packet.length);

  return SUCCESS_CON;
}

resp_con_t mqtt_sn_pub_send(void){
  publish_packet_t packet;
  size_t i = 0;
  uint16_t stopic = 0x0000;
  uint8_t data_len = strlen(mqtt_queue_first->data.message);

  if (mqtt_queue_first->data.msg_type_q != MQTT_SN_TYPE_PUBLISH) {
    debug_mqtt("Erro: Pacote a processar nao e do tipo PUBLISH");
    return FAIL_CON;
  }

  if (data_len > sizeof(packet.data)) {
      printf("Erro: Payload e muito grande!\n");
      return FAIL_CON;
  }

  for (i=0; i < g_task_id; i++)
    if (strcmp(g_topic_bind[i].topic_name,mqtt_queue_first->data.long_topic) == 0) {
      stopic = g_topic_bind[i].short_topic_id;
      break;
    }

  packet.type  = MQTT_SN_TYPE_PUBLISH;
  packet.flags = 0x00;

  if (mqtt_queue_first->data.retain)
    packet.flags += MQTT_SN_FLAG_RETAIN;

  packet.flags += mqtt_sn_get_qos_flag(mqtt_queue_first->data.qos_level);

  // Segundo a especificação:
  // TopicIdType: indicates whether the field TopicId or TopicName included in this message contains a normal
  // topic id (set to “0b00”), a pre-defined topic id (set to “0b01”), or a short topic name (set to “0b10”). The
  // value “0b11” is reserved. Refer to sections 3 and 6.7 for the definition of the various types of topic ids.
  packet.flags += MQTT_SN_TOPIC_TYPE_NORMAL; //Utiliza-se o topic id já registrado

  packet.topic_id = uip_htons(stopic);
  packet.message_id = uip_htons(0x00); //Relevante somente se QoS > 0
  strncpy(packet.data, mqtt_queue_first->data.message, data_len+1);
  //
  //  Pacote PUBLISH
  //  _________________ ______________________ ___________ ________________ ______________ ________________
  // | Comprimento - 0 | Tipo de mensagem - 1 | Flags - 2 | Topic ID - 3,4 | Msg ID - 5,6 | Dado - 7,n ....|
  // |_________________|______________________|___________ ________________|______________|________________|
  //
  packet.length = 0x07 + (data_len+1);

  // debug_mqtt("Enviando o pacote @PUBLISH");
  // debug_mqtt("Enviando o pacote @PUBLISH - Task:[%d]",(int)mqtt_queue_first->data.id_task);
  simple_udp_send(&g_mqtt_sn_con.udp_con,&packet, packet.length);
  return SUCCESS_CON;
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
  temp->data.retain      = new.retain;
  temp->data.qos_level   = new.qos_level;

  temp->data.id_task     = (uint16_t *)g_task_id;

  if (temp->data.msg_type_q == MQTT_SN_TYPE_REGISTER)
    g_task_id++;


  temp->link = NULL;
  if (mqtt_queue_last  ==  NULL) {
      mqtt_queue_first = mqtt_queue_last = temp;
  }
  else {
      mqtt_queue_last->link = temp;
      mqtt_queue_last = temp;
  }

  // char *task_type,*task_type_2;
  // parse_mqtt_type_string(mqtt_queue_first->data.msg_type_q,&task_type_2);
  // debug_mqtt("Task principal:[%2.0d][%s]",(int)mqtt_queue_first->data.id_task,task_type_2);

  // parse_mqtt_type_string(temp->data.msg_type_q,&task_type);
  // debug_mqtt("Task adicionada:[%2.0d][%s]",(int)temp->data.id_task, task_type);
  return SUCCESS_CON;
}

void mqtt_sn_delete_queue(void){
  struct node *temp;

  temp = mqtt_queue_first;
  if (mqtt_queue_first->link == NULL) {
      // debug_mqtt("Task info: Fila vazia");
      mqtt_queue_first = mqtt_queue_last = NULL;
  }
  else {
      char *task_type;
      parse_mqtt_type_string(mqtt_queue_first->data.msg_type_q,&task_type);
      // debug_mqtt("Task removida:[%2.0d][%s]",(int)mqtt_queue_first->data.id_task,task_type);
      mqtt_queue_first = mqtt_queue_first->link;
      free(temp);
  }

  char *task_type_2;
  parse_mqtt_type_string(mqtt_queue_first->data.msg_type_q,&task_type_2);
  // debug_mqtt("Task principal:[%2.0d][%s]",(int)mqtt_queue_first->data.id_task,task_type_2);

}

void mqtt_sn_check_queue(void){
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

bool mqtt_sn_check_empty(void){
  if (mqtt_queue_first  ==  NULL)
    return true;
  else
    return false;
}

/************** FUNÇÕES DE GERENCIMENTO DE CONEXÃO MQTT-SN ********************/
void mqtt_sn_recv_parser(const uint8_t *data){
    uint8_t msg_type = data[1],
            return_code = 0xFF,
            short_topic;
    size_t i = 0;

    // Como o MsgType não se altera de posição, testamos primeiro ele antes do
    // returning code, já que este pode variar
    switch (msg_type) {
      case MQTT_SN_TYPE_CONNACK:
        return_code = data[2]; //No caso do CONNACK - RC[2]
        if (mqtt_sn_check_rc(return_code))
          if (mqtt_queue_first->data.msg_type_q == MQTT_SN_TYPE_CONNECT)
            process_post(&mqtt_sn_main, mqtt_event_connack, NULL);
      break;
      case MQTT_SN_TYPE_REGACK:
        return_code = data[6]; //No caso do REGACK - RC[6]
        short_topic = data[3];
        // Na verdade os bytes de short topic são o [2] e [3], porém
        // só estamos usa-se o [3] porque não consideramos mais do que
        // 15 tópicos
        /// @todo Rever o short topic para adequar bytes [2][3] juntos
        if (mqtt_sn_check_rc(return_code)){
          for (i = 0;i < g_task_id; i++) { //Compara o byte menor do MSG ID para atribuir o short topic a requisição REGISTER correta
            if (i == data[5]){
              // debug_mqtt("RECEBIDO REGACK:\nMSG_ID:%d TOPIC_ID:%d",data[5],short_topic);
              g_topic_bind[i].short_topic_id = short_topic;
            }
          }
          process_post(&mqtt_sn_main, mqtt_event_regack, NULL);
        }
      break;
      case MQTT_SN_TYPE_PUBACK:
        // return_code = data[6]; //No caso do PUBACK - RC[6]
        // short_topic = data[3];
        // // Na verdade os bytes de short topic são o [2] e [3], porém
        // // só estamos usa-se o [3] porque não consideramos mais do que
        // // 15 tópicos
        // /// @todo Rever o short topic para adequar bytes [2][3] juntos
        //
        // /// @TODO Implementar verificação de message ID e short topic ID para melhorar a confiança do recebimento
        // if (mqtt_sn_check_rc(return_code))
        //   if (mqtt_queue_first->data.msg_type_q == MQTT_SN_TYPE_PUBLISH)
        //     process_post(&mqtt_sn_main, mqtt_event_puback, NULL);
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

resp_con_t mqtt_sn_create_sck(mqtt_sn_con_t mqtt_sn_connection, char *topics[], size_t topic_len){
  static uip_ipaddr_t broker_addr;
  static uint8_t con_udp_status = 0;

  g_mqtt_sn_con = mqtt_sn_connection;
  uip_ip6addr(&broker_addr, *g_mqtt_sn_con.ipv6_broker,
                            *(g_mqtt_sn_con.ipv6_broker+1),
                            *(g_mqtt_sn_con.ipv6_broker+2),
                            *(g_mqtt_sn_con.ipv6_broker+3),
                            *(g_mqtt_sn_con.ipv6_broker+4),
                            *(g_mqtt_sn_con.ipv6_broker+5),
                            *(g_mqtt_sn_con.ipv6_broker+6),
                            *(g_mqtt_sn_con.ipv6_broker+7));

  if (strlen(g_mqtt_sn_con.client_id) > 23){
    debug_logic("Cli. ID SIZE:%d > 23!",strlen(g_mqtt_sn_con.client_id));
    return FAIL_CON;
  }

  debug_mqtt("Endereco do broker IPv6: ");
  uip_debug_ipaddr_print(&broker_addr);
  debug_mqtt("Endereco da porta:%d ",g_mqtt_sn_con.udp_port);
  debug_mqtt("Client ID:%s/%d",g_mqtt_sn_con.client_id,strlen(g_mqtt_sn_con.client_id));


  con_udp_status = simple_udp_register(&g_mqtt_sn_con.udp_con,
                                        g_mqtt_sn_con.udp_port,
                                        &broker_addr,
                                        g_mqtt_sn_con.udp_port,
                                        mqtt_sn_udp_rec_cb);
  if(!con_udp_status)
    return FAIL_CON;

  /****************************************************************************/
  // Criando tarefa de [CONNECT]
  //
  // Inicialmente precisamos enviar a requisição de CONNECT ao broker MQTT-SN pa
  // ra que seja possível qualquer outra operação.
  mqtt_sn_task_t connect_task;

  connect_task.msg_type_q = MQTT_SN_TYPE_CONNECT;
  mqtt_sn_insert_queue(connect_task);
  /****************************************************************************/

  /****************************************************************************/
  // Criando tarefas de [REGISTER]
  //
  // Para cada tópico definido pelo usuário no código principal.Inicia-se o pro
  // cesso de preenchimento de tarefas na fila de serviços MQT-SN.
  // Primeiro antes de qualquer processo MQTT-SN registra-se todos os tópicos in
  // formados pelo usuário, otimizando as funções de inscrição e publicação, o
  // broker irá então responder com os respectivos SHORT TOPIC para utilizarmos.
  mqtt_sn_task_t topic_reg;

  size_t i;
  for(i = 0; i < topic_len; i++){
    g_topic_bind[g_task_id].topic_name = topics[i];
    topic_reg.msg_type_q = MQTT_SN_TYPE_REGISTER;
    topic_reg.long_topic = topics[i];
    if (!mqtt_sn_insert_queue(topic_reg)) break;
  }
  /****************************************************************************/

  process_post(&mqtt_sn_main, mqtt_event_connect, NULL);

  return SUCCESS_CON;
}

void mqtt_sn_init(void){
  process_start(&mqtt_sn_main, NULL);

  // Alocação de número de evento disponível para os eventos do MQTT-SN
  mqtt_event_connect   = process_alloc_event();
  mqtt_event_connack   = process_alloc_event();
  mqtt_event_register  = process_alloc_event();
  mqtt_event_regack    = process_alloc_event();
  mqtt_event_run_task  = process_alloc_event();
  mqtt_event_pub_qos_0 = process_alloc_event();
  // mqtt_event_puback   = process_alloc_event();

}

PROCESS_THREAD(mqtt_sn_main, ev, data){
  PROCESS_BEGIN();

  debug_mqtt("Inicio do processo MQTT-SN");

  while(1) {
      PROCESS_WAIT_EVENT();
      /*************************** CONNECT MQTT-SN ****************************/
      if (ev == mqtt_event_connect){
        mqtt_sn_con_send();
        mqtt_status = MQTTSN_WAITING_CONNACK;
        etimer_set(&mqtt_time_connect, 8*MQTT_SN_TIMEOUT);
      }
      else if(etimer_expired(&mqtt_time_connect) &&
              mqtt_queue_first->data.msg_type_q == MQTT_SN_TYPE_CONNECT){
        g_tries_send++;
        if (g_tries_send >= MQTT_SN_RETRY) {
          if (etimer_pending())
            etimer_stop(&mqtt_time_connect);
          g_tries_send = 0;
          mqtt_status = MQTTSN_DISCONNECTED;
          debug_mqtt("Limite maximo de pacotes CONNECT");
        }
        else{
          mqtt_sn_con_send();
          mqtt_status = MQTTSN_WAITING_CONNACK;
          etimer_reset(&mqtt_time_connect);
        }
      }
      else if(ev == mqtt_event_connack){
        g_tries_send = 0;
        mqtt_status = MQTTSN_CONNECTED;
        debug_mqtt("Conectado ao broker MQTT-SN");
        if (etimer_pending())
          etimer_stop(&mqtt_time_connect);
        mqtt_sn_delete_queue(); // Deleta requisição de CONNECT já que estamos conectados;
        process_post(&mqtt_sn_main, mqtt_event_register, NULL);
      }

      /*************************** REGISTER MQTT-SN ***************************/
      else if(ev == mqtt_event_register){
        mqtt_sn_reg_send();
        mqtt_status = MQTTSN_WAITING_REGACK;
        etimer_set(&mqtt_time_register, MQTT_SN_TIMEOUT);
      }
      else if(etimer_expired(&mqtt_time_register) &&
              mqtt_queue_first->data.msg_type_q == MQTT_SN_TYPE_REGISTER){
        g_tries_send++;
        if (g_tries_send >= MQTT_SN_RETRY) {
          if (etimer_pending())
            etimer_stop(&mqtt_time_register);
          g_tries_send = 0;
          mqtt_status = MQTTSN_DISCONNECTED;
          debug_mqtt("Limite maximo de pacotes REGISTER");
        }
        else{
          mqtt_sn_reg_send();
          mqtt_status = MQTTSN_WAITING_REGACK;
          etimer_reset(&mqtt_time_register);
        }
      }
      else if(ev == mqtt_event_regack){
        mqtt_sn_delete_queue(); // Deleta requisição de REGISTER
        g_tries_send = 0;
        if (mqtt_sn_check_empty()) {
          mqtt_status = MQTTSN_CONNECTED; // Volta ao estado padrão da ASM
          //debug_mqtt("Tópicos registrados com sucesso");
          // size_t i = 0;
          // for (i=0; i < g_task_id; i++)
          //    debug_mqtt("ID:[%d] Short:[%d] Topico:%s",i,(int)g_topic_bind[i].short_topic_id,g_topic_bind[i].topic_name);
          // debug_mqtt("...");
          if (etimer_pending())
            etimer_stop(&mqtt_time_register);
        }
        else{
          process_post(&mqtt_sn_main, mqtt_event_register, NULL); // Inicia o processo de registro de tópicos novamente
        }
      }

      /*************************** RUN TASKS MQTT-SN **************************/
      else if(ev == mqtt_event_run_task){
        switch (mqtt_queue_first->data.msg_type_q) {
          case MQTT_SN_TYPE_CONNECT:
          break;
          case MQTT_SN_TYPE_PUBLISH:
            process_post(&mqtt_sn_main, mqtt_event_pub_qos_0, NULL);
          break;
          case MQTT_SN_TYPE_SUBSCRIBE:
          break;
          case MQTT_SN_TYPE_REGISTER:
          break;
        }
      }

      /********************** PUBLISH QoS 0 - MQTT-SN *************************/
      else if((ev == mqtt_event_pub_qos_0) &&
              mqtt_queue_first->data.msg_type_q == MQTT_SN_TYPE_PUBLISH){
        mqtt_sn_pub_send();
        mqtt_sn_delete_queue(); // Deleta requisição de PUBLISH
        if (!mqtt_sn_check_empty())
          process_post(&mqtt_sn_main, mqtt_event_run_task, NULL); // Inicia outras tasks caso a fila não esteja vazia
      }
  }
  PROCESS_END();
}
