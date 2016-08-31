/**
 * @file
 *         Conjunto de protótipos e definiçoes do protocolo MQTT-SN
 * @author
 *         Ânderson Ignácio da Silva <anderson@aignacio.com>
 */

#ifndef MQTT__SN_H
#define MQTT__SN_H

#include "simple-udp.h"
#include "clock.h"
#include "etimer.h"
#include "ctimer.h"
#include "list.h"
#include "net/ip/uip-debug.h"
#include "sys/ctimer.h"
#include <stdbool.h>

#define DEBUG_MQTT_SN
#define DEBUG_OS
#define DEBUG_TASK
//#define DEBUG_UDP
//#define DEBUG_LOGIC

#ifdef DEBUG_TASK
#define debug_task(fmt, args...) printf("\n[Tarefa] "fmt, ##args)
#else
#define debug_task(fmt, ...)
#endif


#ifdef DEBUG_LOGIC
#define debug_logic(fmt, args...) printf("\n[Logic] "fmt, ##args)
#else
#define debug_logic(fmt, ...)
#endif

#ifdef DEBUG_OS
#define debug_os(fmt, args...) printf("\n[HOMESTARK] "fmt, ##args)
#else
#define debug_os(fmt, ...)
#endif

#ifdef DEBUG_MQTT_SN
#define debug_mqtt(fmt, args...) printf("\n[MQTT-SN] "fmt, ##args)
#else
#define debug_mqtt(fmt, ...)
#endif

#ifdef DEBUG_UDP
#define debug_udp(fmt, args...) printf("\n[UDP] "fmt, ##args)
#else
#define debug_udp(fmt, ...)
#endif

#define MQTT_SN_MAX_PACKET_LENGTH  (255)
#define MQTT_SN_MAX_TOPIC_LENGTH   (MQTT_SN_MAX_PACKET_LENGTH-6)

#define MQTT_SN_TYPE_ADVERTISE     (0x00)
#define MQTT_SN_TYPE_SEARCHGW      (0x01)
#define MQTT_SN_TYPE_GWINFO        (0x02)
#define MQTT_SN_TYPE_CONNECT       (0x04)
#define MQTT_SN_TYPE_CONNACK       (0x05)
#define MQTT_SN_TYPE_WILLTOPICREQ  (0x06)
#define MQTT_SN_TYPE_WILLTOPIC     (0x07)
#define MQTT_SN_TYPE_WILLMSGREQ    (0x08)
#define MQTT_SN_TYPE_WILLMSG       (0x09)
#define MQTT_SN_TYPE_REGISTER      (0x0A)
#define MQTT_SN_TYPE_REGACK        (0x0B)
#define MQTT_SN_TYPE_PUBLISH       (0x0C)
#define MQTT_SN_TYPE_PUBACK        (0x0D)
#define MQTT_SN_TYPE_PUBCOMP       (0x0E)
#define MQTT_SN_TYPE_PUBREC        (0x0F)
#define MQTT_SN_TYPE_PUBREL        (0x10)
#define MQTT_SN_TYPE_SUBSCRIBE     (0x12)
#define MQTT_SN_TYPE_SUBACK        (0x13)
#define MQTT_SN_TYPE_UNSUBSCRIBE   (0x14)
#define MQTT_SN_TYPE_UNSUBACK      (0x15)
#define MQTT_SN_TYPE_PINGREQ       (0x16)
#define MQTT_SN_TYPE_PINGRESP      (0x17)
#define MQTT_SN_TYPE_DISCONNECT    (0x18)
#define MQTT_SN_TYPE_WILLTOPICUPD  (0x1A)
#define MQTT_SN_TYPE_WILLTOPICRESP (0x1B)
#define MQTT_SN_TYPE_WILLMSGUPD    (0x1C)
#define MQTT_SN_TYPE_WILLMSGRESP   (0x1D)
#define MQTT_SN_TYPE_SUB_WILDCARD  (0x1E)


#define MQTT_SN_TOPIC_TYPE_NORMAL     (0x00)
#define MQTT_SN_TOPIC_TYPE_PREDEFINED (0x01)
#define MQTT_SN_TOPIC_TYPE_SHORT      (0x02)

#define MQTT_SN_FLAG_DUP     (0x1 << 7)
#define MQTT_SN_FLAG_QOS_0   (0x0 << 5)
#define MQTT_SN_FLAG_QOS_1   (0x1 << 5)
#define MQTT_SN_FLAG_QOS_2   (0x2 << 5)
#define MQTT_SN_FLAG_QOS_N1  (0x3 << 5)
#define MQTT_SN_FLAG_RETAIN  (0x1 << 4)
#define MQTT_SN_FLAG_WILL    (0x1 << 3)
#define MQTT_SN_FLAG_CLEAN   (0x1 << 2)

#define MQTT_SN_PROTOCOL_ID  (0x01)

//Defines para o código de retorno
#define ACCEPTED                    0x00
#define REJECTED_CONGESTION         0x01
#define REJECTED_INVALID_TOPIC_ID   0x02
#define REJECTED_NOT_SUPPORTED      0x03

#define MQTT_SN_TOPIC_TYPE_NORMAL     (0x00)
#define MQTT_SN_TOPIC_TYPE_PREDEFINED (0x01)
#define MQTT_SN_TOPIC_TYPE_SHORT      (0x02)

#define ss(x) sizeof(x)/sizeof(*x)  // Computa o tamanho de um vetor de ponteiros

/******************************************************************************/
// Macros de controle
#define MQTT_SN_AUTO_RECONNECT                       /// \brief Define se o dispositivo deve se auto conectar de tempos em tempos
#define MQTT_SN_RETRY_PING        5                  /// \brief Número de tentativas de envio de PING REQUEST antes de desconectar nó <-> broker
#define MQTT_SN_TIMEOUT_CONNECT   9*CLOCK_SECOND     /// \brief Tempo base para comunicação MQTT-SN broker <-> nó
#define MQTT_SN_TIMEOUT           CLOCK_SECOND       /// \brief Tempo base para comunicação MQTT-SN broker <-> nó
#define MQTT_SN_RETRY             5                  /// \brief Número de tentativas de enviar qualquer pacote ao broker antes de desconectar
#define MAX_QUEUE_MQTT_SN         100                /// \briefNúmero máximo de tarefas a serem inseridas alocadas dinamicamente MQTT-SN
#define MAX_TOPIC_USED            100                /// \brief Número máximo de tópicos que o usuário pode registrar, a API cria um conjunto de
                                                     /// estruturas para o bind de topic e short topic id
/******************************************************************************/

typedef struct __attribute__((packed)){
  uint8_t length;
  uint8_t  msg_type;
  uint16_t duration;
} disconnect_packet_t;

typedef struct {
  uint8_t length;
  uint8_t  msg_type;
  char client_id[23];
} ping_req_t;

/** @struct mqtt_sn_task_t
 *  @brief Estrutura de tarefa de fila MQTT-SN
 *  @var mqtt_sn_task_t::msg_type_q
 *    Tipo de mensagem a ser alocada
 *  @var mqtt_sn_task_t::short_topic
 *    Tópico curto a ser publicado/inscrito
 *  @var mqtt_sn_task_t::long_topic
 *    Tópico longo a ser publicado/inscrito
 *  @var mqtt_sn_task_t::message
 *    Mensagem correspondente da tarefa
 *  @var mqtt_sn_task_t::id_queue
 *    Identificador da tarefa
 */
typedef struct {
  uint8_t  msg_type_q;
  uint8_t  short_topic;
  uint16_t id_task;
  uint8_t  qos_level;
  uint8_t  retain;
} mqtt_sn_task_t;

/** @struct node
 *  @brief Estrutura de fila MQTT-SN
 *  @var data
 *    Tarefa a ser processada
 *  @var link
 *    link para a próxima tarefa
 */
struct node {
    mqtt_sn_task_t data;
    struct node *link;
}*mqtt_queue_first, *mqtt_queue_last;

/*---------------------------------------------------------------------------*/
// Estruturas de controle de pacotes

/** @struct publish_packet_t
 *  @brief Estrutura de pacote do tipo PUBLISH
 *    Identificador da tarefa
 */
typedef struct __attribute__((packed)){
  uint8_t length;
  uint8_t type;
  uint8_t flags;
  uint16_t topic_id;
  uint16_t message_id;
  char data[MQTT_SN_MAX_PACKET_LENGTH-7];
} publish_packet_t;


typedef struct __attribute__((packed)) {
  uint8_t length;
  uint8_t type;
  uint8_t flags;
  uint16_t message_id;
  char topic_name[MQTT_SN_MAX_TOPIC_LENGTH];
} subscribe_wildcard_packet_t;

typedef struct __attribute__((packed)) {
  uint8_t length;
  uint8_t type;
  uint8_t flags;
  uint16_t message_id;
  uint16_t topic_id;
} subscribe_packet_t;

/** @struct connect_packet_t
 *  @brief Estrutura de pacotes MQTT-SN do tipo CONNECT
 *  @var connect_packet_t::length
 *    Comprimento total do pacote MQTT-SN
 *  @var connect_packet_t::type
 *    Descreve o tipo de mensagem que será enviado ao broker
 *  @var connect_packet_t::flags
 *    Contém os parâmetros de flag que serão enviados como (DUP,QoS,Retain,Will,
 *    CleanSession, TopicType)
 *  @var connect_packet_t::protocol_id
 *    Presente somente no CONNECT indicando versão do protocolo e o nome
 *  @var connect_packet_t::duration
 *    Indica a duração de um período em segundos podendo ser de até 18 Horas
 */
typedef struct __attribute__((packed)) {
  uint8_t length;
  uint8_t type;
  uint8_t flags;
  uint8_t protocol_id;
  uint16_t duration;
  char client_id[23];
} connect_packet_t;

/** @struct register_packet_t
 *  @brief Estrutura de pacotes MQTT-SN do tipo REGISTER
 *  @var register_packet_t::length
 *    Comprimento total do pacote MQTT-SN
 *  @var register_packet_t::type
 *    Descreve o tipo de mensagem que será enviado ao broker
 *  @var register_packet_t::topic_id
 *    Short Topic que será utilizado para envio do REGISTER - Quando enviado pelo nó, usa-se 0x0000
 *  @var register_packet_t::message_id
 *    Identificador único do REGACK correspondente enviado pelo broker normalmente
 *  @var register_packet_t::topic_name
 *    Nome do tópico a ser registrado
 */
typedef struct __attribute__((packed)){
  uint8_t length;
  uint8_t type;
  uint16_t topic_id;
  uint16_t message_id;
  char topic_name[MQTT_SN_MAX_TOPIC_LENGTH];
} register_packet_t;


typedef struct __attribute__((packed)){
  uint8_t length;
  uint8_t type;
  uint16_t topic_id;
  uint16_t message_id;
  uint8_t return_code;
} regack_packet_t;

/*---------------------------------------------------------------------------*/

/** @typedef resp_con_t
 *  @brief Tipo de erros de funções
 *  @var SUCCESS_CON::FAIL_CON
 *    Erro ao processar algo
 *  @var SUCCESS_CON::SUCCESS_CON
 *    Sucesso ao processar algo
 *  @todo Implementar mais tipos de erros
 */
typedef enum resp_con{
   FAIL_CON,
   SUCCESS_CON,
} resp_con_t;

/** @typedef short_topics_t
 *  @brief Estrutura para controle de tópicos e tópicos curtos
 */
typedef struct {
   char *topic_name;
   uint8_t short_topic_id;
   uint8_t subscribed;
} short_topics_t;

/** @typedef mqtt_sn_status_t
*  @brief Estados da ASM do MQTT-SN
*/
typedef enum {
  MQTTSN_CONNECTION_FAILED,
  MQTTSN_DISCONNECTED,
  MQTTSN_WAITING_CONNACK,
  MQTTSN_WAITING_REGACK,
  MQTTSN_CONNECTED,
  MQTTSN_TOPIC_REGISTERED,
  MQTTSN_TOPIC_SUBSCRIBING,
  MQTTSN_WAITING_PUBACK,
  MQTTSN_WAITING_SUBACK,
  MQTTSN_PUB_REQ,
  MQTTSN_SUB_REQ,
  MQTTSN_REG_REQ
} mqtt_sn_status_t;

/** @struct mqtt_sn_con_t
 *  @brief Estrutura de conexão ao broker MQTT-SN
 *  @var mqtt_sn_con_t::simple_udp_connection
 *    Handle da conexão UDP com o broker
 *  @var mqtt_sn_con_t::udp_port
 *    Porta UDP de conexão com o broker (default:1884)
 *  @var mqtt_sn_con_t::ipv6_broker
 *    Endereço IPv6 do broker UDP
 *  @var mqtt_sn_con_t::keep_alive
 *    Tempo de requisição Keep Alive para PINGREQ e PINGRESP
 *  @var mqtt_sn_con_t::client_id
 *    Identificador de cliente para conexão com o broker MQTT-SN
 */
typedef struct {
  struct simple_udp_connection udp_con;
  uint16_t udp_port;
  uint16_t *ipv6_broker;
  uint8_t  keep_alive;
  const char* client_id;
} mqtt_sn_con_t;

/** @brief Insere uma tarefa na fila
 *
 * 		Insere uma nova tarefa na fila de requisições a serem processadas.
 *
 *  @param [in] new Nova tarefa a ser processada pela ASM do MQTT-SN
 *
 *  @retval FAIL_CON         Não foi possível alocar uma nova tarefa a fila
 *  @retval SUCCESS_CON      Foi possível alocar uma nova tarefa a fila
 *
 * 	@todo		Melhorar alocação dinâmica de memória
 **/
resp_con_t mqtt_sn_insert_queue(mqtt_sn_task_t new);

/** @brief Remove o elemento mais próximo de ser processado
 *
 * 		Realiza a remoção do elemento mais próximo de ser processado, no caso o
 *    mais antigo inserido na fila
 *
 *  @param [in] 0 Não recebe argumento
 *
 *  @retval 0 Não retorna nada
 *
 * 	@todo	Adicionar opção de exclusão intermediária
 **/
void mqtt_sn_delete_queue();

/** @brief Lista as tarefas da fila
 *
 * 		Percorre os links dos ponteiros listando os elementos a serem
 *    processados pela ASM do MQTT-SN
 *
 *  @param [in] 0 Não recebe argumento
 *
 *  @retval 0 Não retorna nada
 *
 **/
void mqtt_sn_check_queue();

/** @brief Envia requisição de conexão ao broker MQTT-SN
 *
 * 		Realiza o envio de mensagens do tipo CONNECT ao broker MQTT-SN
 *
 *  @param [in] rc Código de retorno da requisição MQTT (Return Code)
 *
 *  @retval FAIL_CON      Falha por algum motivo no código de retorno
 *  @retval SUCCESS_CON   Sucesso no recebimento do código de retorno
 *
 * 	@todo		Expandir o tipo de falha para tornar mais precisa a depuração
 *          futura
 **/
resp_con_t mqtt_sn_check_rc(uint8_t rc);

/** @brief Controla o estado da conexão MQTT-SN
 *
 * 		A partir do status de conexão MQTT-SN gerencia as requisições
 *    atribuindo temporizadores de envio de mensagens conforme a
 *    estrutura alocada na fila.
 *
 *  @param [in] 0 Não recebe argumento
 *
 *  @retval 0 Não retorna nada
 **/
// void mqtt_sn_state_ctrl();

/** @brief Realiza o parsing das mensagens UDP recebidas
 *
 * 		Realiza o parsing das mensagens UDP recebidas de acordo com
 *    o protocolo MQTT-SN, alterando o status da conexão geral com
 *    o broker.
 *
 *  @param [in] data Ponteiro para o conteúdo UDP recebido
 *
 *  @retval 0 Não retorna nada
 **/
void mqtt_sn_recv_parser(const uint8_t *data);

/** @brief Inicia conexão ao broker UDP
 *
 * 		Estabelece a conexão com um servidor MQTT-SN, através
 *    da porta 1884 além de iniciar a fila
 *    de processos de conexão do protocolo.
 *
 *  @param [in] mqtt_sn_connection Estrutura padrão de comunicação MQTT-SN
 *
 *  @retval FAIL_CON      Falha ao alocar conexão UDP
 *  @retval SUCCESS_CON   Sucesso ao alocar conexão UDP
 *
 * 	@todo		Descobrir como informar se o broker esta ativo antes de realizar
 *          o registro da conexão UDP, pois a função de conexão não informa
 **/
resp_con_t mqtt_sn_create_sck(mqtt_sn_con_t mqtt_sn_connection, char *topics[],size_t topic_len);

/** @brief Envio de mensagens ao broker do tipo REGISTER
 *
 * 		Envia ao broker mensagens do tipo REGISTER com o topic name informado conforme a tarefa
 *    primeira na fila
 *
 *  @param [in] 0 Não recebe parâmetro
 *
 *  @retval FAIL_CON      Falha ao enviar o pacote REGISTER
 *  @retval SUCCESS_CON   Sucesso ao enviar o pacote REGISTER
 *
 **/
resp_con_t mqtt_sn_reg_send(void);

/** @brief Envia requisição de conexão ao broker MQTT-SN
 *
 * 		Realiza o envio de mensagens do tipo CONNECT ao broker MQTT-SN
 *
 *  @param [in] 0 Não recebe argumento
 *
 *  @retval FAIL_CON      Falha ao enviar o pacote CONNECT
 *  @retval SUCCESS_CON   Sucesso ao enviar o pacote CONNECT
 *
 **/
mqtt_sn_status_t mqtt_sn_check_status(void);

resp_con_t mqtt_sn_con_send(void);

//void mqtt_sn_pub(char *topic,char *message, bool retain_flag, uint8_t qos_level);

bool mqtt_sn_check_empty(void);

void parse_mqtt_type_string(uint8_t type, char **type_string);

void mqtt_sn_init(void);

resp_con_t mqtt_sn_pub_send(char *topic,char *message, bool retain_flag, uint8_t qos);

char* mqtt_sn_check_status_string(void);

uint8_t mqtt_sn_get_qos_flag(int8_t qos);

resp_con_t mqtt_sn_regack_send(uint16_t msg_id, uint16_t topic_id);

void print_g_topics(void);

resp_con_t mqtt_sn_pub(char *topic,char *message, bool retain_flag, uint8_t qos);

void timeout_con(void *ptr);

void timeout_ping_mqtt(void *ptr);

void mqtt_sn_ping_send(void);

bool unlock_tasks(void);

resp_con_t mqtt_sn_sub(char *topic, uint8_t qos);

resp_con_t mqtt_sn_sub_send(char *topic, uint8_t qos);

resp_con_t mqtt_sn_sub_send_wildcard(char *topic, uint8_t qos);

resp_con_t verf_hist_sub(char *topic);

void init_vectors(void);

void init_sub(void *ptr);

resp_con_t verf_register(char *topic);

resp_con_t mqtt_sn_disconnect(uint16_t duration);
/** @brief Realiza o registro de uma publicação
 *
 * 		Cria uma tarefa de publicação que envia ao broker a mensagem
 *    de publicação MQTT-SN no tópico especificado
 *
 *  @param [in] topic       Tópico MQTT a ser publicado
 *  @param [in] message     Mensagem MQTT a ser publicada
 *  @param [in] retain_flag Flag para identificação de retentividade
 *  @param [in] qos_level   Nível QoS da publicação
 *
 *  @retval 0 Não retorna nada
 *
 **/
// void mqtt_sn_pub_task(char *topic, char *message, bool retain_flag, uint8_t *qos_level);

/** @brief Realiza o envio de publicação
 *
 * 		Realiza o envio de uma mensagem do tipo PUBLISH
 *
 *  @param [in] 0 Não recebe parâmetro
 *
 *  @retval 0 Não retorna nada
 *
 **/
// void mqtt_sn_pub_send(void);

//uint8_t mqtt_sn_get_qos_flag(int8_t qos);
#endif
