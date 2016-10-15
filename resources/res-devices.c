#include "contiki.h"
#include "rest-engine.h"
#include "dev/leds.h"
#include "coap-server.h"
#include "homestark.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#if CONTIKI_TARGET_SRF06_CC26XX
#include "board-peripherals.h"
#endif

uint8_t switch_demo = 1,
        dimmer_value = 50;
uint16_t light_status = 500,
         water_level = 50;

/*********************************** SWITCH ***********************************/
static void
res_get_handler_switch(void *request, void *response, uint8_t *buffer,
                uint16_t preferred_size, int32_t *offset) {
  unsigned int accept = -1;
  REST.get_header_accept(request, &accept);

  if(accept == -1 || accept == REST.type.TEXT_PLAIN) {
    REST.set_header_content_type(response, REST.type.TEXT_PLAIN);
    snprintf((char *)buffer, REST_MAX_CHUNK_SIZE, "switch=%d", switch_demo);

    REST.set_response_payload(response, (uint8_t *)buffer, strlen((char *)buffer));
  } else if(accept == REST.type.APPLICATION_JSON) {
    REST.set_header_content_type(response, REST.type.APPLICATION_JSON);
    snprintf((char *)buffer, REST_MAX_CHUNK_SIZE, "{\"SWITCH\":\"%d\"}",
             switch_demo);

    REST.set_response_payload(response, buffer, strlen((char *)buffer));
  } else if(accept == REST.type.APPLICATION_XML) {
    REST.set_header_content_type(response, REST.type.APPLICATION_XML);
    snprintf((char *)buffer, REST_MAX_CHUNK_SIZE,
             "<switch val=\"%d\"/>", switch_demo);

    REST.set_response_payload(response, buffer, strlen((char *)buffer));
  } else {
    REST.set_response_status(response, REST.status.NOT_ACCEPTABLE);
    REST.set_response_payload(response, coap_server_supported_msg,
                              strlen(coap_server_supported_msg));
  }

}

static void
res_post_handler_switch(void *request, void *response, uint8_t *buffer,
                uint16_t preferred_size, int32_t *offset) {
  size_t len = 0;
  const char *text = NULL;
  char switch_value[10];
  memset(switch_value, 0, 10);

  len = REST.get_post_variable(request, "switch_value", &text);
  if(len > 0 && len < 10) {
    memcpy(switch_value, text, len);
  }

  switch_demo = atoi(switch_value);
}
/*********************************** SWITCH ***********************************/

/*********************************** LIGHT ************************************/
static void
res_get_handler_light(void *request, void *response, uint8_t *buffer,
                uint16_t preferred_size, int32_t *offset) {
  unsigned int accept = -1;
  REST.get_header_accept(request, &accept);

  if(accept == -1 || accept == REST.type.TEXT_PLAIN) {
    REST.set_header_content_type(response, REST.type.TEXT_PLAIN);
    snprintf((char *)buffer, REST_MAX_CHUNK_SIZE, "light=%d", light_status);

    REST.set_response_payload(response, (uint8_t *)buffer, strlen((char *)buffer));
  } else if(accept == REST.type.APPLICATION_JSON) {
    REST.set_header_content_type(response, REST.type.APPLICATION_JSON);
    snprintf((char *)buffer, REST_MAX_CHUNK_SIZE, "{\"LIGHT\":\"%d\"}",
             light_status);

    REST.set_response_payload(response, buffer, strlen((char *)buffer));
  } else if(accept == REST.type.APPLICATION_XML) {
    REST.set_header_content_type(response, REST.type.APPLICATION_XML);
    snprintf((char *)buffer, REST_MAX_CHUNK_SIZE,
             "<light val=\"%d\"/>", light_status);

    REST.set_response_payload(response, buffer, strlen((char *)buffer));
  } else {
    REST.set_response_status(response, REST.status.NOT_ACCEPTABLE);
    REST.set_response_payload(response, coap_server_supported_msg,
                              strlen(coap_server_supported_msg));
  }

}

static void
res_post_handler_light(void *request, void *response, uint8_t *buffer,
                uint16_t preferred_size, int32_t *offset) {
  size_t len = 0;
  const char *text = NULL;
  char dimmer[10];
  memset(dimmer, 0, 10);

  len = REST.get_post_variable(request, "dimmer_value", &text);
  if(len > 0 && len < 10) {
    memcpy(dimmer, text, len);
  }
  dimmer_value = atoi(dimmer);
  // switch_demo = atoi(light_value);
}
/*********************************** LIGHT ************************************/

/*********************************** WATER ************************************/
static void
res_get_handler_water(void *request, void *response, uint8_t *buffer,
                uint16_t preferred_size, int32_t *offset) {
  unsigned int accept = -1;
  REST.get_header_accept(request, &accept);

  if(accept == -1 || accept == REST.type.TEXT_PLAIN) {
    REST.set_header_content_type(response, REST.type.TEXT_PLAIN);
    snprintf((char *)buffer, REST_MAX_CHUNK_SIZE, "water=%d", water_level);

    REST.set_response_payload(response, (uint8_t *)buffer, strlen((char *)buffer));
  } else if(accept == REST.type.APPLICATION_JSON) {
    REST.set_header_content_type(response, REST.type.APPLICATION_JSON);
    snprintf((char *)buffer, REST_MAX_CHUNK_SIZE, "{\"WATER\":\"%d\"}",
             water_level);

    REST.set_response_payload(response, buffer, strlen((char *)buffer));
  } else if(accept == REST.type.APPLICATION_XML) {
    REST.set_header_content_type(response, REST.type.APPLICATION_XML);
    snprintf((char *)buffer, REST_MAX_CHUNK_SIZE,
             "<light val=\"%d\"/>", water_level);

    REST.set_response_payload(response, buffer, strlen((char *)buffer));
  } else {
    REST.set_response_status(response, REST.status.NOT_ACCEPTABLE);
    REST.set_response_payload(response, coap_server_supported_msg,
                              strlen(coap_server_supported_msg));
  }

}

/*********************************** WATER ************************************/

RESOURCE(res_switch,
         "title=\"Switch: GET or POST\";rt=\"Text\"",
         res_get_handler_switch,
         res_post_handler_switch,
         NULL,
         NULL);

RESOURCE(res_light,
         "title=\"Light: GET or POST\";rt=\"Text\"",
         res_get_handler_light,
         res_post_handler_light,
         NULL,
         NULL);

RESOURCE(res_water,
         "title=\"Water: GET or POST\";rt=\"Text\"",
         res_get_handler_water,
         NULL,
         NULL,
         NULL);
