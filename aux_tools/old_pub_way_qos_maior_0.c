else if(etimer_expired(&mqtt_time_publish_qos_0) &&
        mqtt_queue_first->data.msg_type_q == MQTT_SN_TYPE_PUBLISH){
  g_tries_send++;
  if (g_tries_send >= MQTT_SN_RETRY) {
    if (etimer_pending())
      etimer_stop(&mqtt_time_publish_qos_0);
    g_tries_send = 0;
    mqtt_status = MQTTSN_DISCONNECTED;
    debug_mqtt("Limite maximo de pacotes PUBLISH");
  }
  else{
    mqtt_sn_pub_send();
    // mqtt_status = MQTTSN_WAITING_PUBACK;
    etimer_reset(&mqtt_time_publish_qos_0);
  }
}
else if(ev == mqtt_event_puback){
  mqtt_sn_delete_queue(); // Deleta requisição de PUBLISH
  g_tries_send = 0;
  if (mqtt_sn_check_empty()) {
    mqtt_status = MQTTSN_CONNECTED; // Volta ao estado padrão da ASM
    debug_mqtt("Processos concluidos");
    if (etimer_pending())
      etimer_stop(&mqtt_time_publish_qos_0);
  }
  else
    process_post(&mqtt_sn_main, mqtt_event_run_task, NULL); // Inicia outras tasks caso a fila não esteja vazia
}
