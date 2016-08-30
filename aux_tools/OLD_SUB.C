// Testa para ver se estaremos registrando alguma wildcard
if (strstr(topic,"#") || strstr(topic,"+")) {
  debug_mqtt("Topico de inscricao com WILDCARD");
  // mqtt_sn_task_t subscribe_task;
  if (strcmp(topic,topic_temp_wildcard) == 0) {
    debug_mqtt("Topico WILDCARD ja inscrito!");
    return SUCCESS_CON;
  }
  mqtt_sn_sub_send_wildcard(topic,qos);
  topic_temp_wildcard = topic;
  return SUCCESS_CON;
}

// Analisamos o buffer de tópicos registrados para ver se já foi registrado o tópico
size_t i = 0;
for (i=0; i < MAX_TOPIC_USED; i++){
  if (strcmp(g_topic_bind[i].topic_name,topic) == 0){
    registered_topic = true;
    break;
  }
  if (g_topic_bind[i].short_topic_id == 0xFF)
    break;
}

if (registered_topic){ //Tópico existe
  if (g_topic_bind[i].subscribed) {
    debug_mqtt("Topico ja inscrito!");
    return FAIL_CON;
  }
  mqtt_sn_sub_send(topic,qos);
}
else{ //Tópico não existe, precisamos REGISTRA-LO antes
  // Preparamos as tasks para registrar já que o tópico não existe
  // Criamos na sequência duas tarefas: 1-REGISTRAR 2-PUBLICAR O TÓPICO REGISTRADO
  // 1 - REGISTER
  debug_mqtt("Topico novo a REGISTRAR");
  mqtt_sn_task_t topic_reg;
  g_topic_bind[i].topic_name = topic;
  g_topic_bind[i].subscribed = false;

  topic_reg.msg_type_q = MQTT_SN_TYPE_REGISTER;

  // 2 - SUBSCRIBE
  // mqtt_sn_task_t subscribe_task;
  // subscribe_task.msg_type_q          = MQTT_SN_TYPE_SUBSCRIBE;
  // subscribe_task.qos_level           = qos;
  // topic_temp                         = topic;

  if (!mqtt_sn_insert_queue(topic_reg))
    debug_task("ERRO AO ADICIONAR NA FILA");
  //if (!mqtt_sn_insert_queue(subscribe_task))
  //  debug_task("ERRO AO ADICIONAR NA FILA");

  process_post(&mqtt_sn_main, mqtt_event_run_task, NULL);
}
return SUCCESS_CON;
