
  // Analisamos o buffer de tópicos registrados para ver se já foi registrado o tópico
  size_t i = 0;
  for (i=0; i < MAX_TOPIC_USED; i++)
    if (strcmp(g_topic_bind[i].topic_name,topic))
      if (g_topic_bind[i].subscribed)
        registered_topic = true;

  if (registered_topic){
    debug_mqtt("Topico ja inscrito");
    return FAIL_CON;
  }
  else{
      debug_mqtt("Topico nao registrado!#%s",topic);
      mqtt_sn_task_t subscribe_task;
      subscribe_task.msg_type_q          = MQTT_SN_TYPE_SUBSCRIBE;
      subscribe_task.qos_level           = qos;

      for (i=0; i < MAX_TOPIC_USED; i++)
        if (g_topic_bind[i].short_topic_id == 0xFF)
          break;

      subscribe_task.short_topic = i;
      g_topic_bind[i].topic_name = topic;
      g_topic_bind[i].short_topic_id = i;
      g_topic_bind[i].subscribed = true;

      if (!mqtt_sn_insert_queue(subscribe_task))
       debug_task("ERRO AO ADICIONAR NA FILA");
      process_post(&mqtt_sn_main,mqtt_event_run_task,NULL);
  }
  return SUCCESS_CON;
