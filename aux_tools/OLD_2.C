//mqtt_sn_check_queue();
// mqtt_sn_task_t pub_test;

// pub_test.msg_type_q = MQTT_SN_TYPE_PUBLISH;
// pub_test.short_topic = (uint8_t *)25;
// pub_test.long_topic = "demo";
// pub_test.message = "Velho";

// mqtt_sn_insert_queue(pub_test);
//
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
