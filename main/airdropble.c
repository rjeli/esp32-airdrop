void
ble_handler(esp_gap_ble_cb_event_t evt, esp_ble_gap_cb_param_t *param)
{
	printf("got ble event: ");
	switch (evt) {
	ENUMCASEO(ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT);
		printf(" status: %d", param->adv_data_raw_cmpl.status);
		break;
	ENUMCASEO(ESP_GAP_BLE_ADV_START_COMPLETE_EVT);
		printf(" status: %d", param->adv_start_cmpl.status);
		break;
	ENUMCASEO(ESP_GAP_BLE_ADV_STOP_COMPLETE_EVT);
		printf(" status: %d", param->adv_stop_cmpl.status);
		break;
	ENUMCASE(ESP_GAP_BLE_SCAN_RSP_DATA_SET_COMPLETE_EVT);
	ENUMCASE(ESP_GAP_BLE_SCAN_PARAM_SET_COMPLETE_EVT);
	ENUMCASE(ESP_GAP_BLE_SCAN_RESULT_EVT);
	ENUMCASE(ESP_GAP_BLE_SCAN_RSP_DATA_RAW_SET_COMPLETE_EVT);
	ENUMCASE(ESP_GAP_BLE_SCAN_START_COMPLETE_EVT);
	ENUMCASE(ESP_GAP_BLE_SCAN_STOP_COMPLETE_EVT);
	ENUMDEFAULT(evt);
	}
	printf("\n");
}

    // init bt
    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_bt_controller_init(&bt_cfg));
    ESP_ERROR_CHECK(esp_bt_controller_enable(ESP_BT_MODE_BTDM));
    ESP_ERROR_CHECK(esp_bluedroid_init());
    ESP_ERROR_CHECK(esp_bluedroid_enable());
    // init ble
    ESP_ERROR_CHECK(esp_ble_gap_register_callback(ble_handler));
    ESP_ERROR_CHECK(esp_ble_gap_config_adv_data_raw(airdrop_ble_data, sizeof(airdrop_ble_data)));

    esp_ble_adv_params_t adv_params = {
    	.adv_int_min = 300,
    	.adv_int_max = 300,
    	.adv_type = ADV_TYPE_NONCONN_IND,
    	.own_addr_type = BLE_ADDR_TYPE_PUBLIC,
    	.peer_addr = {0},
    	.peer_addr_type = BLE_ADDR_TYPE_PUBLIC,
    	.channel_map = ADV_CHNL_ALL,
    	.adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
    };
    ESP_ERROR_CHECK(esp_ble_gap_start_advertising(&adv_params));
