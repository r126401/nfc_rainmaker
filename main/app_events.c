
#include <string.h>
#include <strings.h>

#include "app_events.h"
#include "app_main.h"

#include "esp_log.h"
#include "esp_err.h"
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>



static char *TAG = "app_events.c";
QueueHandle_t event_queue_app;

/* Callback to handle commands received from the RainMaker cloud */
esp_err_t write_cb(const esp_rmaker_device_t *device, const esp_rmaker_param_t *param,
            const esp_rmaker_param_val_t val, void *priv_data, esp_rmaker_write_ctx_t *ctx)
{
    if (ctx) {
        ESP_LOGI(TAG, "Received write request via : %s", esp_rmaker_device_cb_src_to_str(ctx->src));
    }
    if (strcmp(esp_rmaker_param_get_name(param), ESP_RMAKER_DEF_POWER_NAME) == 0) {
        ESP_LOGI(TAG, "Received value = %s for %s - %s",
                val.val.b? "true" : "false", esp_rmaker_device_get_name(device),
                esp_rmaker_param_get_name(param));
        //app_driver_set_state(val.val.b);
        esp_rmaker_param_update(param, val);
    }
    return ESP_OK;
}






/* Event handler for catching RainMaker events */
void event_handler_rainmaker(void* arg, esp_event_base_t event_base,
                          int32_t event_id, void* event_data)
{
    if (event_base == RMAKER_EVENT) {
        switch (event_id) {
            case RMAKER_EVENT_INIT_DONE:
                ESP_LOGI(TAG, "RainMaker Initialised.");
                break;
            case RMAKER_EVENT_CLAIM_STARTED:
                ESP_LOGI(TAG, "RainMaker Claim Started.");
                break;
            case RMAKER_EVENT_CLAIM_SUCCESSFUL:
                ESP_LOGI(TAG, "RainMaker Claim Successful.");
                break;
            case RMAKER_EVENT_CLAIM_FAILED:
                ESP_LOGI(TAG, "RainMaker Claim Failed.");
                break;
            case RMAKER_EVENT_LOCAL_CTRL_STARTED:
                ESP_LOGI(TAG, "Local Control Started.");
                break;
            case RMAKER_EVENT_LOCAL_CTRL_STOPPED:
                ESP_LOGI(TAG, "Local Control Stopped.");
                break;
            default:
                ESP_LOGW(TAG, "Unhandled RainMaker Event: %"PRIi32, event_id);
        }
    } else if (event_base == RMAKER_COMMON_EVENT) {
        switch (event_id) {
            case RMAKER_EVENT_REBOOT:
                ESP_LOGI(TAG, "Rebooting in %d seconds.", *((uint8_t *)event_data));
                break;
            case RMAKER_EVENT_WIFI_RESET:
                ESP_LOGI(TAG, "Wi-Fi credentials reset.");
                break;
            case RMAKER_EVENT_FACTORY_RESET:
                ESP_LOGI(TAG, "Node reset to factory defaults.");
                break;
            case RMAKER_MQTT_EVENT_CONNECTED:
                ESP_LOGI(TAG, "MQTT Connected.");
                break;
            case RMAKER_MQTT_EVENT_DISCONNECTED:
                ESP_LOGI(TAG, "MQTT Disconnected.");
                break;
            case RMAKER_MQTT_EVENT_PUBLISHED:
                ESP_LOGI(TAG, "MQTT Published. Msg id: %d.", *((int *)event_data));
                break;
            default:
                ESP_LOGW(TAG, "Unhandled RainMaker Common Event: %"PRIi32, event_id);
        }
    } else if (event_base == APP_NETWORK_EVENT) {
        switch (event_id) {
            case APP_NETWORK_EVENT_QR_DISPLAY:
                ESP_LOGI(TAG, "Provisioning QR : %s", (char *)event_data);
                break;
            case APP_NETWORK_EVENT_PROV_TIMEOUT:
                ESP_LOGI(TAG, "Provisioning Timed Out. Please reboot.");
                break;
            case APP_NETWORK_EVENT_PROV_RESTART:
                ESP_LOGI(TAG, "Provisioning has restarted due to failures.");
                break;
            default:
                ESP_LOGW(TAG, "Unhandled App Wi-Fi Event: %"PRIi32, event_id);
                break;
        }
    } else if (event_base == RMAKER_OTA_EVENT) {
        switch(event_id) {
            case RMAKER_OTA_EVENT_STARTING:
                ESP_LOGI(TAG, "Starting OTA.");
                break;
            case RMAKER_OTA_EVENT_IN_PROGRESS:
                ESP_LOGI(TAG, "OTA is in progress.");
                break;
            case RMAKER_OTA_EVENT_SUCCESSFUL:
                ESP_LOGI(TAG, "OTA successful.");
                break;
            case RMAKER_OTA_EVENT_FAILED:
                ESP_LOGI(TAG, "OTA Failed.");
                break;
            case RMAKER_OTA_EVENT_REJECTED:
                ESP_LOGI(TAG, "OTA Rejected.");
                break;
            case RMAKER_OTA_EVENT_DELAYED:
                ESP_LOGI(TAG, "OTA Delayed.");
                break;
            case RMAKER_OTA_EVENT_REQ_FOR_REBOOT:
                ESP_LOGI(TAG, "Firmware image downloaded. Please reboot your device to apply the upgrade.");
                break;
            default:
                ESP_LOGW(TAG, "Unhandled OTA Event: %"PRIi32, event_id);
                break;
        }
    } else {
        ESP_LOGW(TAG, "Invalid event received!");
    }
}




char* event_app_2mnemonic(EVENT_APP type) {

    static char mnemonic[30];

    switch (type) {

        case EVENT_APP_GENERIC:
            strncpy(mnemonic, "EVENT_APP_GENERIC", 30);
        break;

        default:
            ESP_LOGW(TAG, "Evento no implementado");
            strncpy(mnemonic, "no implementado aun", 30);
        break;
    }



        return mnemonic;
}


static void send_event_app(event_app_t event) {


	ESP_LOGW(TAG, " envio de evento app %s", event_app_2mnemonic(event.event_app));
	if ( xQueueSend(event_queue_app, &event, 0) != pdPASS) {
		ESP_LOGE(TAG, "no se ha podido enviar el evento");

	}

}

static void receive_event_app(event_app_t event) {

    switch (event.event_app) {

        case EVENT_APP_GENERIC:
            ESP_LOGI(TAG, "Recibido evento generico");
        break;

        default:
            ESP_LOGW(TAG, "Evento no implementado");
        break;
    }


}



void event_app_task(void *arg) {

	event_app_t event;


	event_queue_app = xQueueCreate(10, sizeof(event_app_t));

	for(;;) {
		ESP_LOGI(TAG, "ESPERANDO EVENTO DE APLICACION...Memoria libre: %d", (int) esp_get_free_heap_size());
		if (xQueueReceive(event_queue_app, &event,  portMAX_DELAY) == pdTRUE) {

			receive_event_app(event);


		} else {
			ESP_LOGE(TAG, "NO SE HA PODIDO PROCESAR LA PETICION");
		}

	}
	vTaskDelete(NULL);


}

void create_event_app_task() {



	xTaskCreatePinnedToCore(event_app_task, "event_app_task", CONFIG_RESOURCE_EVENT_TASK, NULL, 0, NULL,0);
	ESP_LOGW(TAG, "TAREA DE EVENTOS DE APLICACION CREADA CREADA");


}

void send_event_generic(float dat) {

    event_app_t event;
    event.event_app = EVENT_APP_GENERIC;
    event.value = dat;
    send_event_app(event);


}






