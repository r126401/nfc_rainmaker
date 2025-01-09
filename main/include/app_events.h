


#include "esp_rmaker_standard_params.h"
#include <esp_rmaker_core.h>
#include <esp_rmaker_standard_types.h>
#include <esp_rmaker_standard_params.h>
#include <esp_rmaker_standard_devices.h>
#include <esp_rmaker_common_events.h>
#include <app_network.h>
#include <app_insights.h>
#include <esp_rmaker_ota.h>





typedef enum EVENT_APP {

    EVENT_APP_GENERIC,
    EVENT_APP_SETPOINT_THRESHOLD,
    EVENT_APP_TIME_VALID,
    EVENT_APP_AUTO,
    EVENT_APP_MANUAL,
    EVENT_APP_ALARM_ON,
    EVENT_APP_ALARM_OFF,
    EVENT_APP_FACTORY,

}EVENT_APP;


typedef struct event_app_t {

    float value;
    EVENT_APP event_app;
} event_app_t;

esp_err_t write_cb(const esp_rmaker_device_t *device, const esp_rmaker_param_t *param,
            const esp_rmaker_param_val_t val, void *priv_data, esp_rmaker_write_ctx_t *ctx);



void event_handler_rainmaker(void* arg, esp_event_base_t event_base,
                int32_t event_id, void* event_data);


void create_event_app_task();
void send_event_generic(float dat);