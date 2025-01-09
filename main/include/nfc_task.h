
#include <esp_log.h>
#include "rc522.h"
#include "driver/rc522_spi.h"
#include "rc522_picc.h"



static rc522_spi_config_t driver_config = {
    .host_id = SPI3_HOST,
    .bus_config = &(spi_bus_config_t){
        .miso_io_num = CONFIG_RC522_SPI_BUS_GPIO_MISO,
        .mosi_io_num = CONFIG_RC522_SPI_BUS_GPIO_MOSI,
        .sclk_io_num = CONFIG_RC522_SPI_BUS_GPIO_SCLK,
    },
    .dev_config = {
        .spics_io_num = CONFIG_RC522_SPI_SCANNER_GPIO_SDA,
    },
    .rst_io_num = CONFIG_RC522_SCANNER_GPIO_RST,
};

static rc522_driver_handle_t driver;
static rc522_handle_t scanner;


void app_init_rc522();


