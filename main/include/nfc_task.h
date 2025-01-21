
#include <esp_log.h>
#include "rc522.h"
#include "driver/rc522_spi.h"
#include "rc522_picc.h"

#include "picc/rc522_mifare.h"



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




void app_init_rc522();
esp_err_t read_data_from_card(rc522_handle_t scanner, rc522_picc_t *picc, uint8_t block_address);
esp_err_t write_data_to_card(rc522_handle_t scanner, rc522_picc_t *picc, uint8_t block_address, uint8_t *buffer);
esp_err_t get_auth_card(rc522_handle_t scanner, rc522_picc_t *picc, rc522_mifare_key_t *key, uint8_t block_address);


