
#include "time.h"
#include "nfc_task.h"
#include "rc522.h"
#include "esp_check.h"
#include "string.h"
#include "esp_log.h"
#include "esp_log_color.h"



static char *TAG = "nfc_task.c";
static rc522_driver_handle_t driver;
static rc522_handle_t scanner;

uint8_t read_buffer[RC522_MIFARE_BLOCK_SIZE];
uint8_t write_buffer[RC522_MIFARE_BLOCK_SIZE];

#define DUMP(format, ...) esp_log_write(ESP_LOG_INFO, TAG, format, ##__VA_ARGS__)


static void dump_header()
{
    DUMP("Sector  Block                 Bytes                 AccessBits\n");
    DUMP("                0 1 2 3  4 5 6 7  8 9  11 12    15    c1 c2 c3\n");
}


rc522_mifare_key_t key_card = {
        .value = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    };

static void dump_block2(rc522_mifare_sector_block_t *block, uint8_t sector_index)
{
    if (block->type == RC522_MIFARE_BLOCK_TRAILER) {
        DUMP("%*d", 6, sector_index);
    }
    else {
        DUMP("%*s", 6, "");
    }

    // Block address
    DUMP("  %*d", 5, block->address);

    // Data
    DUMP("  ");
    for (uint8_t i = 0; i < 16; i++) {
        DUMP("%02" RC522_X "", block->bytes[i]);

        if ((i % 4) == 3) {
            DUMP(" ");
        }
    }

    // Access bits
    DUMP("    %d  %d  %d", block->access_bits.c1, block->access_bits.c2, block->access_bits.c3);

    // String representation (if it's data block)
    if (block->type == RC522_MIFARE_BLOCK_DATA) {
        DUMP("  |");

        for (uint8_t i = 0; i < 16; i++) {
            if (block->bytes[i] >= 32 && block->bytes[i] <= 126) { // standard ascii codes
                DUMP("%c" LOG_RESET_COLOR, block->bytes[i]);
            }
            else {
                DUMP("%c", '.');
            }
        }

        DUMP("|");
    }

    // Value (if it's value block)
    else if (block->type == RC522_MIFARE_BLOCK_VALUE) {
        DUMP("  (val=%ld (0x%04l" RC522_X "), adr=0x%02" RC522_X ")",
            block->value_info.value,
            block->value_info.value,
            block->value_info.addr);
    }

    // Errors and warnings
    if (block->type == RC522_MIFARE_BLOCK_TRAILER && block->error == RC522_ERR_MIFARE_ACCESS_BITS_INTEGRITY_VIOLATION) {
        DUMP("  ABITS_ERR");
    }

    if (block->type == RC522_MIFARE_BLOCK_VALUE && block->error == RC522_ERR_MIFARE_VALUE_BLOCK_INTEGRITY_VIOLATION) {
        DUMP("  VAL_ERR");
    }

    // Termination
    DUMP("\n");
}

static void dump_block(uint8_t buffer[RC522_MIFARE_BLOCK_SIZE])
{
    uint8_t i;
    static int bloque = 0;
    esp_log_write(ESP_LOG_INFO, TAG, "Bloque: %d -- ", bloque);
    for (i = 0; i < RC522_MIFARE_BLOCK_SIZE; i++) {
        esp_log_write(ESP_LOG_INFO, TAG, "%02" RC522_X " ", buffer[i]);
    }

    esp_log_write(ESP_LOG_INFO, TAG, "\n");
    if (bloque == 63) bloque = 0;
    else bloque++;
}

// Incrementa el contador de 48 bits
void increment_counter(uint8_t *counter, size_t size) {
    for (int i = size - 1; i >= 0; i--) {
        if (++counter[i] != 0) {
            // No hay desbordamiento, terminamos
            break;
        }
        // Si hay desbordamiento, seguimos con el siguiente byte más significativo
    }
}

// Imprime el contador en formato hexadecimal
void print_counter(const uint8_t *counter, size_t size) {

    for (size_t i = 0; i < size; i++) {
        printf("%02X", counter[i]);
    }
    printf("\n");
}



void set_counter(uint8_t *counter) {

    size_t i;
    for (i = 0; i < RC522_MIFARE_KEY_SIZE; i++) {
        key_card.value[i] = counter[i];
    }


}

void rutina_contador(rc522_picc_t *picc) {

    esp_err_t error;

    int i;

    print_counter(key_card.value, RC522_MIFARE_KEY_SIZE);
    for(i=0;i<64;i++) {
        if (read_data_from_card(scanner, picc, i) == ESP_FAIL) {
            ESP_LOGE(TAG, "Error al leer por clave incorrecta de la mifare. Estado: %d", picc->state);
            print_counter(key_card.value, RC522_MIFARE_KEY_SIZE);
            increment_counter(key_card.value, RC522_MIFARE_KEY_SIZE);
            break;
        }
        
    }

        ESP_LOGI(TAG, "fin del bucle");
        
}






void escribir(rc522_picc_t *picc) {



    strncpy((char*) write_buffer, "--------------", RC522_MIFARE_BLOCK_SIZE);
    int r = rand();
    write_buffer[RC522_MIFARE_BLOCK_SIZE - 2] = ((r >> 8) & 0xFF);
    write_buffer[RC522_MIFARE_BLOCK_SIZE - 1] = ((r >> 0) & 0xFF);

    write_data_to_card(scanner, picc, 1, write_buffer);

}

static esp_err_t dump_memory(rc522_handle_t scanner, rc522_picc_t *picc)
{
    rc522_mifare_key_t key = {
        .value = { RC522_MIFARE_KEY_VALUE_DEFAULT },
    };

    rc522_mifare_desc_t mifare;
    ESP_RETURN_ON_ERROR(rc522_mifare_get_desc(picc, &mifare), TAG, "");

    DUMP("\n");
    dump_header();

    // Start from the highest sector
    uint8_t sector_index = mifare.number_of_sectors - 1;

    do {
        rc522_mifare_sector_desc_t sector;
        ESP_RETURN_ON_ERROR(rc522_mifare_get_sector_desc(sector_index, &sector), TAG, "");
        ESP_RETURN_ON_ERROR(rc522_mifare_auth_sector(scanner, picc, &sector, &key), TAG, "");

        rc522_mifare_sector_block_t trailer;
        ESP_RETURN_ON_ERROR(rc522_mifare_read_sector_trailer_block(scanner, picc, &sector, &trailer), TAG, "");

        dump_block2(&trailer, sector_index);

        // Start from the highest (non-trailer) block
        uint8_t block_offset = sector.number_of_blocks - 2;

        do {
            rc522_mifare_sector_block_t block;
            ESP_RETURN_ON_ERROR(rc522_mifare_read_sector_block(scanner, picc, &sector, &trailer, block_offset, &block),
                TAG,
                "");

            dump_block2(&block, sector_index);
        }
        while (block_offset--);
    }
    while (sector_index--);

    DUMP("\n");

    return ESP_OK;
}


void leer_tarjeta(rc522_picc_t *picc) {

    int i;



        if (!rc522_mifare_type_is_classic_compatible(picc->type)) {
        ESP_LOGW(TAG, "Card is not supported by this example");
        return;
    }


    for (i=0;i<16;i++) {

        read_data_from_card(scanner, picc, i);
    }

        if (rc522_mifare_deauth(scanner, picc) != ESP_OK) {
        ESP_LOGW(TAG, "Deauth failed");
    }

}

static void on_picc_state_changed(void *arg, esp_event_base_t base, int32_t event_id, void *data)
{
    rc522_picc_state_changed_event_t *event = (rc522_picc_state_changed_event_t *)data;
    rc522_picc_t *picc = event->picc;

    if (picc->state == RC522_PICC_STATE_ACTIVE) {

        if (!rc522_mifare_type_is_classic_compatible(picc->type)) {
            ESP_LOGW(TAG, "Card is not supported by this example");
            return;
    }

    ESP_LOGI(TAG, "Mifare tipo %d", picc->type);



        rc522_picc_print(picc);
        //leer_tarjeta(picc);
        //escribir(picc);
        //rutina_contador(picc);
        dump_memory(scanner, picc);
        if (rc522_mifare_deauth(scanner, picc) != ESP_OK) {
            ESP_LOGW(TAG, "Deauth failed");
            }

    }
    else if (picc->state == RC522_PICC_STATE_IDLE && event->old_state >= RC522_PICC_STATE_ACTIVE) {
        ESP_LOGI(TAG, "Card has been removed");
    }
}


void app_init_rc522()
{
    srand(time(NULL)); // Initialize random generator
    rc522_spi_create(&driver_config, &driver);
    rc522_driver_install(driver);

    rc522_config_t scanner_config = {
        .driver = driver,
    };

    rc522_create(&scanner_config, &scanner);
    rc522_register_events(scanner, RC522_EVENT_PICC_STATE_CHANGED, on_picc_state_changed, NULL);
    rc522_start(scanner);
}


esp_err_t get_auth_card(rc522_handle_t scanner, rc522_picc_t *picc, rc522_mifare_key_t *key, uint8_t block_address) {

    /*const uint8_t block_address = 4;
    rc522_mifare_key_t key = {
        .value = { RC522_MIFARE_KEY_VALUE_DEFAULT },
    };
*/
    if (rc522_mifare_auth(scanner, picc, block_address, key) != ESP_OK) {
        ESP_LOGE(TAG, "Error al obtener la autorizacion de la mifare");
        return ESP_FAIL;
    }

    return ESP_OK;


}


static esp_err_t validate_data(uint8_t *buf1, uint8_t *buf2) {

    uint8_t i;
    for (i = 0; i < RC522_MIFARE_BLOCK_SIZE; i++) {
        if (buf1[i] != buf2[i]) {
            ESP_LOGE(TAG, "No se ha escrito lo mismo que se ha leido");
            return ESP_FAIL;
        }
    }

    return ESP_OK;


}



esp_err_t read_data_from_card(rc522_handle_t scanner, rc522_picc_t *picc, uint8_t block_address) {

    esp_err_t error;

    if ((error = rc522_mifare_auth(scanner, picc, block_address, &key_card)) != ESP_OK) {
        ESP_LOGE(TAG, "Error al obtener la autorizacion de la mifare. Error: %d", error);
        return ESP_FAIL;
    }


    if ((error = rc522_mifare_read(scanner, picc, block_address, read_buffer)) != ESP_OK) {

        ESP_LOGE(TAG, "error al leer del bloque %d", (int) block_address);
    } else {
        //ESP_LOGI(TAG, "BLOQUE %d: %s", (int) block_address, (char*) read_buffer);
        dump_block(read_buffer);
    }


    return ESP_OK;
}


esp_err_t write_data_to_card(rc522_handle_t scanner, rc522_picc_t *picc, uint8_t block_address, uint8_t *buffer) {

    esp_err_t error;

    if (rc522_mifare_auth(scanner, picc, block_address, &key_card) != ESP_OK) {
        ESP_LOGE(TAG, "Error al obtener la autorizacion de la mifare");
        return ESP_FAIL;
    }

    //ESP_RETURN_ON_ERROR(rc522_mifare_write(scanner, picc, block_address, buffer), TAG, "write fail");
    
    if ((error = rc522_mifare_write(scanner, picc, block_address, buffer)) == ESP_OK) {
        ESP_LOGI(TAG, "El error es: %d", error);
        read_data_from_card(scanner, picc, block_address);
        dump_block(write_buffer);
        dump_block(read_buffer);
    }
    else {
        ESP_LOGE(TAG, "error al escribir el  bloque %d", (int) block_address);
        return ESP_FAIL;
    }




    if ((error = validate_data(read_buffer, buffer)) != ESP_OK) {

        ESP_LOGE(TAG, "Fallo al verificar la escritura");

    } else {
        ESP_LOGI(TAG, "Escritura realizada correctamente");
    }




    return error;
}









