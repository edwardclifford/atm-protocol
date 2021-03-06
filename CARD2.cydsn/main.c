/* ========================================
 *
 * Copyright YOUR COMPANY, THE YEAR
 * All Rights Reserved
 * UNPUBLISHED, LICENSED SOFTWARE.
 *
 * CONFIDENTIAL AND PROPRIETARY INFORMATION
 * WHICH IS THE PROPERTY OF your company.
 *
 * ========================================
*/
#include <project.h>
#include "usbserialprotocol.h"
#include <aes.h>
#include "aes256_tables.h"
#include <sha256.h>

#define PIN_LEN 8
#define UUID_LEN 36
#define PINCHG_SUC "SUCCESS"
#define PROV_MSG "P"
#define RECV_OK "K"
#define PIN_OK "OK"
#define PIN_BAD "BAD"
#define CHANGE_PIN '3'

#define PIN ((uint8*)(CY_FLASH_BASE + 0x6400))
#define UUID ((uint8*)(CY_FLASH_BASE + 0x6480))
#define PROVISIONED ((uint8*)(CY_FLASH_BASE + 0x6500))
#define write_pin(p) CySysFlashWriteRow(200, p);
#define write_uuid(u) CySysFlashWriteRow(201, u);

void mark_provisioned()
{
    uint8 row[128];
    *row = 1;
    CySysFlashWriteRow(202, row);
}

// provisions card (should only ever be called once)
void provision()
{
    uint8 message[128];

    // synchronize with bank
    syncConnection(SYNC_PROV);

    pushMessage((uint8*)PROV_MSG, (uint8)strlen(PROV_MSG));

    // set PIN
    pullMessage(message);
    write_pin(message);
    pushMessage((uint8*)RECV_OK, strlen(RECV_OK));

    // set account number
    pullMessage(message);
    write_uuid(message);
    pushMessage((uint8*)RECV_OK, strlen(RECV_OK));
}


    /*
    to decrypt: need ciphertext, key, plaintext, length of plaintext, and iv
    */



uint8_t decrypt(uint8_t *ciphertext, uint8_t const key[static 32], uint8_t const iv[static 16], uint8_t const *plaintext, uint32_t len) {

     aes256_crypt_ctr(ciphertext, key, iv, plaintext, len);
     return(*plaintext);
}

    /*
    to encrypt: need ciphertext, key, and plaintext
    */
uint8_t encrypt (uint8_t ciphertext[static 16], uint8_t const key[static 32], uint8_t const plaintext[static 16]) {
      aes256_encrypt_block(ciphertext, key, plaintext);
      return(*ciphertext);
}

    /*
    writes the message in SHA256-bit hash into hash, for the message with length len

    */


uint8_t hash (uint8_t *hash, uint8_t const *msg, uint32_t len){
      SHA256(hash, msg, len);
      return (*hash);
}





int main (void)
{
    CyGlobalIntEnable;      /* Enable global interrupts */

    UART_Start();

    /* Declare vairables here */
    uint8 message[128];

    //while(1) UART_UartPutString("HELLO WORLD!\r\n");
    // Provision card if on first boot
    if (*PROVISIONED == 0x00) {
        provision();
        mark_provisioned();
    }

    // Go into infinite loop
    while (1) {
        /* Place your application code here. */

        // syncronize communication with bank
        syncConnection(SYNC_NORM);

        // receive pin number from ATM
        pullMessage(message);

        if (strncmp((char*)message, (char*)PIN, PIN_LEN)) {
            pushMessage((uint8*)PIN_BAD, strlen(PIN_BAD));
        } else {
            pushMessage((uint8*)PIN_OK, strlen(PIN_OK));

            // get command
            pullMessage(message);
            pushMessage((uint8*)RECV_OK, strlen(RECV_OK));

            // change PIN or broadcast UUID
            if(message[0] == CHANGE_PIN)
            {
                pullMessage(message);
                write_pin(message);
                pushMessage((uint8*)PINCHG_SUC, strlen(PINCHG_SUC));
            } else {
                pushMessage(UUID, UUID_LEN);
            }
        }
    }
}
