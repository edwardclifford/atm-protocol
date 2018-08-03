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
#include <stdlib.h>
#include "usbserialprotocol.h"
#include "aes.h"
#include "sha256.h"

#define UUID_LEN 128
#define PROV_MSG "P"
#define RECV_OK "K"

#define PACKAGE1 ((uint8*)(CY_FLASH_BASE + 0x5840))
#define PACKAGE2 ((uint8*)(CY_FLASH_BASE + 0x5920))
#define PACKAGE3 ((uint8*)(CY_FLASH_BASE + 0x6000))
#define IV ((uint8*)(CY_FLASH_BASE + 0x6080))
#define AES_KEY ((uint8*)(CY_FLASH_BASE + 0x6160))
#define TAMPER_CODE ((uint8*)(CY_FLASH_BASE + 0x6320))
#define PIN ((uint8*)(CY_FLASH_BASE + 0x6400))
#define UUID ((uint8*)(CY_FLASH_BASE + 0x6480))
#define PROVISIONED ((uint8*)(CY_FLASH_BASE + 0x6500))

#define write_package1(p1) CySysFlashWriteRow(193, p1);
#define write_package2(p2) CySysFlashWriteRow(194, p2);
#define write_package3(p3) CySysFlashWriteRow(195, p3);
#define write_iv(iv) CySysFlashWriteRow(196, iv);
#define write_aes_key(ak) CySysFlashWriteRow(197, ak);
#define write_tampercode(t) CySysFlashWriteRow(199, t);
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

    // set account number
    pullMessage(message);
    write_uuid(message);
    pushMessage((uint8*)RECV_OK, strlen(RECV_OK));

    //set tamper code
    pullMessage(message);
    write_tampercode(message);
    pushMessage((uint8*)RECV_OK, strlen(RECV_OK));

    //take initial key
    pullMessage(message);
    write_aes_key(message);
    pushMessage((uint8*)RECV_OK, strlen(RECV_OK));

    //take initial iv
    pullMessage(message);
    write_iv(message);
    pushMessage((uint8*)RECV_OK, strlen(RECV_OK));

}

int main (void)
{
    CyGlobalIntEnable;      /* Enable global interrupts */
    UART_Start();

    /* Declare vairables here */
    uint8_t message[128];
    uint8_t tampercode[128];
    uint8_t tamperHash[256];

    //encrypt arrays
    uint8_t messageArray[160]; //plaintext
    uint8_t messageEncrypted[160]; //ciphertext
    uint8_t keyArray[32];  //key
    uint8_t ivArray[16];  //iv

    //decrypt values
    uint8_t decryptArray[176];

    //Zero array to overwrite data
    uint8_t emptyArray[128] = {0};

    //set flag for recieving commands
    bool flag = true;

    // Provision card if on first boot
    if (*PROVISIONED == 0x00) {
        provision();
        mark_provisioned();
    }

    // Go into infinite loop
    while (1) {

        //write key array from flash
        for(int i = 0; i < 32; i++) {
            keyArray[i] = *((uint8_t*)(CY_FLASH_BASE + (0x6160 + i)));
        }

        //write iv array from flash
        for(int i = 0; i < 16; i++) {
            ivArray[i] = *((uint8_t*)(CY_FLASH_BASE + (0x6080 + i)));
        }

        //Hash tampercode and move it to memory:
        SHA256(tamperHash, TAMPER_CODE, 128);

        //Overwrite tampercode
        write_tampercode(emptyArray);

        //concatinate uuid and tamperhash to messageArray
        memcpy(messageArray, tamperHash, 32);
        memcpy(messageArray + 32, UUID, 128);

        //encrypts array messageArray and stores it in messageEncrypted
        aes256_crypt_ctr(messageEncrypted, keyArray, ivArray, messageArray, 160);

        // syncronize communication with bank
        syncConnection(SYNC_NORM);

            // get command, if first run
            if (flag) {
            pullMessage(message);
            pushMessage((uint8*)RECV_OK, strlen(RECV_OK));
            }

            //send packet with uuid (first 128) and hashed tampercode (last 256)
            pushMessage(messageEncrypted, (uint8_t)160);

            //recieve new tampercode and aes key (+ iv)
            pullMessage(message);
            pushMessage((uint8*)RECV_OK, strlen(RECV_OK));

            //decrypt new tampercode and aes key
            aes256_crypt_ctr(message, keyArray, ivArray, decryptArray, 176);

            //break down encrypted package
            memcpy(keyArray, decryptArray, 32);
            memcpy(ivArray, decryptArray + 32, 16);
            memcpy(tampercode, decryptArray + 48, 128);

            //write values to flash
            write_aes_key(keyArray);
            write_iv(ivArray);
            write_tampercode(tampercode);

            //if second command is sent, run again, if not, terminate
            pullMessage(message);
            pushMessage((uint8*)RECV_OK, strlen(RECV_OK));
            flag = false;
    }
}
