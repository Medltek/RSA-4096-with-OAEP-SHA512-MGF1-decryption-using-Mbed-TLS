/*
 *  Public key-based simple decryption program
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "mbedtls/build_info.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if defined(MBEDTLS_BIGNUM_C) && defined(MBEDTLS_PK_PARSE_C) && \
    defined(MBEDTLS_FS_IO) && defined(MBEDTLS_ENTROPY_C) && \
    defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include <stdio.h>
#include <string.h>
#endif

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_PK_PARSE_C) ||  \
    !defined(MBEDTLS_FS_IO) || !defined(MBEDTLS_ENTROPY_C) || \
    !defined(MBEDTLS_CTR_DRBG_C)
int main(void)
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_PK_PARSE_C and/or "
        "MBEDTLS_FS_IO and/or MBEDTLS_ENTROPY_C and/or "
        "MBEDTLS_CTR_DRBG_C not defined.\n");
    mbedtls_exit(0);
}
#else

int main(int argc, char* argv[])
{
    //Testing tokens defined in NFC CARD EMULATOR App
    unsigned char testingToken1[] = { 0x56, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x74, 0x6F, 0x6B, 0x65, 0x6E, 0x20, 0x6F, 0x66, 0x20, 0x73, 0x74, 0x75, 0x64, 0x65, 0x6E, 0x74, 0x20, 0x6E, 0x31 };
    unsigned char testingToken2[] = { 0x56, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x74, 0x6F, 0x6B, 0x65, 0x6E, 0x20, 0x6F, 0x66, 0x20, 0x73, 0x74, 0x75, 0x64, 0x65, 0x6E, 0x74, 0x20, 0x6E, 0x32 };
    unsigned char testingToken3[] = { 0x56, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x74, 0x6F, 0x6B, 0x65, 0x6E, 0x20, 0x6F, 0x66, 0x20, 0x73, 0x74, 0x75, 0x64, 0x65, 0x6E, 0x74, 0x20, 0x6E, 0x33 };
    unsigned char testingToken4[] = { 0x56, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x74, 0x6F, 0x6B, 0x65, 0x6E, 0x20, 0x6F, 0x66, 0x20, 0x73, 0x74, 0x75, 0x64, 0x65, 0x6E, 0x74, 0x20, 0x6E, 0x34 };
    unsigned char testingToken5[] = { 0x56, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x74, 0x6F, 0x6B, 0x65, 0x6E, 0x20, 0x6F, 0x66, 0x20, 0x73, 0x74, 0x75, 0x64, 0x65, 0x6E, 0x74, 0x20, 0x6E, 0x35 };

    //Place PrivateKey.key file next to source or specify the path
    //Let me know if this needs to be hard coded instead of imported from file
    char pathToPrivateKey[] = "PrivateKey.key";

    FILE* f;
    int ret = 1;
    unsigned c;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    size_t i, olen = 0;
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char result[1024];
    unsigned char buf[512];
    const char* pers = "mbedtls_pk_decrypt";
    ((void)argv);
    
    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    memset(result, 0, sizeof(result));
   
    //implements &ctr_drbg, which is needed for decryption and generating random nonce
    mbedtls_printf("\n  . Seeding the random number generator...\n");
    fflush(stdout);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
        (const unsigned char*)pers,
        strlen(pers))) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    //generating nonce 16B
    //nonce is handed over to NFC Card Emulator in 2nd message 
    //serves as protection against replay attack
    unsigned char randomByteArray[16];
    mbedtls_ctr_drbg_random(&ctr_drbg, randomByteArray, 16);
    printf("  . Nonce generated: ");
    for (int i = 0; i < 16; ++i) {
        if (!(i % 16) && i)
            printf("\n");

        printf("0x%02x ", randomByteArray[i]);
    }
    

    //reading private key from file specified in pathToPrivateKey
    mbedtls_printf("\n  . Reading private key from '%s'", pathToPrivateKey);
    fflush(stdout);

    if ((ret = mbedtls_pk_parse_keyfile(&pk, pathToPrivateKey,   "",
        mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_pk_parse_keyfile returned -0x%04x\n", (unsigned int)-ret);
        goto exit;
    }
    

    //setting the correct padding of our rsa = SHA512 and MBEDTLS_RSA_PKCS_V21(supporting SHA2)
    if ((ret = mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk),
        MBEDTLS_RSA_PKCS_V21,
        MBEDTLS_MD_SHA512)) != 0)
    {
        mbedtls_printf(" failed\n  ! Padding not supported\n");
        goto exit;
    }
    
    //Extract the RSA encrypted value from the text file
    if ((f = fopen("EncryptedMessage.txt", "rb")) == NULL)
    {
        mbedtls_printf("\n  ! Could not open %s\n\n", "EncryptedMessage.txt");
        ret = 1;
        goto exit;
    }

    i = 0;
    while (fscanf(f, "%02X", (unsigned int*)&c) > 0 &&
        i < (int)sizeof(buf))
    {
        buf[i++] = (unsigned char)c;
    }

    fclose(f);

    //Connecting two byte arrays of Cipher message incoming from the application
    //Please fill these arrays with actual data
    //ATM data are just for test
    //later in decrypt function replace buf with CipherMessageArray
    unsigned char CipherMessageArray[256 + 256];
    unsigned char b[256];
    memcpy(CipherMessageArray + 256, b, 256); // a+n is destination, b is source and third argument is m
    
    
    //Decrypt the encrypted RSA data and print the result.
    //In order to decrypt with two arrays connected through above code snip please replace 
    //buf with CipherMessageArray in following mbedtls_pk_decrypt(&pk, buf, i, result, &olen, sizeof(result),  mbedtls_ctr_drbg_random, & ctr_drbg)) != 0)
    mbedtls_printf("\n  . Decrypting the encrypted data");
    fflush(stdout);

    if ((ret = mbedtls_pk_decrypt(&pk, buf, i, result, &olen, sizeof(result),
        mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_pk_decrypt returned -0x%04x\n",
            (unsigned int)-ret);
        goto exit;
    }

    mbedtls_printf("\n  . OK\n\n");

    mbedtls_printf("  . The decrypted result is(16B of random nonce + 32B of verification token): '%s'\n", result);

    //Extracting the Nonce bytes from result(decrypted message)
    printf("  . Extracted Nonce bytes: ");
    unsigned char rawReceivedNonceBytes[16];
    for (int i = 0; i < 16; ++i) {
        if (!(i % 16) && i)
            printf("\n");

        rawReceivedNonceBytes[i] = result[i];
        printf("0x%02x ", result[i]);
    }
    printf("\n\n");

    //Comparing Outgoing Nonce and Received Nonce bytes
    //ATM gives wrong result as the Nonce is not yet communicated between devices
    /*int n;

    n = memcmp(randomByteArray, rawReceivedNonceBytes, sizeof(randomByteArray));

    if (n > 0) printf("'%s' is greater than '%s'.\n", randomByteArray, rawReceivedNonceBytes);
    else if (n < 0) printf("'%s' is less than '%s'.\n", randomByteArray, rawReceivedNonceBytes);
    else printf("'%s' is the same as '%s'.\n", randomByteArray, rawReceivedNonceBytes);
    */
    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

    mbedtls_pk_free(&pk);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);

#if defined(MBEDTLS_ERROR_C)
    if (exit_code != MBEDTLS_EXIT_SUCCESS)
    {
        mbedtls_strerror(ret, (char*)buf, sizeof(buf));
        mbedtls_printf("  !  Last error was: %s\n", buf);
    }
#endif

#if defined(_WIN32)
    mbedtls_printf("  + Press Enter to exit this program.\n");
    fflush(stdout); getchar();
#endif

    mbedtls_exit(exit_code);
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_PK_PARSE_C && MBEDTLS_FS_IO &&
          MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C */
