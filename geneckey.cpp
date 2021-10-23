/* Based on:  Key generation application

    Copyright The Mbed TLS Contributors
    SPDX-License-Identifier: Apache-2.0

    Licensed under the Apache License, Version 2.0 (the "License"); you may
    not use this file except in compliance with the License.
    You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Arduino.h>

#define mbedtls_printf          Serial.printf

#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include "geneckey.h"

// We cannot use CURVE2551 in the older version of Espressif -- as mbedtls does not know its OID.
//
static const mbedtls_ecp_group_id DFL_EC_CURVE = MBEDTLS_ECP_DP_SECP256R1; // MBEDTLS_ECP_DP_CURVE25519
static const char *seed = "geneckey" __DATE__ __TIME__;

// #define DEBUG

int geneckey(mbedtls_pk_context *key)
{
  mbedtls_entropy_context entropy_ctx;
  mbedtls_ctr_drbg_context ctr_drbg;
#ifdef DEBUG
  unsigned char * tmp;
#endif
  char buff[48];
  int ret = 1;

  mbedtls_ctr_drbg_init( &ctr_drbg );
  mbedtls_entropy_init( &entropy_ctx );

  if ( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy_ctx,
                                      (const unsigned char*)seed, strlen(seed))) != 0 ) {
    mbedtls_strerror(ret, buff, sizeof(buff));
    Serial.print("mbedtls_ctr_drbg_seed: ");
    Serial.println(buff);
    return ret;
  };
  mbedtls_pk_init(key);
  if ( ( ret = mbedtls_pk_setup(key,
                                mbedtls_pk_info_from_type( MBEDTLS_PK_ECKEY ) ) ) != 0 ) {
    mbedtls_strerror(ret, buff, sizeof(buff));
    //mbedtls_printf("mbedtls_pk_setup returned -x%04x: %s\n", (unsigned int) - ret, buff);
    Serial.print("mbedtls_pk_setup: ");
    Serial.println(buff);
    goto exit;
  }

  if ((ret = mbedtls_ecp_gen_key(DFL_EC_CURVE, mbedtls_pk_ec(*key),
                                 mbedtls_ctr_drbg_random, &ctr_drbg )) != 0) {
    mbedtls_strerror(ret, buff, sizeof(buff));
    // mbedtls_printf("mbedtls_ecp_gen_key returned -0x%04x: %s\n", (unsigned int) - ret, buff);
    Serial.print("mbedtls_ecp_gen_key: ");
    Serial.println(buff);
    goto exit;
  }

#ifdef DEBUG
  tmp = (unsigned char *) malloc( 8 * 1024);
  if (tmp == NULL || (ret = mbedtls_pk_write_key_pem(key, tmp, 8 * 1024)) != 0) {
    mbedtls_strerror(ret, buff, sizeof(buff));
    Serial.print("mbedtls_pk_write_key_pem: ");
    Serial.println(buff);
    goto exit;
  };
  Serial.printf("%s\n", tmp);
  free(tmp);
#endif

exit:
  mbedtls_ctr_drbg_free( &ctr_drbg );
  mbedtls_entropy_free( &entropy_ctx );
  return ret;

}
