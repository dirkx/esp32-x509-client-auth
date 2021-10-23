
#include <WiFi.h>
#include <WiFiUdp.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <mbedtls/sha256.h>

#include "geneckey.h"
#include "selfsign.h"

char * server_cert_as_pem = NULL;
char * client_cert_as_pem = NULL;
char * client_key_as_pem = NULL;
unsigned char sha256_client[32], sha256_server[32], sha256_server_key[32];
char * ca_root = NULL;
char * nonce = NULL;


#define URL "https://makerspaceleiden.nl:4443/crm/pettycash"
#define REGISTER_PATH "/api/v2/register"

void setupAuth(const char * terminalName) {
  char tmp[65];
  mbedtls_pk_context key;
  geneckey(&key);

  mbedtls_x509write_cert crt;
  if (0 != populate_self_signed(&key, terminalName, &crt)) {
    Serial.println("Generation error. Aborting");
    return;
  }
  if (0 != sign_and_topem(&key, &crt, &client_cert_as_pem, &client_key_as_pem)) {
    Serial.println("Derring error. Aborting");
    return;
  };
  fingerprint_from_pem(client_cert_as_pem, sha256_client);

  Serial.print("Fingerprint (as shown in CRM): ");
  Serial.println(sha256toHEX(sha256_client, tmp));
  // Serial.println(client_key_as_pem);
  // Serial.println(client_cert_as_pem);
}

void setup() {
  Serial.begin(115200);
  Serial.println("Start\n\n");

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_NETWORK, WIFI_PASSWD);
  WiFi.setHostname("foo");

  while (WiFi.waitForConnectResult() != WL_CONNECTED) {
    ESP.restart();
  }
  configTime(0, 0, "10.11.0.2");
  setupAuth("ard-client");

  Serial.println("starting loop()");
}

void loop() {
  WiFiClientSecure *client;
  const mbedtls_x509_crt *peer ;
  HTTPClient https;
  int httpCode, len, ret;
  unsigned char tmp[128], buff[2 * 1024], sha256[256 / 8];

  // Wait for the time to work - to prevent SSL funnyness.
  //
  time_t now = time(nullptr);
  if (now < 3600)
    return;

  if (ca_root == NULL) {
    if (!(client = new WiFiClientSecure())) {
      Serial.println("WiFiClientSecure for CA fetch failed.");
      return;
    }
    // Sadly required - due to a limitation in the current SSL stack we must
    // provide the root CA. but we do not know it (yet). So learn it first.
    //
    client->setInsecure();
    if (!https.begin(*client, URL ) || https.GET() < 0) {
      Serial.println("Failed to begin https");
      goto exit;
    };
    const mbedtls_x509_crt* peer = client->getPeerCertificate();

    server_cert_as_pem = der2pem("CERTIFICATE", peer->raw.p, peer->raw.len);

    // Traverse up to (any) root & serialize the CAcert. We need it in
    // PEM format; as that is what setCACert() expects.
    //
    while (peer->next) peer = peer->next;
    ca_root = der2pem("CERTIFICATE", peer->raw.p, peer->raw.len);

    Serial.println("CA-Cert fetched");
    goto exit;
  };

  if (nonce == NULL) {
    if (!(client = new WiFiClientSecure())) {
      Serial.println("WiFiClientSecure for register fetch failed.");
      return;
    }
    client->setCACert(ca_root);
    client->setCertificate(client_cert_as_pem);
    client->setPrivateKey(client_key_as_pem);

    if (!https.begin(*client, URL REGISTER_PATH "?name=testV2" )) {
      Serial.println("Failed to begin https");
      goto exit;
    };

    httpCode =  https.GET();
    if (httpCode != 401)
      goto exit;

    // Extract peer cert and calculate hash over the public key; as, especially
    // with Let's Encrypt - the cert itself is regularly renewed.
    //
    peer = client->getPeerCertificate();
    mbedtls_sha256_ret(peer->raw.p, peer->raw.len, sha256_server, 0);

    Serial.print("Fingerprint server cert: ");
    for (int i = 0; i < 32; i++) Serial.printf("%02x", sha256_server[i]);
    Serial.println("");

    nonce = strdup((https.getString().c_str()));
    Serial.println("Got a NONCE");
    goto exit;
  };

  if (nonce) {
    if (!(client = new WiFiClientSecure())) {
      Serial.println("WiFiClientSecure for register fetch failed.");
      return;
    }

    client->setCACert(ca_root);
    client->setCertificate(client_cert_as_pem);
    client->setPrivateKey(client_key_as_pem);

    // Create the reply; SHA256(nonce, tag(secret), client, server);
    //
    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts_ret(&sha_ctx, 0);
    // we happen to know that the first two can safely be treated as strings.
    mbedtls_sha256_update_ret(&sha_ctx, (unsigned char*) nonce, strlen(nonce));
    mbedtls_sha256_update_ret(&sha_ctx, (unsigned char*) TEST_TAG, strlen(TEST_TAG));
    // mbedtls_sha256_update_ret(&sha_ctx, (unsigned char*) sha256toHEX(sha256_client, (char*)tmp), 64);
    // mbedtls_sha256_update_ret(&sha_ctx, (unsigned char*) sha256toHEX(sha256_server, (char*)tmp), 64);
    mbedtls_sha256_update_ret(&sha_ctx, sha256_client, 32);
    mbedtls_sha256_update_ret(&sha_ctx, sha256_server, 32);
    mbedtls_sha256_finish_ret(&sha_ctx, sha256);
    sha256toHEX(sha256, (char*)tmp);
    mbedtls_sha256_free(&sha_ctx);

    snprintf((char *) buff, sizeof(buff),  URL REGISTER_PATH "?response=%s", (char *)tmp);

    if (!https.begin(*client, (char *)buff )) {
      Serial.println("Failed to begin https");
      delete client;
      return;
    };

    httpCode =  https.GET();
    if (httpCode != 200) {
      Serial.println("Failed to register");
      delete client;
      return;
    }
    Serial.println("Registration was accepted");

    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts_ret(&sha_ctx, 0);
    mbedtls_sha256_update_ret(&sha_ctx, (unsigned char*) TEST_TAG, strlen(TEST_TAG));
    mbedtls_sha256_update_ret(&sha_ctx, sha256, 32);
    mbedtls_sha256_finish_ret(&sha_ctx, sha256);
    sha256toHEX(sha256, (char*)tmp);
    mbedtls_sha256_free(&sha_ctx);

    if (!https.getString().equalsIgnoreCase((char*)tmp)) {
      Serial.println("Registered OK - but confirmation did not compute");
      delete client;
      return;
    }

    Serial.println("We are fully paired - we've proven to each other we know the secret & there is no MITM.");

    // store/keep the server KEY sha256 & our own key/cert.
    // note: server currently tracks our full cert (not just the key as it should).
  };

  Serial.println("Wait forever");
  for (;;) {};

exit :
  https.end();
  client->stop();
  delete client;
}
