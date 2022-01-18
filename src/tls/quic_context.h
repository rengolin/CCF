// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "cert.h"
#include "crypto/base64.h"
#include "crypto/entropy.h"
#include "ds/logger.h"

#include <memory>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_openssl.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdarg.h>

#define BIDI_STREAM_DATA_MAX (128UL * 1024)

using namespace crypto;

namespace tls
{
  class Context
  {
  protected:
    crypto::OpenSSL::Unique_SSL_CTX cfg;
    crypto::OpenSSL::Unique_SSL ssl;
    crypto::EntropyPtr entropy;
    ngtcp2_conn *conn;
    ngtcp2_cid scid, dcid, ocid;
    ngtcp2_path path;
    int last_error;
    bool client, handshake_confirmed = false;
    int64_t stream_id = -1;

    static int set_encryption_secrets(
      SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level,
      const uint8_t *rx_secret,
      const uint8_t *tx_secret, size_t secretlen) {
      tls::Context *c = static_cast<tls::Context *>(SSL_get_app_data(ssl));
      ngtcp2_crypto_level level =
        ngtcp2_crypto_openssl_from_ossl_encryption_level(ossl_level);

      if ((!c->client || rx_secret) &&
        ngtcp2_crypto_derive_and_install_rx_key(c->conn, NULL, NULL, NULL, level,
                                                rx_secret, secretlen) != 0)
      {
        throw std::runtime_error("install rx_key failed");
        return 0;
      }
      if ((c->client || tx_secret ) && ngtcp2_crypto_derive_and_install_tx_key(c->conn, NULL, NULL, NULL, level,
                                                tx_secret, secretlen) != 0)
      {
        throw std::runtime_error("install tx_key failed");
        return 0;
      }
      return 1;
    }

    static int add_handshake_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level,
                                const uint8_t *data, size_t len)
    {
      tls::Context *c = static_cast<tls::Context *>(SSL_get_app_data(ssl));
      ngtcp2_crypto_level level =
          ngtcp2_crypto_openssl_from_ossl_encryption_level(ossl_level);
      int rv;

      rv = ngtcp2_conn_submit_crypto_data(c->conn, level, data, len);
      if (rv != 0)
      {
        throw std::runtime_error("submit crypto data failed");
        return 0;
      }
      return 1;
    }

    static int flush_flight(SSL *ssl) {
      (void)ssl;
      return 1;
    }

    static void log_print_cb(void *ctxt, const char *format, ...)
    {
      (void)ctxt;
      va_list args;
      va_start(args, format);
      vprintf(format, args);
      putchar('\n');
      va_end(args);
    }

    static int send_alert(SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level,
                          uint8_t alert) {
      tls::Context *c = static_cast<tls::Context *>(SSL_get_app_data(ssl));
      (void)ossl_level;

      c->last_error = NGTCP2_CRYPTO_ERROR | alert;

      return 1;
    }

    const SSL_QUIC_METHOD quic_methods = {
      set_encryption_secrets,
      add_handshake_data,
      flush_flight,
      send_alert
    };

    static void rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *ctx)
    {
      tls::Context *ctxt = static_cast<tls::Context *>(ctx->native_handle);
      ctxt->populate_rand(dest, destlen);
    }

    static int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
      uint8_t *token, size_t cidlen, void *user_data)
    {
      (void)conn;
      (void)user_data;

      SSL *ssl = static_cast<SSL *>(ngtcp2_conn_get_tls_native_handle(conn));
      tls::Context *ctxt = static_cast<tls::Context *>(SSL_get_app_data(ssl));
      ctxt->populate_rand(cid->data, cidlen);
      cid->datalen = cidlen;
      ctxt->populate_rand(token, NGTCP2_STATELESS_RESET_TOKENLEN);

      return 0;
    }

    static int recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags,
      int64_t stream_id, uint64_t offset, const uint8_t *data, size_t datalen,
      void *user_data, void *stream_user_data)
    {
      SSL *ssl = static_cast<SSL *>(ngtcp2_conn_get_tls_native_handle(conn));
      tls::Context *ctxt = static_cast<tls::Context *>(SSL_get_app_data(ssl));

      LOG_DEBUG_FMT("{} gets stream message at ID {}, offset {}, content: {:.{}}", ctxt->client? "Client" : "Server", stream_id, offset, (const char *)data, datalen);
      return 0;
    }

    static int handshake_confirmed_cb(ngtcp2_conn *conn, void *user_data)
    {
      SSL *ssl = static_cast<SSL *>(ngtcp2_conn_get_tls_native_handle(conn));
      tls::Context *ctxt = static_cast<tls::Context *>(SSL_get_app_data(ssl));

      LOG_DEBUG_FMT("{} confirms handshake is done", ctxt->client? "Client" : "Server");
      ctxt->handshake_confirmed = true;
      return 0;
    }

    static int extend_max_local_streams_bidi_cb(ngtcp2_conn *conn, uint64_t max_streams, void *user_data)
    {
      SSL *ssl = static_cast<SSL *>(ngtcp2_conn_get_tls_native_handle(conn));
      tls::Context *ctxt = static_cast<tls::Context *>(SSL_get_app_data(ssl));
      int rv;

      if (max_streams > 1) {
        throw std::runtime_error("More than 1 max streams");
        return NGTCP2_ERR_CALLBACK_FAILURE;
      }

      rv = ngtcp2_conn_open_bidi_stream(conn, &ctxt->stream_id, nullptr);
      if (rv && rv != NGTCP2_ERR_STREAM_ID_BLOCKED) {
        throw std::runtime_error(std::string("bidi stream open failed with ") + std::to_string(rv));
        return NGTCP2_ERR_CALLBACK_FAILURE;
      }

      return 0;
    }

    static int acked_stream_data_offset_cb(ngtcp2_conn *conn,
      int64_t stream_id, uint64_t offset, uint64_t datalen, void *user_data,
      void *stream_user_data)
    {
      SSL *ssl = static_cast<SSL *>(ngtcp2_conn_get_tls_native_handle(conn));
      tls::Context *ctxt = static_cast<tls::Context *>(SSL_get_app_data(ssl));

      LOG_DEBUG_FMT("Remote acked {} bytes of data at offset {} in stream {}", datalen, offset, stream_id);

      return 0;
    }

  public:
    void populate_rand(uint8_t *data, size_t datalen)
    {
      entropy->random(data, datalen);
    }

    Context(bool client, bool dtls) :
      cfg(client ? TLS_client_method() : TLS_server_method()),
      ssl(cfg),
      entropy(crypto::create_entropy()),
      client(client)
    {
      // QUIC only works with TLS 1.3 for now.
      if (dtls)
        throw std::runtime_error("QUIC does not support dTLS");
      SSL_CTX_set_min_proto_version(cfg, TLS1_3_VERSION);
      SSL_CTX_set_max_proto_version(cfg, TLS1_3_VERSION);
      SSL_set_min_proto_version(ssl, TLS1_3_VERSION);
      SSL_set_max_proto_version(ssl, TLS1_3_VERSION);
      SSL_set_app_data(ssl, this);
      SSL_CTX_set_quic_method(cfg, &quic_methods);
      SSL_set_quic_method(ssl, &quic_methods);
      if (client) {
        SSL_set_connect_state(ssl);
      } else {
        SSL_set_accept_state(ssl);
      }
    }

    int quic_init(
      const struct sockaddr *remote_addr,
      size_t remote_addrlen,
      const struct sockaddr *local_addr,
      size_t local_addrlen,
      ngtcp2_cid scid,
      ngtcp2_cid dcid,
      ngtcp2_cid ocid,
      ngtcp2_tstamp initial_ts)
    {
      int rv;
      ngtcp2_settings settings;
      ngtcp2_transport_params params;
      ngtcp2_path path = {
        {(struct sockaddr *)local_addr, local_addrlen},
        {(struct sockaddr *)remote_addr, remote_addrlen},
        this
      };
      this->path = path;
      ngtcp2_callbacks cbs = {
        .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
        .encrypt = ngtcp2_crypto_encrypt_cb,
        .decrypt = ngtcp2_crypto_decrypt_cb,
        .hp_mask = ngtcp2_crypto_hp_mask_cb,
        .recv_stream_data = recv_stream_data_cb,
        .acked_stream_data_offset = acked_stream_data_offset_cb,
        .extend_max_local_streams_bidi = extend_max_local_streams_bidi_cb,
        .rand = rand_cb,
        .get_new_connection_id = get_new_connection_id_cb,
        .update_key = ngtcp2_crypto_update_key_cb,
        .handshake_confirmed = handshake_confirmed_cb,
        .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
        .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
        .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb
      };
      if (client) {
        cbs.client_initial = ngtcp2_crypto_client_initial_cb;
        cbs.recv_retry = ngtcp2_crypto_recv_retry_cb;
      } else {
        cbs.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
      }

      this->scid = scid;
      this->dcid = dcid;
      this->ocid = ocid;

      ngtcp2_settings_default(&settings);
      settings.rand_ctx.native_handle = this;
      settings.initial_ts = initial_ts;
      settings.log_printf = log_print_cb;

      ngtcp2_transport_params_default(&params);
      params.initial_max_streams_bidi = 1;
      params.initial_max_stream_data_bidi_local = BIDI_STREAM_DATA_MAX;
      params.initial_max_stream_data_bidi_remote = BIDI_STREAM_DATA_MAX;
      params.initial_max_data = 1024 * 1024;  
      params.max_udp_payload_size = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
      if (client)
        rv = ngtcp2_conn_client_new(&conn, &this->dcid, &this->scid, &path, NGTCP2_PROTO_VER_V1,
          &cbs, &settings, &params, NULL, this);
      else {
        params.original_dcid = this->ocid;
        rv = ngtcp2_conn_server_new(&conn, &this->dcid, &this->scid, &path, NGTCP2_PROTO_VER_V1,
          &cbs, &settings, &params, NULL, this);
      }
      if (rv) return rv;
      ngtcp2_conn_set_tls_native_handle(conn, ssl);

      return 0;
    }

    virtual ~Context() {}

    ssize_t write_stream(uint8_t *buf, size_t buflen, const uint8_t *msg, size_t msglen, bool stream, ngtcp2_tstamp tstamp, ngtcp2_ssize *pdatalen)
    {
      ssize_t nwrite;
      int64_t sid = stream_id;
      uint32_t flag = NGTCP2_WRITE_STREAM_FLAG_NONE;

      if (!stream)
        sid = -1;
      nwrite = ngtcp2_conn_write_stream(this->conn, nullptr, nullptr, buf, buflen, pdatalen, flag, sid, (const uint8_t *)msg, msglen, tstamp);
      if (nwrite < 0 && nwrite != NGTCP2_ERR_WRITE_MORE) // TODO: handle errors in correct ways.
      {
        LOG_FAIL_FMT("{} error in write_stream, code {}", client? "Client" : "Server", nwrite);
        return -1;
      }
      LOG_DEBUG_FMT("{} written packet of size {}, datalen {}", client? "Client" : "Server", nwrite, *pdatalen);
      // nwrite is the packet size. The bytes from stream consumed is in *pdatalen.
      return nwrite;
    }

    ssize_t read_stream(const uint8_t *buf, size_t buflen, ngtcp2_tstamp tstamp)
    {
      ssize_t nread;
      ngtcp2_pkt_info pi = {0};
      LOG_DEBUG_FMT("{} read packet of size {}", client? "Client" : "Server", buflen);
      nread = ngtcp2_conn_read_pkt(conn, &this->path, &pi, buf, buflen, tstamp);
      if (nread != 0) {
        // TODO: handle errors
        LOG_FAIL_FMT("ngtcp2_conn_read_pkt fail: {}", ngtcp2_strerror(nread));
        return -1;
      }
      // When no error, the full packet is processed.
      return buflen;
    }

    int close()
    {
      return SSL_shutdown(ssl);
    }

    int verify_result()
    {
      return SSL_get_verify_result(ssl);
    }

    virtual std::string host()
    {
      return {};
    }

    std::vector<uint8_t> peer_cert()
    {
      auto bio = BIO_new(BIO_s_mem());
      i2d_X509_bio(bio, (X509*)SSL_get_peer_certificate(ssl));
      BUF_MEM* ptr;
      BIO_get_mem_ptr(bio, &ptr);
      BIO_free(bio);
      return std::vector<uint8_t>(ptr->data, ptr->data + ptr->length);
    }

    void set_require_auth(bool state)
    {
      SSL_CTX_set_verify(
        cfg, state ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, nullptr);
    }
  };
}
