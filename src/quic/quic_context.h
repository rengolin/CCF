// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "cert.h"
#include "crypto/base64.h"
#include "crypto/entropy.h"
#include "ds/logger.h"
#include "tls/tls.h"

#include <memory>
#include <openssl/bio.h>
#include <openssl/ssl.h>

using namespace crypto;

namespace tls
{
  class QUICContext
  {
  public:
    QUICContext() : { }

    virtual ~QUICContext() = default;

   bool peer_cert_ok()
    {
      return SSL_get_verify_result(ssl) == X509_V_OK;
    }

    std::string get_verify_error()
    {
      return X509_verify_cert_error_string(SSL_get_verify_result(ssl));
    }

    virtual std::string host()
    {
      return {};
    }

    std::vector<uint8_t> peer_cert()
    {
      // CodeQL complains that we don't verify the peer certificate. We don't
      // need to do that because it's been verified before and we use
      // SSL_get_peer_certificate just to extract it from the context.

      crypto::OpenSSL::Unique_X509 cert(
        SSL_get_peer_certificate(ssl), /*check_null=*/false);
      if (!cert)
      {
        LOG_TRACE_FMT("Empty peer cert");
        return {};
      }
      crypto::OpenSSL::Unique_BIO bio;
      if (!i2d_X509_bio(bio, cert))
      {
        LOG_TRACE_FMT("Can't convert X509 to DER");
        return {};
      }

      // Get the total length of the DER representation
      auto len = BIO_get_mem_data(bio, nullptr);
      if (!len)
      {
        LOG_TRACE_FMT("Null X509 peer cert");
        return {};
      }

      // Get the BIO memory pointer
      BUF_MEM* ptr = nullptr;
      if (!BIO_get_mem_ptr(bio, &ptr))
      {
        LOG_TRACE_FMT("Invalid X509 peer cert");
        return {};
      }

      // Return its contents as a vector
      auto ret = std::vector<uint8_t>(ptr->data, ptr->data + len);
      return ret;
    }
  };
}
