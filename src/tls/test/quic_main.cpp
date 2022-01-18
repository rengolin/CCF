// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "crypto/certs.h"
#include "crypto/key_pair.h"
#include "crypto/verifier.h"

#include <openssl/err.h>
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "ds/buffer.h"
#include "ds/logger.h"
#include "tls/client.h"
#include "tls/msg_types.h"
#include "tls/server.h"

#include <chrono>
#include <doctest/doctest.h>
#include <iostream>
#include <memory>
#include <netdb.h>
#include <string>
#include <ngtcp2/ngtcp2.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>

#define TEST_CLIENT_SCID 0xdeadbeef80000000UL
#define TEST_CLIENT_DCID 0x80000000deadbeefUL
#define TEST_SERVER_SCID 0x90000000deadbeefUL
#define TEST_SERVER_DCID TEST_CLIENT_SCID

using namespace std;
using namespace crypto;
using namespace tls;

ngtcp2_tstamp get_tstamp()
{
  auto start = std::chrono::system_clock::now().time_since_epoch();

  return (chrono::duration_cast<std::chrono::nanoseconds>(start)).count();
}

struct NetworkCA
{
  shared_ptr<crypto::KeyPair> kp;
  crypto::Pem cert;
};

/// Get self-signed CA certificate.
NetworkCA get_ca()
{
  // Create a CA with a self-signed certificate
  auto kp = crypto::make_key_pair();
  auto crt = kp->self_sign("CN=issuer");
  LOG_DEBUG_FMT("New self-signed CA certificate:{}", crt.str());
  return {kp, crt};
}

/// Creates a tls::Cert with a new CA using a new self-signed Pem certificate.
unique_ptr<tls::Cert> get_dummy_cert(NetworkCA& net_ca, string name)
{
  // Create a CA with a self-signed certificate
  auto ca = make_unique<tls::CA>(CBuffer(net_ca.cert.str()));

  // Create a signing request and sign with the CA
  auto kp = crypto::make_key_pair();
  auto csr = kp->create_csr("CN=" + name);
  LOG_DEBUG_FMT("CSR for {} is:{}", name, csr.str());

  auto crt = net_ca.kp->sign_csr(net_ca.cert, csr);
  LOG_DEBUG_FMT("New CA-signed certificate:{}", crt.str());

  // Verify node certificate with the CA's certificate
  auto v = crypto::make_verifier(crt);
  REQUIRE(v->verify_certificate({&net_ca.cert}));

  // Create a tls::Cert with the CA, the signed certificate and the private key
  auto pk = kp->private_key_pem();
  return make_unique<Cert>(move(ca), crt, pk);
}

/// Test runner, with various options for different kinds of tests.
void run_test_case(
  int dgram,
  const uint8_t* message,
  size_t message_length,
  const uint8_t* response,
  size_t response_length,
  unique_ptr<tls::Cert> server_cert,
  unique_ptr<tls::Cert> client_cert,
  bool requires_auth)
{
  struct sockaddr_in client_addr, server_addr;
  size_t client_addrlen = sizeof(client_addr), server_addrlen = sizeof(server_addr);
  ngtcp2_cid client_scid, client_dcid, server_scid, server_dcid;
  int pfd[2]; // 0 client, 1 server
  int rv;
  uint8_t client_buf[NGTCP2_MAX_UDP_PAYLOAD_SIZE];
  uint8_t server_buf[NGTCP2_MAX_UDP_PAYLOAD_SIZE];

  // Create a pair of client/server
  tls::Server server(move(server_cert), dgram);
  server.set_require_auth(requires_auth);
  tls::Client client(move(client_cert), dgram);
  client.set_require_auth(requires_auth);
  // ngtcp2 does not support non AF_INET sockets.
  if ((pfd[0] = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    throw runtime_error("Failed to create client socket: " + string(strerror(errno)));
  if ((pfd[1] = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    throw runtime_error("Failed to create server socket: " + string(strerror(errno)));
  inet_pton(AF_INET, "127.0.0.1", &(client_addr.sin_addr));
  client_addr.sin_port = htons(444);
  client_addr.sin_family = AF_INET;
  inet_pton(AF_INET, "127.0.0.1", &(server_addr.sin_addr));
  server_addr.sin_port = htons(445);
  server_addr.sin_family = AF_INET;
  if (::bind(pfd[0], (struct sockaddr *)&client_addr, client_addrlen) == -1)
    throw runtime_error("Failed to bind client local socket: " + string(strerror(errno)));
  if (connect(pfd[0], (struct sockaddr *)&server_addr, server_addrlen) == -1)
    throw runtime_error("Failed to connect client socket to server: " + string(strerror(errno)));
  if (::bind(pfd[1], (struct sockaddr *)&server_addr, server_addrlen) == -1)
    throw runtime_error("Failed to bind server local socket: " + string(strerror(errno)));
  if (connect(pfd[1], (struct sockaddr *)&client_addr, client_addrlen) == -1)
    throw runtime_error("Failed to connect server socket to client: " + string(strerror(errno)));

  *(uint64_t*)client_scid.data = TEST_CLIENT_SCID;
  client_scid.datalen = sizeof(TEST_CLIENT_SCID);
  *(uint64_t*)client_dcid.data = TEST_CLIENT_DCID;
  client_dcid.datalen = sizeof(TEST_CLIENT_DCID);
  *(uint64_t*)server_scid.data = TEST_SERVER_SCID;
  server_scid.datalen = sizeof(TEST_SERVER_SCID);
  *(uint64_t*)server_dcid.data = TEST_SERVER_DCID;
  server_dcid.datalen = sizeof(TEST_SERVER_DCID);

  LOG_INFO_FMT("Init started");
  if (client.quic_init((struct sockaddr *)&server_addr, server_addrlen,
                   (struct sockaddr *)&client_addr, client_addrlen,
                   client_scid, client_dcid, client_dcid, get_tstamp()))
  {
    throw runtime_error(
      "Client quic init failed");
  }
  server.quic_init((struct sockaddr *)&client_addr, client_addrlen,
                   (struct sockaddr *)&server_addr, server_addrlen,
                   server_scid, server_dcid, client_dcid, get_tstamp());

  // Create a thread for the client handshake
  thread client_thread([&]() {
    ngtcp2_ssize datalen = 0;
    ssize_t pktlen;

    LOG_INFO_FMT("Client ready to send stream");
    while (datalen < (ssize_t)message_length) {
      pktlen = client.write_stream(client_buf, sizeof(client_buf), (const uint8_t *)message, message_length, true, get_tstamp(), &datalen);
      LOG_INFO_FMT("Client pktlen is {}", pktlen);
      if (pktlen > 0) {
        send(pfd[0], client_buf, pktlen, 0);
        pktlen = recv(pfd[0], client_buf, sizeof(client_buf), 0);
        client.read_stream(client_buf, pktlen, get_tstamp());
      }
    }
    LOG_INFO_FMT("Client stream send done");
  });
  thread server_thread([&]() {
    ssize_t pktlen;
    ngtcp2_ssize datalen;

    LOG_INFO_FMT("Server ready to receive stream");
    while (1) {
      pktlen = recv(pfd[1], server_buf, sizeof(server_buf), 0);
      server.read_stream(server_buf, pktlen, get_tstamp());
      pktlen = server.write_stream(server_buf, sizeof(server_buf), nullptr, 0, false, get_tstamp(), &datalen);
      if (pktlen > 0)
        send(pfd[1], server_buf, pktlen, 0);
    }
    LOG_INFO_FMT("Server do handshake done");
  });

  client_thread.join();
  server_thread.join();

  LOG_INFO_FMT("Closing connection");
  client.close();
  server.close();
  close(pfd[0]);
  close(pfd[1]);
}

/*
TEST_CASE("unverified handshake")
{
  // Create a CA
  auto ca = get_ca();

  // Create bogus certificate
  auto server_cert = get_dummy_cert(ca, "server");
  auto client_cert = get_dummy_cert(ca, "client");

  // Just testing handshake, does not verify certificates, no communication.
  LOG_INFO_FMT("About to test");
  run_test_case(
    0,
    (const uint8_t*)"",
    0,
    (const uint8_t*)"",
    0,
    move(server_cert),
    move(client_cert),
    false);
}

TEST_CASE("unverified communication")
{
  const uint8_t message[] = "Hello World!";
  size_t message_length = strlen((const char*)message);
  const uint8_t response[] = "Hi back!";
  size_t response_length = strlen((const char*)response);

  // Create a CA
  auto ca = get_ca();

  // Create bogus certificate
  auto server_cert = get_dummy_cert(ca, "server");
  auto client_cert = get_dummy_cert(ca, "client");

  // Just testing communication channel, does not verify certificates.
  run_test_case(
    0,
    message,
    message_length,
    response,
    response_length,
    move(server_cert),
    move(client_cert),
    false);
}

TEST_CASE("verified handshake")
{
  // Create a CA
  auto ca = get_ca();

  // Create bogus certificate
  auto server_cert = get_dummy_cert(ca, "server");
  auto client_cert = get_dummy_cert(ca, "client");

  // Just testing handshake, no communication, but verifies certificates.
  run_test_case(
    0,
    (const uint8_t*)"",
    0,
    (const uint8_t*)"",
    0,
    move(server_cert),
    move(client_cert),
    true);
}
 */

TEST_CASE("verified communication")
{
  const uint8_t message[] = "Hello World!";
  size_t message_length = strlen((const char*)message);
  const uint8_t response[] = "Hi back!";
  size_t response_length = strlen((const char*)response);

  // Create a CA
  auto ca = get_ca();

  // Create bogus certificate
  auto server_cert = get_dummy_cert(ca, "server");
  auto client_cert = get_dummy_cert(ca, "client");

  // Testing communication channel, verifying certificates.
  run_test_case(
    0,
    message,
    message_length,
    response,
    response_length,
    move(server_cert),
    move(client_cert),
    true);
}

/*
TEST_CASE("large message")
{
  // Uninitialised on purpose, we don't care what's in here
  size_t len = 8192;
  uint8_t buf[len];
  auto message = crypto::b64_from_raw(buf, len);

  // Create a CA
  auto ca = get_ca();

  // Create bogus certificate
  auto server_cert = get_dummy_cert(ca, "server");
  auto client_cert = get_dummy_cert(ca, "client");

  // Testing communication channel, verifying certificates.
  run_test_case(
    0,
    (const uint8_t*)message.data(),
    message.size(),
    (const uint8_t*)message.data(),
    message.size(),
    move(server_cert),
    move(client_cert),
    true);
}
 */