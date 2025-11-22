#include "protocol/protocol.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdexcept>
#include <iostream>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")

void crypto_init() {
    if (sodium_init() < 0) throw std::runtime_error("sodium init failed");
}

void generate_identity_keys(SecureContext& ctx) {
    crypto_init();
    crypto_box_keypair(ctx.identity_public, ctx.identity_private);
}

bool authenticated_handshake(SecureContext& ctx, SocketHandle handle, bool is_server) {
    SOCKET sock = (SOCKET)handle;

    unsigned char ephemeral_pub[32], ephemeral_priv[32];
    crypto_box_keypair(ephemeral_pub, ephemeral_priv);

    unsigned char signed_data[64];
    memcpy(signed_data, ctx.identity_public, 32);
    memcpy(signed_data + 32, ephemeral_pub, 32);

    unsigned char signature[64];
    if (crypto_sign_detached(signature, nullptr, signed_data, 64, ctx.identity_private) != 0)
        return false;

    // Отправляем: identity_pub + ephemeral_pub + подпись
    std::vector<unsigned char> hello;
    hello.insert(hello.end(), ctx.identity_public, ctx.identity_public + 32);
    hello.insert(hello.end(), ephemeral_pub, ephemeral_pub + 32);
    hello.insert(hello.end(), signature, signature + 64);
    send(sock, (char*)hello.data(), hello.size(), 0);

    // Получаем ответ
    unsigned char buffer[128]{};
    if (recv(sock, (char*)buffer, 128, 0) != 128)
        return false;

    unsigned char peer_identity[32], peer_ephemeral[32], peer_sig[64];
    memcpy(peer_identity, buffer, 32);
    memcpy(peer_ephemeral, buffer + 32, 32);
    memcpy(peer_sig, buffer + 64, 64);

    // Проверяем подпись
    if (crypto_sign_verify_detached(peer_sig, buffer, 64, peer_identity) != 0)
        return false;

    memcpy(ctx.peer_identity_public, peer_identity, 32);

    // DH с ephemeral ключами
    unsigned char dh1[32], dh2[32];
    if (crypto_scalarmult(dh1, ephemeral_priv, peer_ephemeral) != 0)
        return false;
    if (crypto_scalarmult(dh2, ctx.identity_private, ctx.peer_identity_public) != 0)
        return false;

    unsigned char input[64];
    memcpy(input, dh1, 32);
    memcpy(input + 32, dh2, 32);

    crypto_kdf_derive_from_key(ctx.root_key, 32, 1, "GULIBv3", input);

    sodium_memzero(ephemeral_priv, 32);
    sodium_memzero(dh1, 32);
    sodium_memzero(dh2, 32);
    sodium_memzero(input, 64);

    ctx.authenticated = true;
    std::cout << "Аутентификация успешна!\n";
    return true;
}

void ratchet_initialize(SecureContext& ctx) {
    if (!ctx.authenticated) throw std::runtime_error("Handshake first!");

    crypto_kdf_derive_from_key(ctx.send_chain_key, 32, 1, "SENDKEY", ctx.root_key);
    crypto_kdf_derive_from_key(ctx.recv_chain_key, 32, 2, "RECVKEY", ctx.root_key);
    ctx.ratchet_initialized = true;
    std::cout << "Double Ratchet запущен — PFS активен!\n";
}

std::vector<unsigned char> secure_send(SecureContext& ctx, const std::string& message) {
    if (!ctx.ratchet_initialized) throw std::runtime_error("Ratchet not ready");

    std::array<unsigned char, 32> msg_key{};
    crypto_kdf_derive_from_key(msg_key.data(), 32, ++ctx.send_counter, "MSGKEY", ctx.send_chain_key);

    unsigned char nonce[12];
    randombytes_buf(nonce, 12);

    std::vector<unsigned char> ct(message.size() + 16);
    unsigned long long clen;
    crypto_aead_chacha20poly1305_ietf_encrypt(ct.data(), &clen,
        (unsigned char*)message.data(), message.size(),
        nullptr, 0, nullptr, nonce, msg_key.data());
    ct.resize(clen);

    // Ratchet шаг
    crypto_kdf_derive_from_key(ctx.send_chain_key, 32, 0, "NEXTCHN", msg_key.data());
    sodium_memzero(msg_key.data(), 32);

    // Пакет: counter + nonce + ciphertext
    std::vector<unsigned char> packet;
    uint32_t n = htonl(ctx.send_counter);
    packet.insert(packet.end(), (unsigned char*)&n, (unsigned char*)&n + 4);
    packet.insert(packet.end(), nonce, nonce + 12);
    packet.insert(packet.end(), ct.begin(), ct.end());

    return packet;
}

std::string secure_receive(SecureContext& ctx, const std::vector<unsigned char>& packet) {
    if (packet.size() < 16 + 16) throw std::runtime_error("Packet too short");

    uint32_t n = ntohl(*(uint32_t*)packet.data());
    if (n <= ctx.recv_counter && ctx.skipped_message_keys.count(n))
        throw std::runtime_error("Replay attack!");

    const unsigned char* nonce = packet.data() + 4;
    const unsigned char* ct = packet.data() + 16;
    size_t ct_len = packet.size() - 16;

    std::array<unsigned char, 32> chain{};
    std::copy(ctx.recv_chain_key, ctx.recv_chain_key + 32, chain.begin());

    // Пропуск пропущенных сообщений
    for (uint32_t i = ctx.recv_counter + 1; i < n; ++i) {
        std::array<unsigned char, 32> mk{};
        crypto_kdf_derive_from_key(mk.data(), 32, i, "MSGKEY", chain.data());
        ctx.skipped_message_keys[i] = mk;
        crypto_kdf_derive_from_key(chain.data(), 32, 0, "NEXTCHN", mk.data());
    }

    std::array<unsigned char, 32> msg_key{};
    if (ctx.skipped_message_keys.count(n)) {
        msg_key = ctx.skipped_message_keys[n];
        ctx.skipped_message_keys.erase(n);
    } else {
        crypto_kdf_derive_from_key(msg_key.data(), 32, n, "MSGKEY", chain.data());
        crypto_kdf_derive_from_key(ctx.recv_chain_key, 32, 0, "NEXTCHN", msg_key.data());
    }
    ctx.recv_counter = n;

    std::vector<unsigned char> pt(ct_len);
    unsigned long long plen;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(pt.data(), &plen, nullptr,
            ct, ct_len, nullptr, 0, nonce, msg_key.data()) != 0) {
        throw std::runtime_error("Decrypt failed");
    }

    sodium_memzero(msg_key.data(), 32);
    pt.resize(plen);
    return std::string(pt.begin(), pt.end());
}

void obfuscate(std::vector<unsigned char>& data) {
    std::vector<unsigned char> header(64);
    randombytes_buf(header.data(), 56);
    *(uint64_t*)(header.data() + 56) = 0xddddddddddddddddULL;
    data.insert(data.begin(), header.begin(), header.end());
}

void deobfuscate(std::vector<unsigned char>& data) {
    if (data.size() < 64 || *(uint64_t*)(data.data() + 56) != 0xddddddddddddddddULL)
        throw std::runtime_error("Bad obfuscation");
    data.erase(data.begin(), data.begin() + 64);
}
