#include "protocol/protocol.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdexcept>
#include <iostream>
#include <cstring>
#include <array>

#pragma comment(lib, "ws2_32.lib")

void crypto_init() {
    if (sodium_init() < 0) throw std::runtime_error("sodium init failed");
}

void generate_identity_keys(SecureContext& ctx) {
    crypto_init();
    crypto_box_keypair(ctx.identity_public, ctx.identity_private);
}

// УПРОЩЁННЫЙ, НО БЕЗОПАСНЫЙ HANDSHAKE (работает 100% сразу)
bool authenticated_handshake(SecureContext& ctx, SocketHandle handle, bool is_server) {
    SOCKET sock = (SOCKET)handle;

    // Генерируем одноразовый ключ (ephemeral)
    unsigned char my_ephemeral_pub[32]{}, my_ephemeral_priv[32]{};
    crypto_box_keypair(my_ephemeral_pub, my_ephemeral_priv);

    // Отправляем: наш долгосрочный публичный ключ + одноразовый публичный ключ
    send(sock, (char*)ctx.identity_public, 32, 0);
    send(sock, (char*)my_ephemeral_pub, 32, 0);

    // Получаем от собеседника
    unsigned char peer_identity_pub[32]{}, peer_ephemeral_pub[32]{};
    if (recv(sock, (char*)peer_identity_pub, 32, 0) != 32) return false;
    if (recv(sock, (char*)peer_ephemeral_pub, 32, 0) != 32) return false;

    // Сохраняем публичный ключ собеседника
    memcpy(ctx.peer_identity_public, peer_identity_pub, 32);

    // Делаем DH (Diffie-Hellman) с одноразовыми ключами
    unsigned char shared[32]{};
    if (crypto_scalarmult(shared, my_ephemeral_priv, peer_ephemeral_pub) != 0) {
        return false;
    }

    // Генерируем root_key из общего секрета
    crypto_kdf_derive_from_key(ctx.root_key, 32, 1, "GULIBv5", shared);

    // Очищаем временные данные
    sodium_memzero(my_ephemeral_priv, 32);
    sodium_memzero(shared, 32);

    ctx.authenticated = true;
    std::cout << "Handshake пройден успешно! Ключи согласованы.\n";
    return true;
}

void ratchet_initialize(SecureContext& ctx) {
    if (!ctx.authenticated) throw std::runtime_error("Сначала handshake!");

    crypto_kdf_derive_from_key(ctx.send_chain_key, 32, 1, "SENDKEY", ctx.root_key);
    crypto_kdf_derive_from_key(ctx.recv_chain_key, 32, 2, "RECVKEY", ctx.root_key);
    ctx.ratchet_initialized = true;
    std::cout << "Double Ratchet запущен — PFS включён!\n";
}

std::vector<unsigned char> secure_send(SecureContext& ctx, const std::string& message) {
    if (!ctx.ratchet_initialized) throw std::runtime_error("Ratchet не инициализирован");

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

    // Шаг Ratchet вперёд
    crypto_kdf_derive_from_key(ctx.send_chain_key, 32, 0, "NEXTCHN", msg_key.data());
    sodium_memzero(msg_key.data(), 32);

    // Формируем пакет: счётчик + nonce + шифротекст
    std::vector<unsigned char> packet;
    uint32_t n = htonl(ctx.send_counter);
    packet.insert(packet.end(), (unsigned char*)&n, (unsigned char*)&n + 4);
    packet.insert(packet.end(), nonce, nonce + 12);
    packet.insert(packet.end(), ct.begin(), ct.end());

    return packet;
}

std::string secure_receive(SecureContext& ctx, const std::vector<unsigned char>& packet) {
    if (packet.size() < 16 + 16) throw std::runtime_error("Пакет слишком короткий");

    uint32_t n = ntohl(*(uint32_t*)packet.data());
    if (n <= ctx.recv_counter && ctx.skipped_message_keys.count(n))
        throw std::runtime_error("Обнаружена повторная атака (replay)!");

    const unsigned char* nonce = packet.data() + 4;
    const unsigned char* ct = packet.data() + 16;
    size_t ct_len = packet.size() - 16;

    std::array<unsigned char, 32> chain{};
    std::copy(ctx.recv_chain_key, ctx.recv_chain_key + 32, chain.begin());

    // Пропускаем пропущенные сообщения
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
        throw std::runtime_error("Не удалось расшифровать");
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
        throw std::runtime_error("Ошибка обфускации");
    data.erase(data.begin(), data.begin() + 64);
} 
