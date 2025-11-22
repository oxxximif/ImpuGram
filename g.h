#pragma once

#include <sodium.h>
#include <cstdint>
#include <vector>
#include <string>
#include <array>
#include <unordered_map>

// Портативный тип сокета (чтобы не тащить winsock2.h в заголовок)
using SocketHandle = void*;

struct SecureContext {
    // Долгосрочные ключи (Ed25519 → X25519)
    unsigned char identity_private[32]{};
    unsigned char identity_public[32]{};
    unsigned char peer_identity_public[32]{};

    // Ratchet состояние
    unsigned char root_key[32]{};
    unsigned char send_chain_key[32]{};
    unsigned char recv_chain_key[32]{};
    uint32_t send_counter = 0;
    uint32_t recv_counter = 0;

    // Защита от replay + пропущенных сообщений
    std::unordered_map<uint32_t, std::array<unsigned char, 32>> skipped_message_keys;

    bool authenticated = false;
    bool ratchet_initialized = false;
};

// Инициализация криптографии
void crypto_init();

// Генерация долгосрочных ключей
void generate_identity_keys(SecureContext& ctx);

// Аутентифицированный handshake
bool authenticated_handshake(SecureContext& ctx, SocketHandle sock, bool is_server);

// Запуск Double Ratchet
void ratchet_initialize(SecureContext& ctx);

// Безопасная отправка (PFS + replay protection)
std::vector<unsigned char> secure_send(SecureContext& ctx, const std::string& message);

// Безопасный приём
std::string secure_receive(SecureContext& ctx, const std::vector<unsigned char>& packet);

// Обфускация как в MTProto
void obfuscate(std::vector<unsigned char>& data);
void deobfuscate(std::vector<unsigned char>& data);
