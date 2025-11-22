#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "protocol/protocol.h"

int main() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    SecureContext ctx{};
    generate_identity_keys(ctx);

    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(4433);

    bind(listen_sock, (sockaddr*)&addr, sizeof(addr));
    listen(listen_sock, 1);
    std::cout << "Сервер запущен на порту 4433...\n";

    SOCKET client_sock = accept(listen_sock, nullptr, nullptr);
    std::cout << "Клиент подключился!\n";

    // ← ИСПРАВЛЕНО: передаём как SocketHandle
    if (!authenticated_handshake(ctx, (SocketHandle)client_sock, true)) {
        std::cerr << "Аутентификация провалилась!\n";
        closesocket(client_sock);
        closesocket(listen_sock);
        WSACleanup();
        return 1;
    }

    ratchet_initialize(ctx);

    char buf[65536];
    int n = recv(client_sock, buf, sizeof(buf), 0);
    if (n > 0) {
        std::vector<unsigned char> data((unsigned char*)buf, (unsigned char*)buf + n);
        deobfuscate(data);
        std::string msg = secure_receive(ctx, data);
        std::cout << "Клиент: " << msg << "\n";

        auto reply = secure_send(ctx, "Привет! Ты прошёл аутентификацию и защищён PFS!");
        obfuscate(reply);
        send(client_sock, (char*)reply.data(), reply.size(), 0);
    }

    closesocket(client_sock);
    closesocket(listen_sock);
    WSACleanup();
    return 0;
} 
