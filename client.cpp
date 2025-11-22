#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "protocol/protocol.h"

int main() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    SecureContext ctx{};
    generate_identity_keys(ctx);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4433);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
        std::cerr << "Нет соединения\n";
        return 1;
    }

    // ← Исправлено: каст к SocketHandle
    if (!authenticated_handshake(ctx, (SocketHandle)sock, false)) {
        std::cerr << "Аутентификация провалилась!\n";
        return 1;
    }

    ratchet_initialize(ctx);

    std::string msg = "Привет! Я аутентифицирован с PFS!";
    auto packet = secure_send(ctx, msg);
    obfuscate(packet);
    send(sock, (char*)packet.data(), packet.size(), 0);

    char buf[65536];
    int n = recv(sock, buf, sizeof(buf), 0);
    if (n > 0) {
        std::vector<unsigned char> data((unsigned char*)buf, (unsigned char*)buf + n);
        deobfuscate(data);
        std::string reply = secure_receive(ctx, data);
        std::cout << "Сервер: " << reply << "\n";
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}
