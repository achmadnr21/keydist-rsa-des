#ifndef SOCKET_WIN_H   
#define SOCKET_WIN_H

class Connection{
    SOCKET serverSocket;
    WSADATA wsData;
    sockaddr_in serverAddr;
    SOCKET clientSocket;
public:    
    int startServerSocket(unsigned short port, unsigned long address);
    int startClientSocket(unsigned short port, const char* address);
    int startServerMultipleClient();
    int acceptClient();
    int startServer();
    int startClient();
    SOCKET getClientSocket();
    SOCKET getServerSocket();
    void cleanUp();
    void closeSocket(SOCKET socket);
};

int Connection::startServerSocket(unsigned short port, unsigned long address){
    if (WSAStartup(MAKEWORD(2, 2), &wsData) != 0) {
        cerr << "Failed to initialize Winsock.\n";
        return -1;
    }
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        cerr << "Failed to create socket.\n";
        WSACleanup();
        return -1;
    }
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = address;
    return 1;
}
int Connection::startClientSocket(unsigned short port, const char* address){
    WSADATA wsData;
    if (WSAStartup(MAKEWORD(2, 2), &wsData) != 0) {
        cerr << "Failed to initialize Winsock.\n";
        return -1;
    }
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        cerr << "Failed to create socket.\n";
        WSACleanup();
        return -1;
    }
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = inet_addr(address);
    return 1;
}
int Connection::startServerMultipleClient(){
    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cerr << "Bind failed.\n";
        closesocket(serverSocket);
        WSACleanup();
        return -1;
    }
    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        cerr << "Listen failed.\n";
        closesocket(serverSocket);
        WSACleanup();
        return -1;
    }
    return 1;
}
int Connection::acceptClient(){
    // cout << "Server is listening for incoming Connections...\n";
    clientSocket = accept(serverSocket, nullptr, nullptr);
    if (clientSocket == INVALID_SOCKET) {
        cerr << "Accept failed.\n";
        closesocket(serverSocket);
        WSACleanup();
        return -1;
    }
    return 1;
}
int Connection::startServer(){
    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cerr << "Bind failed.\n";
        closesocket(serverSocket);
        WSACleanup();
        return -1;
    }
    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        cerr << "Listen failed.\n";
        closesocket(serverSocket);
        WSACleanup();
        return -1;
    }
    cout << "Server is listening for incoming Connections...\n";
    clientSocket = accept(serverSocket, nullptr, nullptr);
    if (clientSocket == INVALID_SOCKET) {
        cerr << "Accept failed.\n";
        closesocket(serverSocket);
        WSACleanup();
        return -1;
    }
    return 1;
}
int Connection::startClient(){
    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cerr << "Connection failed.\n";
        closesocket(clientSocket);
        WSACleanup();
        return -1;
    }
    return 1;
}
SOCKET Connection::getClientSocket(){
    return clientSocket;
}
SOCKET Connection::getServerSocket(){
    return serverSocket;
}
void Connection::cleanUp(){
    WSACleanup();
}
void Connection::closeSocket(SOCKET socket){
    closesocket(socket);
}
#endif