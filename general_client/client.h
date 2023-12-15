#ifndef CLIENT_H
#define CLIENT_H

#include "../general.h"

Connection con;
HANDLE listen_thread, send_thread;
long long int P = 11, Q = 19;
string client_id = "default";

struct Data{
    SOCKET sock;
    string key;
};



//prototype
void setUnamePQ(string username, long long int p, long long int q);
int run_client(unsigned int PORT);
Data createNewData ();
DWORD WINAPI listenThread(LPVOID lpParam);
DWORD WINAPI sendThread(LPVOID lpParam);
int recv_key(SOCKET client_socket, string msg);

void setUnamePQ(string username, long long int p, long long int q){
    client_id = username;
    P = p;
    Q = q;
}
int run_client(unsigned int PORT) {
    // Jika return -1 maka error
    if (con.startClientSocket(PORT, "127.0.0.1") == -1) return 0;
    if (con.startClient() == -1) return 0;
    SOCKET client_socket = con.getClientSocket();
    
    Rsa rsa(P, Q);
    int amount_recv = 0, 
        n_client = 0, 
        n_server = 0, 
        n_client_from_server=0, 
        n_client_encrypt = 0, 
        n_server_encrypt = 0, 
        n_client_from_server_encrypt=0, 
        idLength=0,
        des_key_len = 16;
    int self_ekey = rsa.getPublicKey().first;
    int self_nkey = rsa.getPublicKey().second;
    pair<int, int> server_pk;
    string des_key = "";
    
    // Pertukaran public key
    system("cls");
    cout << "============== INIT:PUBLIC_Key EXCHANGE ==============\n";
    cout << "client public key\t: ("<< self_ekey << ","<< self_nkey << ")\n";
    send(client_socket, reinterpret_cast<char*>(&self_ekey), sizeof(self_ekey), 0);
    send(client_socket, reinterpret_cast<char*>(&self_nkey), sizeof(self_nkey), 0);
    if ((server_pk.first = recv_key(client_socket, "[ERROR] receiving client public key e")) == -1) return 0;
    if ((server_pk.second = recv_key(client_socket, "[ERROR] receiving client public key n")) == -1) return 0;
    cout << "server public key\t: ("<<server_pk.first << ","<<server_pk.second << ")\n\n";


    // Pertukaran N
    cout << "==============\tN::CLIENT\t==============\n";
    // Kirim N1
    n_client = rsa.generateKeyDistribution(server_pk.first, server_pk.second);
    n_client_encrypt = rsa.encrypt(n_client, server_pk.first, server_pk.second);
    send(client_socket, reinterpret_cast<char*>(&n_client_encrypt), sizeof(n_client_encrypt), 0);
    cout << "[SEND]:: Mengirimkan N1 atau N_client ke server\n";
    cout << "N1\t: " << n_client << "\n";
    cout << "N1 PU_S\t: " << n_client_encrypt << "\n";
    // Terima N1
    amount_recv = recv(client_socket, reinterpret_cast<char*>(&n_client_from_server_encrypt), sizeof(n_client_from_server_encrypt), 0);
    cout << "[RECV]:: Menerima N1 atau N_client dari server\n";
    if (amount_recv <= 0) {
        cerr << "[FAILED]::Error receiving client n_key.\n";
        con.closeSocket(client_socket);
        return 0;
    }
    n_client_from_server = rsa.decrypt(n_client_from_server_encrypt);
    cout << "N1 PU_C\t: " << n_client_from_server_encrypt << "\n";
    cout << "N1\t: " << n_client_from_server << "\n";
    cout << "check >> (N client, N client dec) = (" << n_client << "," << n_client_from_server << ")\n";
    if (n_client_from_server != n_client){
        cerr << "Conection failed due to wrong n_key client from server\n";
        con.closeSocket(client_socket);
        return 0;
    }
    cout << "N client in client and N client decrypted is equal.\n\n";
    
    cout << "==============\tN::SERVER\t==============" << "\n";
    // Terima N2
    amount_recv = recv(client_socket, reinterpret_cast<char*>(&n_server_encrypt), sizeof(n_server_encrypt), 0);
    cout << "[RECV]:: Menerima N2 atau N_server dari server\n";
    if (amount_recv <= 0) {
        cerr << "[FAILED]:: Error receiving server n_key.\n";
        return 0;
    }
    n_server = rsa.decrypt(n_server_encrypt);
    cout << "N2 PU_C\t: " << n_server_encrypt << "\n";
    cout << "N2\t: " << n_server << "\n";
    // Kirim N2
    n_server_encrypt = rsa.encrypt(n_server, server_pk.first, server_pk.second);
    send(client_socket, reinterpret_cast<char*>(&n_server_encrypt), sizeof(n_server_encrypt), 0);
    cout << "[SEND]:: Mengirimkan N2 atau N_server ke server\n";
    cout << "N2 PU_S\t: " << n_server_encrypt << "\n\n";
    // Registrasi
    cout << "[CLIENT][USERNAME]\t: " << client_id << "\n\n";
    int messageLength = client_id.length();
    send(client_socket, reinterpret_cast<char*>(&messageLength), sizeof(messageLength), 0);
    send(client_socket, client_id.c_str(), messageLength, 0);
    
    // Terima DES key
    
    char* buffer = new char[des_key_len+1];
    amount_recv = recv(client_socket, buffer, des_key_len, 0);
    if (amount_recv <= 0) {
        cerr << "[FAILED]:: Error receiving des key from server.\n";
        delete[] buffer;
        return 0;
    }        
    buffer[amount_recv] = '\0';
    des_key = buffer;
    cout << "[RECV][DES]\t\t: " << des_key << "\n\n";
    delete[] buffer;

    // Chat dimulai
    Data data = createNewData();
    data.sock = client_socket;
    // Jika ingin lihat bagaimana efek dari pengiriman DES nya,
    // maka comment line dibawah ini
    data.key = des_key;
    send_thread = CreateThread(NULL, 0, sendThread, &data, 0, NULL);
    listen_thread = CreateThread(NULL, 0, listenThread, &data, 0, NULL);
    
    if (listen_thread == NULL || send_thread == NULL) {
        cerr << "[FAILED]:: Error creating threads" << endl;
    }

    WaitForSingleObject(listen_thread, INFINITE);
    WaitForSingleObject(send_thread, INFINITE);

    CloseHandle(listen_thread);
    CloseHandle(send_thread);
    
    con.closeSocket(client_socket);
    con.cleanUp();
    return 0;
}

Data createNewData (){
    Data temp;
    temp.sock = 0;
    temp.key = "FEDCBA9876543210";
    return temp;
}

DWORD WINAPI listenThread(LPVOID lpParam) {
    Data data = *static_cast<Data*>(lpParam);
    SOCKET clientSocket = data.sock;
	// DES_Encryption DES; 
    Pesan message;
    message.setKey(data.key);
    string received_message;
    int messageLength=0;
    int des_iteration=0;
    int amount_recv=0;
    cout << "Type with format and hit ENTER to send message\n";
    cout << "<username_tosend> <message...>\n\n";
    while (true) {
        // Menerima panjang pesan dari server
        amount_recv = recv(clientSocket, reinterpret_cast<char*>(&messageLength), sizeof(messageLength), 0);
        if (amount_recv <= 0) {
            cerr << "\n\n[FAILED]:: Error receiving message!!!...\nClosing thread.\n";
            CloseHandle(send_thread);
            break;
        }
        // Membuat buffer sesuai panjang pesan dari server
        char* buffer = new char[messageLength+1];
        // Menerima pesan dari server
        amount_recv = recv(clientSocket, buffer, messageLength, 0);
        if (amount_recv <= 0) {
            cerr << "[FAILED]:: Error receiving message.\n";
            delete[] buffer;
            CloseHandle(send_thread);
            break;
        }
        // Batasi string dengan null agar hanya ditampilkan string yang sesuai
        buffer[amount_recv] = '\0';
        message.setMessage(buffer);
        // DES Decryption
        message.messageDecryption();
        cout << "CIPHER HEX\t: " << buffer << "\n";
        cout << "ASCII STR\t: " << message.getMessage() << "\n\n";
        // Hapus buffer setelah digunakan agar memori tidak tertumpuk
        delete[] buffer;
        
    }
    return 0; 
}
const string commands[1] = {"!clear"};
DWORD WINAPI sendThread(LPVOID lpParam) {
    Data data = *static_cast<Data*>(lpParam);
    SOCKET clientSocket = data.sock;
	// DES_Encryption DES; 
    Pesan message;
    message.setKey(data.key);
    string userMessage;
    int messageLength=0;
    int des_iteration=0;
    int amount_recv=0;

    while (true) {
        // Prompt pesan kepada user server
        // cout << "Enter a message: "; 
        getline(cin, userMessage); cout << "\n";
        if (userMessage[0] == '!') {
            if(userMessage == commands[0]){
                system("cls");
                continue;
            }
        }
        message.setMessage(userMessage);
        // DES Encryption
        message.messageEncryption();
        // Kirim panjang pesan yang akan diterima oleh client
        messageLength = message.getMessage().length();
        send(clientSocket, reinterpret_cast<char*>(&messageLength), sizeof(messageLength), 0);
        // Kirim pesan ke client
        send(clientSocket, message.getMessage().c_str(), messageLength, 0);
    }
    return 0; 
}

int recv_key(SOCKET client_socket, string msg){
    int n_client = 0, amount_recv;
    amount_recv = recv(client_socket, reinterpret_cast<char*>(&n_client), sizeof(n_client), 0);
    if (amount_recv <= 0) {
        cerr << msg << "\n";
        con.closeSocket(client_socket);
        return -1;
    }
    return n_client;
}

#endif