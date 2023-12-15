#ifndef SERVER_H
#define SERVER_H

#include "../general.h"
struct isConnected {
    SOCKET value = 0;
};

struct desKey {
    string value = "";
};

Connection con;
map<string, isConnected> client_sockets;
map<string, desKey> client_des_keys;
vector<string> client_ids;
const long long int P = 11, Q = 17;

struct Data{
    SOCKET sock;
    HANDLE thread;
    string message;
    string id;
};

Data createNewData (){
    Data temp;
    temp.sock = 0;
    temp.thread = NULL;
    temp.message = "";
    temp.id = "";
    return temp;
}

// prototype function
int run_server(unsigned short PORT);
DWORD WINAPI listenThread(LPVOID lpParam);
DWORD WINAPI sendThread(LPVOID lpParam);
int recv_key(SOCKET client_socket, string msg);
void eraseClient(string val);

int run_server(unsigned short PORT){
    if (con.startServerSocket(PORT, INADDR_ANY) == -1) return 0;
    if (con.startServerMultipleClient() == -1) return 0;
    SOCKET server_socket = con.getServerSocket();

    HANDLE listen_thread;
    vector<HANDLE> threads;

    int amount_recv = 0;
    int n_client = 0, 
        n_server = 0, 
        n_server_from_client=0,
        n_client_encrypt = 0, 
        n_server_encrypt = 0, 
        n_server_from_client_encrypt =0;
    int idLength = 0;
    pair<int, int> client_pk;

    while(true){
        con.acceptClient();
        SOCKET client_socket = con.getClientSocket();
        Rsa rsa(P, Q);
        int self_ekey = rsa.getPublicKey().first;
        int self_nkey = rsa.getPublicKey().second;

        // Pertukaran public key
        if ((client_pk.first = recv_key(client_socket, "Error receiving client public key.")) == -1) continue;
        if ((client_pk.second = recv_key(client_socket, "Error receiving client public key.")) == -1) continue;
        system("cls");
        cout << "============== INIT:PUBLIC_Key EXCHANGE ==============\n";
        cout << "client public key\t: ("<< client_pk.first << ","<< client_pk.second << ")\n";
        cout << "server public key\t: ("<< self_ekey << ","<< self_nkey << ")\n\n";
        send(client_socket, reinterpret_cast<char*>(&self_ekey), sizeof(self_ekey), 0);
        send(client_socket, reinterpret_cast<char*>(&self_nkey), sizeof(self_nkey), 0);

        // N Exchange
        cout << "==============\tN::CLIENT\t==============\n";
        // Receive N1
        amount_recv = recv(client_socket, reinterpret_cast<char*>(&n_client_encrypt), sizeof(n_client_encrypt), 0);
        cout << "[RECV]:: Menerima N1 dari Client\n";
        if (amount_recv <= 0) {
            cerr << "[FAILED]:: Error receiving client n_key.\n";
            continue;
        }
        n_client = rsa.decrypt(n_client_encrypt);
        cout << "N1 PU_S\t: " << n_client_encrypt << "\n";
        cout << "N1\t: " << n_client << "\n";
        // Send N1
        n_client_encrypt = rsa.encrypt(n_client, client_pk.first, client_pk.second);

        cout <<"[SEND]:: Mengirimkan N1 ke Client\n";
        send(client_socket, reinterpret_cast<char*>(&n_client_encrypt), sizeof(n_client_encrypt), 0);
        cout << "N1 PU_C\t: " << n_client_encrypt << "\n\n";
    
        cout << "==============\tN::SERVER\t==============" << "\n";
        // Send N2
        n_server=rsa.generateKeyDistribution(client_pk.first, client_pk.second);
        n_server_encrypt = rsa.encrypt(n_server, client_pk.first, client_pk.second);

        cout << "[SEND]:: Mengirimkan N2 ke Client\n";
        send(client_socket, reinterpret_cast<char*>(&n_server_encrypt), sizeof(n_server_encrypt), 0);
        cout << "N2\t: " << n_server << "\n";
        cout << "N2 PU_C\t: " << n_server_encrypt << "\n";
        // Receive N2
        amount_recv = recv(client_socket, reinterpret_cast<char*>(&n_server_from_client_encrypt), sizeof(n_server_from_client_encrypt), 0);
        cout << "[RECV]:: Menerima N2 dari Client\n";
        if (amount_recv <= 0) {
            cerr << "[FAILED]:: Error receiving client n_key.\n";
            con.closeSocket(client_socket);
            continue;
        }
        n_server_from_client = rsa.decrypt(n_server_from_client_encrypt);
        cout << "N1 PU_C\t: " << n_server_from_client_encrypt << "\n";
        cout << "N1\t: " << n_server_from_client << "\n\n";
        
        cout << "check >> (N server, N server dec) = (" << n_server << "," << n_server_from_client << ")\n";
        if (n_server_from_client != n_server){
            cerr << "Conection failed due to wrong n_key server from client\n";
            con.closeSocket(client_socket);
            continue;
        }
        
        cout << "N server in server and N server decrypted is equal.\n\n";
        // register client ke daftar
        cout << "[CLIENT][REGISTERED][USERNAME]\t: ";
        amount_recv = recv(client_socket, reinterpret_cast<char*>(&idLength), sizeof(idLength), 0);
        if (amount_recv <= 0) {
            cerr << "Error receiving id length.\n";
            continue;
        }
        char* buffer = new char[idLength+1];
        amount_recv = recv(client_socket, buffer, idLength, 0);
        if (amount_recv <= 0) {
            cerr << "Error receiving message.\n";
            delete[] buffer;
            continue;
        }        
        buffer[amount_recv] = '\0';
        string client_id = buffer;
        cout << client_id << "\n";
        delete[] buffer;

        // Regist ke daftar
        client_ids.push_back(client_id);
        client_sockets[client_id].value = client_socket;


        Data data = createNewData();
        data.sock = client_socket;
        data.message = client_id;
        data.id = client_id;
        listen_thread = CreateThread(NULL, 0, listenThread, &data, 0, NULL);

        if (listen_thread == NULL) {
            cerr << "Error creating threads" << endl;
            closesocket(client_socket);
            continue;
        }

        threads.push_back(listen_thread);
    }

    WaitForMultipleObjects(static_cast<DWORD>(threads.size()), threads.data(), TRUE, INFINITE);
    for (auto& thread : threads) {
        CloseHandle(thread);
    }
    for (auto& client_socket : client_sockets){
        con.closeSocket(client_socket.second.value);
    }
    con.closeSocket(server_socket);
    con.cleanUp();
}

DWORD WINAPI sendThread(LPVOID lpParam) {
    Data data = *static_cast<Data*>(lpParam);
    string sender_id = data.id;
    Pesan message;
    string userMessage;
    int messageLength=0;
    int des_iteration=0;
    int amount_recv=0;

    size_t spacePos = data.message.find(' '); 
    string name = data.message.substr(0, spacePos);
    string msg = data.message.substr(spacePos + 1);
    // jika nama yang ingin dikirim dengan nama pengirim sama, maka kirim pesan error
    if (name == sender_id){
        cerr << "[SEND][FAILED][USER]\t: (" << name << ") cannot send message to itself\n\n";
        SOCKET client_socket = client_sockets[name].value;
        message.setKey(client_des_keys[name].value);
        message.setMessage("[SERVER]: You Are Sending Message To Yourself!...");
        message.messageEncryption();
        messageLength = message.getMessage().length();
        send(client_socket, reinterpret_cast<char*>(&messageLength), sizeof(messageLength), 0);
        send(client_socket, message.getMessage().c_str(), messageLength, 0);
        return 0; 
    }
    
    if (client_sockets[name].value == 0){
        cerr << "[SEND][FAILED][USER]\t: (" << name << ") not found\n\n";
        return 0; 
    }
    SOCKET client_socket = client_sockets[name].value;
    message.setKey(client_des_keys[name].value);
    message.setMessage("["+sender_id+"]: "+msg);
    // DES Encryption
    message.messageEncryption();
    messageLength = message.getMessage().length();
    send(client_socket, reinterpret_cast<char*>(&messageLength), sizeof(messageLength), 0);
    send(client_socket, message.getMessage().c_str(), messageLength, 0);
    return 0; 
}

void eraseClient(string val){
    // hapus client dari client_ids
    client_ids.erase(std::remove_if(client_ids.begin(), client_ids.end(), [&](const std::string &client) {
        return client == val;
    }), client_ids.end());
    // hapus client_sockets[val] dari client_sockets
    client_sockets.erase(val);
    // hapus client_des_keys[val] dari client_des_keys
    client_des_keys.erase(val);
}

DWORD WINAPI listenThread(LPVOID lpParam) {
    Data data = *static_cast<Data*>(lpParam);
    SOCKET client_socket = data.sock;
    string sender_id = data.id;
    Pesan message;
    string received_message;
    int messageLength=0;
    int des_iteration=0;
    int amount_recv=0;
    int des_key_len = 16;
    string des_key = "";

    // Mengirim DES Key.
    cout << "[SEND][DES]:: ";
    message.randomizerKey();
    des_key = message.getKey();
    client_des_keys[data.message].value = des_key; 
    cout << des_key << "\n\n";
    send(client_socket, des_key.c_str(), des_key_len, 0);

    while (true) {
        amount_recv = recv(client_socket, reinterpret_cast<char*>(&messageLength), sizeof(messageLength), 0);
        if (amount_recv <= 0) {
            cerr << "\n\nError receiving message.\nClosing thread.\n";
            eraseClient(data.message);
            break;
        }
        char* buffer = new char[messageLength+1];
        amount_recv = recv(client_socket, buffer, messageLength, 0);
        if (amount_recv <= 0) {
            cerr << "Error receiving message.\n";
            eraseClient(data.message);
            delete[] buffer;
            break;
        }
        buffer[amount_recv] = '\0';
        message.setMessage(buffer);
        // DES Decrypt
        message.messageDecryption();
        cout << "CIPHER HEX\t: " << buffer << "\n";
        cout << "ASCII STR\t: " << message.getMessage() << "\n";
        delete[] buffer;

        data = createNewData();
        data.message = message.getMessage();
        data.id = sender_id;
        HANDLE send_thread = CreateThread(NULL, 0, sendThread, &data, 0, NULL);
        if (send_thread == NULL) {
            cerr << "[FAILED]:: Error creating threads" << endl;
            continue;
        }
        WaitForSingleObject(send_thread, INFINITE);
        CloseHandle(send_thread);
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