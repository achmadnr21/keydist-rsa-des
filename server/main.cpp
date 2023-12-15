#include "server.h"

int main(int argc, char const *argv[]) {
    // Jika return -1 maka error
    cout << "Server is running..." << endl;
    int port = stoi(argv[1]);
    int status = run_server(port);
    return 0;
}