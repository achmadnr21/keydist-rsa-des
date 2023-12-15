
#include "../general_client/client.h"


long long generate_random_prime(){
    long long prime[] = {7, 11, 13, 17, 19, 23, 27};
    int random_index = rand() % 7;
    return prime[random_index];
}

int main(int argc, char const *argv[]) {
    setUnamePQ(argv[1] , 7, 23);
    unsigned int port = stoi(argv[2]);
    int status = run_client(port);
    if (status <=0)
    {
        cout << "Client Shutdown!..." << status << endl;
    }
    
    return 0;
}
