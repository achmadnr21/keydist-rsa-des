#ifndef PESAN_H   
#define PESAN_H


class Pesan{
    DES_Enc DES2;
    string message = "";
    string key = "FEDCBA9876543210";
public:
    Pesan(){
        // Default Key
        key = "FEDCBA9876543210";
        DES2.setKeyStrHex(key);
    }
    void randomizerKey();
    void setKey(string key);
    string getKey();
    void setMessage(string msg);
    string getMessage();
    
    void messageEncryption();
    void messageDecryption();
};

// PUBLIC

void Pesan::randomizerKey(){
    int max_char = 16;
    char hexa[max_char] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
    long long int val = 1;
    key = "";
    srand(time(0)); 
    while(true){
        val = 1;
        for (int i = 0; i < 5; i++) 
            val = val * rand() % max_char;
        if (val != 1 && val != 0 && val != 2) break;
    }
    for (int i = 0; i<max_char; i++){
        val = (val * (i+1)) + 1;
        key = key + hexa[val % max_char];
    }
}
void Pesan::setKey(string Key){
    this->key = Key;
    DES2.setKeyStrHex(Key);
}
string Pesan::getKey(){
    return key;
}
void Pesan::setMessage(string msg){
    message = msg;
}
string Pesan::getMessage(){
    return message;
}
void Pesan::messageEncryption(){
    std::string submessage = message;
    // message = DES.ASCIItoHEX(message);
    // int des_iteration = DES.countIteration(message);
    // message = DES.addPadding(des_iteration, message);
    // message = DES.recurrentEncryption(des_iteration, message, key);
    // cout << "D1: Encrypted message: " << message << "\n";
    // cout << "D2: Encrypted message: " << DES2.encrypt(submessage) << "\n";
    message = DES2.encrypt(submessage);
}
void Pesan::messageDecryption(){
    std::string submessage = message;
    DES2.setKeyStrHex(key);
    // int des_iteration = DES.countIteration(message);
    // message = DES.recurrentDecryption(des_iteration, message, key);
    // message = DES.hexToASCII(message);
    // cout << "D1: Decrypted message: " << message << "\n";
    // cout << "D2: Decrypted message: " << DES2.decrypt_strhex(submessage) << "\n";
    message = DES2.decrypt_strhex(submessage);
}
#endif