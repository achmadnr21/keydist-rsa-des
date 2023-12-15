#ifndef RSA_H   
#define RSA_H

// #include <utility>
// typedef long long int lld;

class Rsa{
    lld n;
    lld e;
    lld d; 
    lld p; 
    lld q;
public:
    Rsa(lld P, lld Q);
    int gcd(int a, int h);
    lld moduloExponential(lld b, lld e, lld m);
    int decrypt(int key, lld D = 0, lld N = 0);
    int encrypt(int key, lld E = 0, lld N = 0);
    pair<int, int> getPublicKey();
    lld generateKeyDistribution(int P, int Q);

};

// agar para fungsi dibawah dikenali sebagai method dari class RSA
// maka harus didefinisikan ulang dengan cara RSA::nama_fungsi
Rsa::Rsa(lld P, lld Q){
        p = P; 
        q = Q;
        n = p * q;
        e = 2;
        lld phi = (p - 1) * (q - 1);
        while (e < phi) {
            if (gcd((int)e, (int)phi) == 1)
                break;
            else
                e++;
        }
        d = 2;
        while(((d*e) % phi) != 1ll){
            d++;
        }
    }
int Rsa::gcd(int a, int h){
    int temp;
    while (1) {
        temp = a % h;
        if (temp == 0)
            return h;
        a = h;
        h = temp;
    }
}
lld Rsa::moduloExponential(lld b, lld e, lld m){
    lld r = 1;
    while(e > 0ll){
        if((e & 1) == 1){
            r = (r * b) % m;
        }
        e >>= 1ll;
        b = (b * b) % m;
    }
    return (lld)r;
}
int Rsa::decrypt(int key, lld D, lld N){
    // Decryption (key ^ d) % n
    if (D != 0 && N != 0) return (int)moduloExponential(key, D, N);
    else return (int)moduloExponential(key, d, n);
}
int Rsa::encrypt(int key, lld E, lld N){
    // Encryption (key ^ e) % n
    if (E != 0 && N != 0) return (int)moduloExponential((lld)key, E, N);
    else return (int)moduloExponential((lld)key, e, n);
}
pair<int, int> Rsa::getPublicKey(){
    return make_pair((int)e, (int)n);
}
lld Rsa::generateKeyDistribution(int P, int Q){
    lld val = 1;
    srand(time(0));
    // val <= p*q-2 terkecil
    while(true){
        val = 1;
        for (int i = 0; i < 5; i++) 
            val = val * rand() % (p*q-1);
        if (val != 1 && val != 0 && val != 2) break;
    }
    return val;
}
#endif