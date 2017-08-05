#include <iostream>
#include <vector>
#include <string>
#include "monocypher.h"

using namespace std;

int main(int argc, char** argv) {
    string password(argv[1]);
    vector<uint8_t> password_bytes(password.begin(), password.end());
    vector<uint8_t> hash;
    hash.resize(32);
    std::string salt = "abcdefgh";
    vector<uint8_t> salt_bytes(salt.begin(), salt.end());
    vector<uint8_t> work_area;
    work_area.resize(1024*1024*32);
    crypto_argon2i(hash.data(), hash.size(),     // >= 4
                        work_area.data(), 1024*32, // correlates to memory usage
                        3, // iterations
                        password_bytes.data(), password_bytes.size(),
                        salt_bytes.data(), salt_bytes.size(),
                        0, 0, 
                        0, 0);

    vector<uint8_t> input = { 'a', 'b', 'c', 'd' }; 
    vector<uint8_t> cipher_text;
    cipher_text.resize(24 + 16 + input.size());

    crypto_lock(cipher_text.data() + 24, //mac, size == 16
                cipher_text.data() + 24 + 16, //output
                hash.data(), //key
                cipher_text.data(), //nonce, size == 24
                input.data(), input.size());

    vector<uint8_t> output;
    output.resize(cipher_text.size() - 24 - 16);

    crypto_unlock(output.data(),
                  hash.data(),
                  cipher_text.data(), // nonce
                  cipher_text.data() + 24, // mac
                  cipher_text.data() + 24 + 16, output.size());

    for (auto i : output)
        cout << i << endl;
}
