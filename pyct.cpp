#include <iostream>
#include <vector>
#include <string>
#include <array>
#include <random>
#include <algorithm>
#include <termios.h>

#include "monocypher.h"

using namespace std;

using u8 = uint8_t;
using u32 = uint32_t;
using u64 = uint64_t;

template<typename T>
class OnScopeEnd
{
public:
    OnScopeEnd(T func) : m_func(std::move(func)) {}
    ~OnScopeEnd() { m_func(); }
private:
    T m_func;
};

template<typename T>
OnScopeEnd<T> on_scope_end(T t)
{
    return OnScopeEnd<T>{std::move(t)};
}

string toBase64(const vector<u8>& bytes)
{
    static const array<char, 64> table = {
        'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
        'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
        '0','1','2','3','4','5','6','7','8','9','+','-'
    };
    string ret;
    size_t i = 0;
    if (bytes.size() >= 3) {
        for (; i <=bytes.size() - 3; i += 3) {
            ret += table[(bytes[i]   & 0b11111100) >> 2];
            ret += table[(bytes[i]   & 0b00000011) << 4 |
                         (bytes[i+1] & 0b11110000) >> 4];
            ret += table[(bytes[i+1] & 0b00001111) << 2 |
                         (bytes[i+2] & 0b11000000) >> 6];
            ret += table[(bytes[i+2] & 0b00111111)];
        }
    }
    if (i + 1 == bytes.size()) {
        ret += table[(bytes[i] & 0b11111100) >> 2];
        ret += table[(bytes[i] & 0b00000011) << 4];
        ret += '=';
        ret += '=';
    } else if (i + 2 == bytes.size()) {
        ret += table[(bytes[i]   & 0b11111100) >> 2];
        ret += table[(bytes[i]   & 0b00000011) << 4 |
                     (bytes[i+1] & 0b11110000) >> 4];
        ret += table[(bytes[i+1] & 0b00001111) << 2];
        ret += '=';
    } 
    return ret;
}

vector<u8> fromBase64(string b64)
{
    static const array<u8, 256> table = {
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,62,64,63,64,64,
        52,53,54,55,56,57,58,59,60,61,64,64,64,64,64,64,
        64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,64,64,64,64,64,
        64,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64
    };
    b64.erase(remove_if(b64.begin(), b64.end(), [](char c) { return c == '\n'; }), b64.end());
    if (b64.size() % 4 != 0) 
        throw invalid_argument("Invalid base64 input length");
    for (size_t i = 0; i < b64.size(); ++i) {
        if (table[b64[i]] < 64)
            continue;
        if (i + 2 == b64.size() && b64[i] == '=' && b64[i+1] == '=')
            break;
        if (i + 1 == b64.size() && b64[i] == '=')
            break;
        throw invalid_argument{"Invalid base64 character"};
    }

    vector<u8> ret;
    size_t i = 0;
    if (b64.size() >= 4) {
        for (; i < b64.size() - 4; i += 4) {
            ret.push_back(((table[b64[i]]   & 0b00111111) << 2) |
                          ((table[b64[i+1]] & 0b00110000) >> 4));
            ret.push_back(((table[b64[i+1]] & 0b00001111) << 4) |
                          ((table[b64[i+2]] & 0b00111100) >> 2));
            ret.push_back(((table[b64[i+2]] & 0b00000011) << 6) |
                          ((table[b64[i+3]] & 0b00111111)));
        }
    }
    if (b64[i+2] == '=') {
        ret.push_back(((table[b64[i]]   & 0b00111111) << 2) |
                      ((table[b64[i+1]] & 0b00110000) >> 4));
    } else if (b64[i+3] == '=') {
        ret.push_back(((table[b64[i]]   & 0b00111111) << 2) |
                      ((table[b64[i+1]] & 0b00110000) >> 4));
        ret.push_back(((table[b64[i+1]] & 0b00001111) << 4) |
                      ((table[b64[i+2]] & 0b00111100) >> 2));
    } else { 
        ret.push_back(((table[b64[i]]   & 0b00111111) << 2) |
                      ((table[b64[i+1]] & 0b00110000) >> 4));
        ret.push_back(((table[b64[i+1]] & 0b00001111) << 4) |
                      ((table[b64[i+2]] & 0b00111100) >> 2));
        ret.push_back(((table[b64[i+2]] & 0b00000011) << 6) |
                      ((table[b64[i+3]] & 0b00111111)));
    }
    return ret;
}

template<typename T>
T read_from_stdin() {
    T data;
    size_t old_size = 0;
    size_t new_size = 32;
    while (true) {
        data.resize(new_size);
        cin.read(reinterpret_cast<char*>(&data[old_size]), new_size - old_size);
        if (cin.bad()) {
            throw runtime_error{"It's fucked"};
        }
        if (cin.eof()) {
            data.resize(old_size + cin.gcount());
            return data;
        }
        old_size = new_size;
        new_size *= 2;
    }
}

string ask_pass(bool confirm) {
    FILE* in;
    FILE* out;
    out = in = fopen("/dev/tty", "w+ce");
    auto close = on_scope_end([in] { fclose(in); });

    // literally caveman-tier shit
    termios t;
    tcgetattr(fileno(in), &t);
    auto show_input = on_scope_end([in, t] { tcsetattr(fileno(in), TCSANOW, &t); });
    t.c_lflag &= ~ECHO;
    tcsetattr(fileno(in), TCSANOW, &t);

    auto get_pass = [in, out](const char* prompt){
        fprintf(out, "%s", prompt);
        string s;
        while (true) {
            auto c = fgetc(in);
            if (c == '\n' || c == EOF)
                break;
            s.push_back(static_cast<char>(c));
        }
        fprintf(out, "\n");
        return s;
    };
    string pass = get_pass("Password:");
    if (confirm && get_pass("Confirm password:") != pass) {
        throw runtime_error{"Passwords do not match"};
    }
    return pass;
}

vector<u8> hash_password(const string& password, const string& salt) {
    if (salt.size() < 8) { 
        throw invalid_argument{"salt too small"};
    };
    vector<u8> hash;
    hash.resize(32);

    vector<u8> work_area;
    size_t kilobytes = 64*1024;
    work_area.resize(1024*kilobytes);

    crypto_argon2i(hash.data(), hash.size(),
                   work_area.data(), kilobytes,  // memory usage
                   3,                            // iterations
                   reinterpret_cast<const u8*>(&password[0]), password.size(),
                   reinterpret_cast<const u8*>(&salt[0]), salt.size(),
                   0, 0, 
                   0, 0);
    return hash;
}

vector<u8> encrypt(const vector<u8>& input, const vector<u8>& hash) {
    vector<u8> output;
    output.resize(24 + 16 + input.size());

    // get some random data as the nonce
    random_device device;
    for (int i = 0; i < 6; ++i) {
        auto rand = device();
        output[i * 4]     = static_cast<u8>((rand & 0x000000FF));
        output[i * 4 + 1] = static_cast<u8>((rand & 0x000FFF00) >> 8);
        output[i * 4 + 2] = static_cast<u8>((rand & 0x00FF0000) >> 16);
        output[i * 4 + 3] = static_cast<u8>((rand & 0xFF000000) >> 24);
    }

    crypto_lock(output.data() + 24,      // mac, size == 16
                output.data() + 24 + 16, // output
                hash.data(),             // key
                output.data(),           // nonce, size == 24
                input.data(), input.size());
    return output;
}

vector<u8> decrypt(const vector<u8>& input, const vector<u8>& hash) {
    vector<u8> output;
    size_t encrypted_size = input.size() - 24 - 16;
    output.resize(encrypted_size);

    if (0 != crypto_unlock(output.data(),
                           hash.data(),
                           input.data(),      // nonce
                           input.data() + 24, // mac
                           input.data() + 24 + 16, encrypted_size)) 
    {
        throw invalid_argument{"Couldn't decrypt, invalid password?"};
    }
    return output;
}

int main(int argc, char** argv) {
    string salt = "abcdefgh";

    bool base64 = true;

    string op(argv[1]);
    try {
        if (op == "encrypt") {
            auto password = ask_pass(true);
            auto input = read_from_stdin<vector<u8>>();
            auto encrypted = encrypt(input, hash_password(password, salt));
            if (base64) { 
                cout << toBase64(encrypted) << endl;
            } else {
                copy_n(reinterpret_cast<u8*>(encrypted.data()), encrypted.size(), ostreambuf_iterator<char>(cout));
            }
        } else if (op == "decrypt") {
            auto password = ask_pass(false);
            auto input = base64 ? fromBase64(read_from_stdin<string>()) : read_from_stdin<vector<u8>>();
            auto decrypted = decrypt(input, hash_password(password, salt));
            copy_n(reinterpret_cast<u8*>(decrypted.data()), decrypted.size(), ostreambuf_iterator<char>(cout));
        }
    } catch (const std::exception& e) {
        cerr << e.what() << endl;
        return 1;
    }
}
