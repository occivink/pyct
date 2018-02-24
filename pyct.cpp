#include <iostream>
#include <vector>
#include <string>
#include <array>
#include <random>
#include <optional>
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
    out = in = fopen("/dev/tty", "w+");
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
                   work_area.data(), kilobytes, // memory usage
                   3,                           // iterations
                   reinterpret_cast<const u8*>(&password[0]), password.size(),
                   reinterpret_cast<const u8*>(&salt[0]), salt.size());
    return hash;
}

vector<u8> encrypt(vector<u8> input, u64 padded_length, const vector<u8>& hash) {
    if (padded_length == 0) {
        padded_length = input.size();
    } else if (padded_length < input.size()) {
        throw invalid_argument{"Padded length is smaller than input"};
    }
    input.resize(padded_length + 8, 0);
    {
        auto size = input.size();
        input[size - 8] = static_cast<u8>((padded_length & 0x00000000000000FF));
        input[size - 7] = static_cast<u8>((padded_length & 0x000000000000FF00) >> 8);
        input[size - 6] = static_cast<u8>((padded_length & 0x0000000000FF0000) >> 16);
        input[size - 5] = static_cast<u8>((padded_length & 0x00000000FF000000) >> 24);
        input[size - 4] = static_cast<u8>((padded_length & 0x000000FF00000000) >> 32);
        input[size - 3] = static_cast<u8>((padded_length & 0x0000FF0000000000) >> 40);
        input[size - 2] = static_cast<u8>((padded_length & 0x00FF000000000000) >> 48);
        input[size - 1] = static_cast<u8>((padded_length & 0xFF00000000000000) >> 56);
    }
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
    {
        auto size = output.size();
        u64 original_size = static_cast<u64>(output[size - 8])       |
                            static_cast<u64>(output[size - 7]) << 8  |
                            static_cast<u64>(output[size - 6]) << 16 |
                            static_cast<u64>(output[size - 5]) << 24 |
                            static_cast<u64>(output[size - 4]) << 32 |
                            static_cast<u64>(output[size - 3]) << 40 |
                            static_cast<u64>(output[size - 2]) << 48 |
                            static_cast<u64>(output[size - 1]) << 56;
        output.resize(original_size);
    }
    return output;
}

struct Args {
    enum class Operation {
        Encrypt,
        Decrypt,
        Hash
    } operation;
    bool base64;
    optional<string> password;
    optional<vector<u8>> hash;
    optional<string> salt;
    optional<uint64_t> padded_length;
};

Args parse_args(int argc, char** argv) {
    argc--;
    argv++;
    Args args;
    args.base64 = false;
    if (argc == 0)
        throw invalid_argument{"Missing operation"};
    string op(argv[0]);
    if (string("encrypt").substr(0, op.size()) == op)
        args.operation = Args::Operation::Encrypt;
    else if (string("decrypt").substr(0, op.size()) == op)
        args.operation = Args::Operation::Decrypt;
    else if (string("hash").substr(0, op.size()) == op)
        args.operation = Args::Operation::Hash;
    else
        throw invalid_argument{"Invalid operation"};

    auto option_value = [argc, argv](int i) {
        if (i >= argc)
            throw invalid_argument{"Missing option value"};
        return string(argv[i]);
    };
    for (int i = 1; i < argc; ++i) {
        string arg(argv[i]);
        if (arg == "-b" || arg == "--base64") {
            args.base64 = true;
        } else if (arg == "-h" || arg == "--hash") {
            args.hash = fromBase64(option_value(++i));
            if (args.hash->size() != 32) {
                throw invalid_argument{"Hash is not the correct size"};
            }
        } else if (arg == "-s" || arg == "--salt") {
            args.salt = option_value(++i);
            if (args.salt->size() < 8) {
                throw invalid_argument{"Salt is too small"};
            }
        } else if (arg == "-l" || arg == "--padded-length") {
            args.padded_length = stoull(option_value(++i));
        } else {
            throw invalid_argument{"Unrecognized argument"};
        }
    }
    if (args.salt.has_value() && args.hash.has_value()) {
        throw invalid_argument{"Cannot provide both hash and salt"};
    } else if (args.operation != Args::Operation::Encrypt && args.padded_length.has_value()) {
        throw invalid_argument{"Can only pad when encrypting"};
    }
    return args;
}

int main(int argc, char** argv) {
    try {
        const auto args = parse_args(argc, argv);
        auto get_hash = [&args](bool confirm) {
            vector<u8> hash;
            if (args.hash.has_value()) {
                return args.hash.value();
            } else {
                string password = ask_pass(confirm);
                const auto salt = args.salt.value_or("abcdefgh");
                return hash_password(password, salt);
            }
        };

        if (args.operation == Args::Operation::Encrypt) {
            const auto input = read_from_stdin<vector<u8>>();
            const auto hash = get_hash(true);
            const auto padded_length = args.padded_length.value_or(0);
            const auto encrypted = encrypt(input, padded_length, hash);
            if (args.base64) {
                cout << toBase64(encrypted) << endl;
            } else {
                copy_n(reinterpret_cast<const u8*>(encrypted.data()), encrypted.size(), ostreambuf_iterator<char>(cout));
            }
        } else if (args.operation == Args::Operation::Decrypt) {
            const auto hash = get_hash(false);
            const auto input = args.base64 ? fromBase64(read_from_stdin<string>()) : read_from_stdin<vector<u8>>();
            const auto decrypted = decrypt(input, hash);
            copy_n(reinterpret_cast<const u8*>(decrypted.data()), decrypted.size(), ostreambuf_iterator<char>(cout));
        } else if (args.operation == Args::Operation::Hash) {
            cout << toBase64(get_hash(true)) << endl;
        }
    } catch (const std::exception& e) {
        cerr << e.what() << endl;
        return 1;
    }
}
