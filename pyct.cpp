#include <iostream>
#include <vector>
#include <string>
#include <array>
#include <random>
#include <optional>
#include <algorithm>
#include <termios.h>
#include <unistd.h>

#include "monocypher.h"

using namespace std;

using u8 = uint8_t;
using u32 = uint32_t;
using u64 = uint64_t;

template<typename T>
class OnScopeEnd
{
public:
    OnScopeEnd(T func) : m_func(move(func)) {}
    ~OnScopeEnd() { m_func(); }
private:
    T m_func;
};

template<typename T>
string to_base_64(const T& bytes)
{
    static const array<char, 64> table = {
        'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
        'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
        '0','1','2','3','4','5','6','7','8','9','+','-'
    };
    string ret;
    auto s = bytes.size();
    ret.reserve(4 * (s / 3 + (s % 3 > 0 ? 1 : 0)));
    size_t i = 0;
    if (bytes.size() >= 3) {
        for (; i <= bytes.size() - 3; i += 3) {
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
    } else if ((i + 2) == bytes.size()) {
        ret += table[(bytes[i]   & 0b11111100) >> 2];
        ret += table[(bytes[i]   & 0b00000011) << 4 |
                     (bytes[i+1] & 0b11110000) >> 4];
        ret += table[(bytes[i+1] & 0b00001111) << 2];
        ret += '=';
    }
    return ret;
}

vector<u8> from_base_64(string b64)
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
    b64.erase(remove_if(b64.begin(), b64.end(), [](char c) { return c == '\n' or c == ' '; }), b64.end());
    if (b64.size() % 4 != 0)
        throw invalid_argument("Invalid base64 input length");
    for (size_t i = 0; i < b64.size(); ++i) {
        if (table[b64[i]] < 64)
            continue;
        if ((i + 2) == b64.size() and b64[i] == '=' and b64[i+1] == '=')
            break;
        if ((i + 1) == b64.size() and b64[i] == '=')
            break;
        throw invalid_argument{"Invalid base64 character"};
    }

    vector<u8> ret;
    ret.reserve(b64.size() / 4 * 3);
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
T read_from_fd(int fd) {
    T data;
    size_t old_size = 0;
    size_t new_size = 32;
    while (true) {
        data.resize(new_size);
        size_t left_to_read = new_size - old_size;
        size_t already_read = 0;
        while (left_to_read > 0) {
            auto just_read = read(fd, data.data() + old_size + already_read, left_to_read);
            if (just_read < 0 || (size_t)just_read > left_to_read)
                throw std::runtime_error{"I/O error"};
            else if (just_read == 0) {
                data.resize(old_size + already_read);
                return data;
            }
            left_to_read -= just_read;
            already_read += just_read;
        }
        old_size = new_size;
        new_size *= 2;
    }
}

string ask_pass(bool confirm) {
    FILE* in;
    FILE* out;
    out = in = fopen("/dev/tty", "w+");
    auto close = OnScopeEnd([in] { fclose(in); });

    // literally caveman-tier shit
    termios t;
    tcgetattr(fileno(in), &t);
    auto show_input = OnScopeEnd([in, t] { tcsetattr(fileno(in), TCSANOW, &t); });
    t.c_lflag &= ~ECHO;
    tcsetattr(fileno(in), TCSANOW, &t);

    auto get_pass = [in, out](const char* prompt){
        fprintf(out, "%s", prompt);
        string s;
        while (true) {
            auto c = fgetc(in);
            if (c == '\n' or c == EOF)
                break;
            s.push_back(static_cast<char>(c));
        }
        fprintf(out, "\n");
        return s;
    };
    string pass = get_pass("Password:");
    if (confirm and get_pass("Confirm password:") != pass)
        throw runtime_error{"Passwords do not match"};
    return pass;
}

array<u8, 32> hash_password(const string& password, const string& salt) {
    if (salt.size() < 8)
        throw invalid_argument{"salt too small"};

    const size_t kilobytes = 128*1024;
    vector<u8> work_area(1024*kilobytes);
    u32 iterations = 10;

    array<u8, 32> hash;
    crypto_argon2i(hash.data(), hash.size(),
                   work_area.data(), kilobytes,
                   iterations,
                   reinterpret_cast<const u8*>(&password[0]), password.size(),
                   reinterpret_cast<const u8*>(&salt[0]), salt.size());
    return hash;
}

vector<u8> encrypt(vector<u8> input, const optional<u64>& pad_to, const array<u8, 32>& hash) {
    if (pad_to and *pad_to < input.size())
        throw invalid_argument{"Padded length is smaller than input"};
    u64 real_length = input.size();
    u64 padded_length = pad_to.value_or(input.size());
    u64 message_total_length = padded_length + 8;

    // allocate space for the padded message, its size, the mac and the nonce
    input.resize(padded_length +                   8 +       16 +        24);
    // the padding is unitialized data but that's fine

    u8* message_data = input.data();
    u8* size_data = message_data + padded_length;
    u8* mac_data = size_data + 8;
    u8* nonce_data = mac_data + 16;

    size_data[7] = static_cast<u8>((real_length & 0x00000000000000FF));
    size_data[6] = static_cast<u8>((real_length & 0x000000000000FF00) >> 8);
    size_data[5] = static_cast<u8>((real_length & 0x0000000000FF0000) >> 16);
    size_data[4] = static_cast<u8>((real_length & 0x00000000FF000000) >> 24);
    size_data[3] = static_cast<u8>((real_length & 0x000000FF00000000) >> 32);
    size_data[2] = static_cast<u8>((real_length & 0x0000FF0000000000) >> 40);
    size_data[1] = static_cast<u8>((real_length & 0x00FF000000000000) >> 48);
    size_data[0] = static_cast<u8>((real_length & 0xFF00000000000000) >> 56);

    // get some random data as the nonce
    random_device device;
    for (int i = 0; i < 6; ++i) {
        auto rand = device();
        nonce_data[i * 4]     = static_cast<u8>((rand & 0x000000FF));
        nonce_data[i * 4 + 1] = static_cast<u8>((rand & 0x000FFF00) >> 8);
        nonce_data[i * 4 + 2] = static_cast<u8>((rand & 0x00FF0000) >> 16);
        nonce_data[i * 4 + 3] = static_cast<u8>((rand & 0xFF000000) >> 24);
    }

    // do in-place encryption
    crypto_lock(mac_data,
                message_data,
                hash.data(),
                nonce_data,
                message_data, message_total_length);
    return input;
}

vector<u8> decrypt(vector<u8> input, const array<u8, 32>& hash) {
    if (input.size() < (8 + 16 + 24))
        throw invalid_argument{"Not enough data"};
    size_t message_length = input.size() - 24 - 16;
    u8* message_data = input.data();
    u8* mac_data = message_data + message_length;
    u8* nonce_data = mac_data + 16;

    if (0 != crypto_unlock(message_data,
                           hash.data(),
                           nonce_data,
                           mac_data,
                           message_data, message_length))
        throw invalid_argument{"Couldn't decrypt, invalid password?"};

    u8* size_data = message_data + message_length - 8;
    u64 original_size = static_cast<u64>(size_data[7])       |
                        static_cast<u64>(size_data[6]) << 8  |
                        static_cast<u64>(size_data[5]) << 16 |
                        static_cast<u64>(size_data[4]) << 24 |
                        static_cast<u64>(size_data[3]) << 32 |
                        static_cast<u64>(size_data[2]) << 40 |
                        static_cast<u64>(size_data[1]) << 48 |
                        static_cast<u64>(size_data[0]) << 56;
    input.resize(original_size);
    return input;
}

struct Args {
    enum class Operation {
        Encrypt,
        Decrypt,
        Hash
    } operation;
    bool help = false;
    bool base64 = false;
    bool interactive = true;
    optional<string> password;
    optional<array<u8, 32>> hash;
    optional<string> salt;
    optional<uint64_t> padded_length;
};

Args parse_args(int argc, char** argv) {
    argc--;
    argv++;
    Args args;
    if (argc == 0)
        throw invalid_argument{"Missing operation"};
    string op(argv[0]);
    if (op == "-h" or op == "--help") {
        args.help = true;
        return args;
    }
    const auto is_prefix = [](const string& pre, const string& s) {
        return pre.size() <= s.size() && equal(pre.begin(), pre.end(), s.begin());
    };
    if (is_prefix(op, "encrypt"))
        args.operation = Args::Operation::Encrypt;
    else if (is_prefix(op, "decrypt"))
        args.operation = Args::Operation::Decrypt;
    else if (is_prefix(op, "hash"))
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
        if (arg == "-h" or arg == "--help") {
            args.help = true;
        } else if (arg == "-b" or arg == "--base-64") {
            args.base64 = true;
        } else if (arg == "-n" or arg == "--non-interactive") {
            args.interactive = false;
        } else if (arg == "--hash-fd") {
            auto fd = stoi(option_value(++i));
            vector<u8> hash;
            try {
                hash = from_base_64(read_from_fd<string>(fd));
            } catch(...) {
                throw invalid_argument{"Invalid hash"};
            }
            if (hash.size() != 32)
                throw invalid_argument{"Hash is not the correct size"};
            args.hash.emplace();
            std::copy(hash.begin(), hash.end(), args.hash->begin());
        } else if (arg == "--pass-fd") {
            auto fd = stoi(option_value(++i));
            args.password = read_from_fd<string>(fd);
        } else if (arg == "-s" or arg == "--salt") {
            args.salt = option_value(++i);
            if (args.salt->size() < 8)
                throw invalid_argument{"Salt is too small"};
        } else if (arg == "-l" or arg == "--padded-length") {
            args.padded_length = stoull(option_value(++i));
        } else {
            throw invalid_argument{"Unrecognized argument"};
        }
    }
    if (args.salt and args.hash)
        throw invalid_argument{"Cannot provide both hash and salt"};
    else if (args.password and args.hash)
        throw invalid_argument{"Cannot provide both password and hash"};
    else if (args.operation != Args::Operation::Encrypt and args.padded_length)
        throw invalid_argument{"Can only pad when encrypting"};
    return args;
}

void print_help() {
    cerr << "A symmetric encryption program that uses argon2 password hashing.\n";
    cerr << "\n";
    cerr << "USAGE: pyct <SUBCOMMAND> [OPTIONS]\n";
    cerr << "\n";
    cerr << "SUBCOMMANDS:\n";
    cerr << "    encrypt    Encrypts the data passed on standard input\n";
    cerr << "    decrypt    Decrypts the pyct-encrypted data passed on standard input\n";
    cerr << "    hash       Prints the hashed password, for use with later invocations of pyct\n";
    cerr << "\n";
    cerr << "OPTIONS:\n";
    cerr << "    -b, --base-64                   When encrypting, produce base64 output. When decrypting, assumes that the input is base64\n";
    cerr << "        --pass-fd <FD>              Specify a file descriptor from which to read the password\n";
    cerr << "        --hash-fd <FD>              Specify a file descriptor from which to read the hash\n";
    cerr << "    -l, --padded-length <LENGTH>    Pad the input data to be LENGTH bytes long. Only when encrypting\n";
    cerr << "    -s, --salt <SALT>               Use SALT for password hashing. Must be at least 8 characters\n";
    cerr << "    -n, --non-interactive>          Do not prompt for password. Will abort if --pass-fd or --hash-fd is not specified\n";
    cerr << "    -h, --help                      Print this help message\n";
}

int main(int argc, char** argv) {
    try {
        const auto args = parse_args(argc, argv);
        if (args.help) {
            print_help();
            return 0;
        }
        auto get_hash = [&args](bool confirm) {
            if (args.hash)
                return *args.hash;
            string password;
            if (args.password)
                password =  *args.password;
            else if (args.interactive)
                password = ask_pass(confirm);
            else
                throw invalid_argument{"Either hash or password must be provided in non-interactive mode"};
            const auto salt = args.salt.value_or("86627104");
            return hash_password(password, salt);
        };

        if (args.operation == Args::Operation::Encrypt) {
            const auto hash = get_hash(true);
            auto input = read_from_fd<vector<u8>>(0);
            const auto encrypted = encrypt(move(input), args.padded_length, hash);
            if (args.base64) {
                cout << to_base_64(encrypted) << endl;
            } else {
                copy_n(reinterpret_cast<const u8*>(encrypted.data()), encrypted.size(), ostreambuf_iterator<char>(cout));
            }
        } else if (args.operation == Args::Operation::Decrypt) {
            const auto hash = get_hash(false);
            auto input = args.base64 ? from_base_64(read_from_fd<string>(0)) : read_from_fd<vector<u8>>(0);
            const auto decrypted = decrypt(move(input), hash);
            copy_n(reinterpret_cast<const u8*>(decrypted.data()), decrypted.size(), ostreambuf_iterator<char>(cout));
        } else if (args.operation == Args::Operation::Hash) {
            cout << to_base_64(get_hash(false)) << endl;
        }
    } catch (const exception& e) {
        cerr << e.what() << endl;
        return 1;
    }
}
