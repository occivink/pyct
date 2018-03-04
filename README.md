**Warning**: this repo is still in experimental stage. Use the programs here at your own risk, I **will** make compatibility-breaking changes in the beginning.

# Pyct

A simple symmetric encryption program. Comes with a password management script built on top.

* `pyct`: the main program which does symmetric encryption/decryption on standard input.
```
A symmetric encryption program that uses argon2 password hashing.

USAGE: pyct <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    encrypt    Encrypts the data passed on standard input
    decrypt    Decrypts the pyct-encrypted data passed on standard input
    hash       Prints the hashed password, for use with later invocations of pyct

OPTIONS:
    -b, --base-64                   When encrypting, produce base64 output. When decrypting, assumes that the input is base64
        --pass-fd <FD>              Specify a file descriptor from which to read the password
        --hash-fd <FD>              Specify a file descriptor from which to read the hash
    -l, --padded-length <LENGTH>    Pad the input data to be LENGTH bytes long. Only when encrypting
    -s, --salt <SALT>               Use SALT for password hashing. Must be at least 8 characters
    -n, --non-interactive>          Do not prompt for password. Will abort if --pass-fd or --hash-fd is not specified
    -h, --help                      Print this help message
```
* `contrib/passwords.elv`: an *elvish* script that uses `pyct` to manage passwords.
```
Pyct-based password manager

USAGE: passwords [OPTIONS] <SUBCOMMAND>

OPTIONS:
    -f, --password-file <FILE>   Use a specific password file [default: ~/.config/passwords]
    -h, --help                   Print this help message

SUBCOMMANDS:
    list        List all entries
    show        Print the password of the specified entry
    generate    Randomly generate a password for an entry, and add it to the file
```

## Prerequisites

* `pyct`: A c++17 compiler. Call `make debug=no` and you're good to go. 
* `contrib/passwords.elv`: the `elvish` shell. Fortunately, it is quite portable.

## FAQ

### Why not just use `pass`?

I don't like that it leaks metadata (meaning that I couldn't just commit it with my dotfiles), and I find `gpg` very cumbersome to use.

### Okay, but why not use an existing crypto tool to handle the encryption, like `gpg` or `openssl`?

Since this is not a general purpose tool and the problem domain is known, we can make decisions in accordance. For example, we use argon2 with conservative parameters (takes about 1s on my hardware) because that's acceptable for a password manager.

This also makes it much easier to make portable binaries.

But if you wish, you could make it so that `passwords` uses `openssl` or `gpg` for the encryption.

### I don't see any crypto library, are you rolling your own?

No, I'm using [monocypher](https://github.com/LoupVaillant/Monocypher) for the heavy lifting. I simply copied its source (`monocypher.h` and `monocypher.cpp`) into the repo for simplicity, as encouraged by the project.

### The `passwords` script is in... *elvish*?

I initially wanted to make it a posix-compliant shell script, but I quickly realized that some of its features would not be possible.

For example, in `generate` mode, the script decrypts the password file and re-encrypts its content with some data appended to the end. To avoid prompting for the password multiple times, we first hash it explictly with `pyct` and pass this hash to later invocations using the `--hash-fd` switch. It turns out that in posix shell, you cannot pass arbitrary data to a program using a file descriptor: it can only come from a file or a fifo. For security reasons I don't want to do either of these, and so I gave up on doing it in posix shell.

I may make a crippled version of `passwords` in posix shell in the future, for portability reasons.

### Why symmetric rather than asymmetric encryption?

Asymmetric encryption has the nice property that you can move your password file(s) around by themselves without ever worrying about them being decrypted by an attacker. However, securely getting access to your passwords from a new device is not trivial, and requires (at least) a back-and-forth with an already secure device.  
This is more work than I care for, and I think the additional steps required increase the chance for operational mistakes, and the overall risk.

Symmetric encryption is weaker in the sense that your password file(s) could be decrypted in transit (see next question), but also a lot more practical to handle: just get the passwords file to the new device (e.g. by carrying it on your phone, or cloning your dotfiles) and you're good to go.  
To me the added convenience is worth it.

### Couldn't the passwords file be brute-forced, then?

The password derivation is done using the expensive (memory and execution-time wise) argon2 hash, making brute-force very expensive. This should only be a concern if you use a weak password, or one that can be found in password dumps. Obviously you shouldn't do either of these.

### Why two separate programs?

I find myself needing symmetric encryption of files from time to time, so I made a separate binary for doing just that.

However, note that `pyct` reads the entire input data in memory, meaning that it must allocate at least the size of the data you want to encrypt. Since monocyper supports encryption of streams, I might improve that in the future.

### The encryption takes too much/little time.

Most of the time is spent hashing the password. You can tweak the argon2 parameters in code to make it more or less expensive. Naturally, the same parameters should be used for encryption/decryption. 

### What's with the hardcoded salt, `86627104`?

Keeping it secret would lower convenience, requiring the user to remember two secrets. This hardcoded string in addition to the argon2 parameters should be sufficient against dictionary attacks. But if you wish, you can specify your own salt.

### Why should I trust you?

You don't have to, but it should be relatively easy to review the source. You can easily verify that monocypher is untouched too.

However, while I don't have malicious intent, there is always the possibility that a technical flaw will cause your passwords to be leaked. For that reason, I decline all responsibility if that were to happen to you.

### This is not secure, and your entire reasoning is flawed because of `<x>`.

Then please let me know. I'm far from being a crypto expert, but I don't think I've committed any fundamental mistake.

## Planned

* a posix shell equivalent of passwords.elv
* a kakoune plugin to edit the content of pyct-encrypted files

## LICENSE

Unlicense
