A command-line password manager that aims to stay simple.

It comes in two pieces:
* `pyct`: a binary that does symmetric encryption/decryption on standard input.
* `passwords`: a shell script that uses `pyct` to manage passwords.

# Prerequisites

Just a c++17 compiler. Call `make debug=no` and you're good to go. `passwords` is POSIX-compliant and should therefore be portable.

# FAQ

## Why not just use `pass`?

I don't like that it leaks metadata (meaning that I couldn't just commit it with my dotfiles), and I find `gpg` very cumbersome to use.

## Okay, but why not use an existing crypto tool to handle the encryption, like `gpg` or `openssl`?

Since this is not a general purpose tool and the problem domain is known, we can make decisions in accordance. For example, we use argon2 with conservative parameters (takes about 1s on my hardware) because that's acceptable for a password manager.

This also makes it much easier to make portable binaries.

But if you wish, you could make it so that `passwords` uses `openssl` or `gpg` for the encryption.

## I don't see any crypto library, are you rolling your own?

No, I'm using [monocypher](https://github.com/LoupVaillant/Monocypher) for the heavy lifting. I simply copied its source (`monocypher.h` and `monocypher.cpp`) into the repo for simplicity, as encouraged by the project.

## Why symmetric rather than asymmetric encryption?

Asymmetric encryption has the nice property that you can move your password file(s) around by themselves without ever worrying about them being decryped. However, securely getting access to your passwords from a new device is not trivial, and requires (at least) a back-and-forth with an already secure device.  
This is more work than I care for, and I think the additional steps required increase the chance for operational mistakes, and the overall risk.

Symmetric encryption is weaker in the sense that your password file(s) could be decrypted in transit (see next question), but also a lot more practical to handle: just get the passwords file to the new device (e.g. by carrying it on your phone) and you're good to go.  
To me the added convenience is worth it.

## Couldn't the passwords file be brute-forced, then?

The password derivation is done using the expensive (memory and execution-time wise) argon2 hash, making brute-force very expensive. This should only be a concern if you use a weak password, or one that can be found in password dumps. Obviously you shouldn't do either of these.

## Why two separate programs?

I find myself needing symmetric encryption of files from time to time, so I made a separate binary for doing just that.

However, note that `pyct` reads the entire input data in memory, meaning that it must allocate at least the size of the data you want to encrypt. Since monocyper supports encryption of streams, I might improve that in the future.

## The encryption takes too much/little time.

Most of the time is spent hashing the password. You can tweak the argon2 parameters in code to make it more or less expensive. Naturally, the same parameters should be used for encryption/decryption. 

## What's with the hardcoded salt, `86627104`?

Keeping it secret would lower convenience, requiring the user to remember two secrets. This hardcoded string in addition to the argon2 parameters should be sufficient against dictionary attacks. But if you wish, you can specify your own salt.

## Why should I trust you?

You don't have to, but it should be relatively easy to review the source. You can easily verify that monocypher is untouched too.

However, while I don't have malicious intent, there is always the possibility that a technical flaw will cause your passwords to be leaked. For that reason, I decline all responsibility if that were to happen to you.

## This is not secure, and your entire reasoning is flawed because of reason <x>.

Then please let me know. I'm far from being a crypto expert, but I don't think I've committed any fundamental error.

# LICENSE

Unlicense
