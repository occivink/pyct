This is a command-line password manager that aims to stay simple. 
# FAQ

## Why not just use `pass`?

I don't like that it leaks metadata (meaning that I couldn't just commit it with my dotfiles), and I find `gpg` very cumbersome to use.

## Okay, but why not use an existing crypto tool to handle the encryption, like `gpg` or `openssl`?

Since this is not a general purpose tool and the problem domain is known, we can make decisions in accordance. For example, we use argon2 with parameters such that 1s is an acceptable time for password hashing.

This also makes it much easier to make portable binaries.

## I don't see any crypto library, are you rolling your own?

No, I'm using monocypher for the heavy lifting. I simply copied its source (`monocypher.h` and `monocypher.cpp`) into the repo for simplicity, as encouraged by the project.

## Why symmetric rather than asymmetric encryption?

Asymmetric encryption has the nice property that you can move your password file(s) around by themselves without ever worrying about them being decryped. However, securely getting access to your passwords from a new device is not trivial, and requires a back-and-forth with an already secure device.  
This is more work than I care for, and I think the additional steps required increase the chance for operational mistakes, and the overall risk.

Symmetric encryption is weaker in the sense that your password file(s) could be decrypted in transit (see next question), but also a lot more practical to handle: get the passwords file to the new device, decrypt it and you're good to go.  
To me the added convenience is worth it.

## Couldn't the passwords file be brute-forced, then?

The password derivation is done using the expensive argon2 hash (with conservative parameters by default), making brute-force very expensive. This should only be a concern if you use a weak password, or one that can be found in password dumps.

## The encryption takes too much/little time.

Most of the time is spent hashing the password. You can tweak the argon2 parameters in code to make it more or less expensive. Naturally, the same parameters should be used for encryption/decryption. 

## What's with the hardcoded salt, "abcdefgh"?

Keeping it secret would lower convenience, requiring the user to remember two secrets. The hardcoded string "abcdefgh" in addition of the argon2 parameters should be sufficient against dictionary attacks. But if you wish, you can specify your own salt.

## Why should I trust you?

You don't have to, but it should be relatively easy to review the source. You can easily verify that monocypher is untouched too.

However, while I don't have malicious intent, there is always the possibility that a technical flaw will cause your passwords to be leaked. For that reason, I decline all responsibility if that were to happen to you.

# LICENSE

Unlicense
