#!/usr/bin/env elvish

try {
    i=0
    has-arg=[]{ < $i (count $args) }
    next-arg=[]{ put $args[$i]; i=(+ $i 1) }

    mode=
    passwords-file=~/.config/passwords
    while ($has-arg) {
        arg=($next-arg)
        if (has-value [-f --password-file] $arg) {
            if (not $has-arg) { fail missing-arg }
            passwords-file=($next-arg)
        } elif (has-value [-h --help] $arg) {
             fail help
        } elif (has-value [list show generate] $arg) {
             mode=$arg
             break
        } else {
             fail unrecognized
        }
    }
    if (eq $mode '') { fail missing-arg }
    if (and (has-value [list show] $mode) (not ?(test -f $passwords-file))) { fail missing-password-file }

    if (eq $mode list) {
        while ($has-arg) {
            arg=($next-arg)
            if (has-value [-h --help] $arg) {
                 fail help-list
            } else {
                 fail unrecognized
            }
        }
        is-key=$true
        try {
            ./pyct decrypt -b < $passwords-file 2>/dev/null | each [line]{
                 if $is-key { echo $line }
                 is-key=(not $is-key)
            }
        } except _ { fail password }
    } elif (eq $mode show) {
        name=
        fuzzy=$false
        while ($has-arg) {
            arg=($next-arg)
            if (has-value [-f --fuzzy] $arg) {
                 fuzzy=$true
            } elif (has-value [-h --help] $arg) {
                 fail help-show
            } elif (eq $name '') {
                 name=$arg
            } else {
                 fail unrecognized
            }
        }
        if (eq $name '') { fail missing-arg }

        match=(if $fuzzy {
             fuzzed=(put '' (explode $name) '' | joins '.*')
             put [arg]{ use re; re:match $fuzzed $arg }
        } else {
             put [arg]{ eq $arg $name }
        })

        is-name=$true
        print=$false
        try {
            ./pyct decrypt -b < $passwords-file 2>/dev/null | each [line]{
                if $print { print $line; break }
                print=(and $is-name ($match $line))
                is-name=(not $is-name)
            }
        } except _ { fail password }
        if (not $print) { fail nomatch }
    } elif (eq $mode generate) {
        name=
        length=16
        append=
        print=$false
        while ($has-arg) {
            arg=($next-arg)
            if (has-value [-l --length] $arg) {
                 if (not ($has-arg)) { fail missing-arg }
                 length=($next-arg)
                 use re
                 if (not (re:match '[1-9]\d*' $length)) { fail invalid }
            } elif (has-value [-h --help] $arg) {
                 fail help-generate
            } elif (has-value [-a --append] $arg) {
                 if (not ($has-arg)) { fail missing-arg }
                 append=($next-arg)
            } elif (has-value [-p --print] $arg) {
                 print=$true
            } elif (eq $name '') {
                 name=$arg
            } else {
                 fail unrecognized
            }
        }
        if (eq $name '') { fail missing-arg }

        hash=(./pyct hash)
        pass=(try { cat /dev/urandom | tr -dc 'A-Za-z0-9-+_' | head -c$length } except _ { })
        if (not-eq (count $pass) $length) { fail unknown }
        pass=$pass$append

        dec=
        if ?(test -f $passwords-file) {
            p=(pipe)
            run-parallel {
                print $hash > $p
                pwclose $p
            } {
                try {
                    dec=(./pyct decrypt -b --hash-fd 3 < $passwords-file 3< $p 2>/dev/null | slurp)
                } except _ { fail password } finally { prclose $p }
            }
            splits "\n" $dec | each [line]{
                if (eq $name $line) { fail generate-exists }
            }
        }

        p=(pipe)
        run-parallel {
            print $hash > $p
            pwclose $p
        } {
            print $dec$name"\n"$pass"\n" | ./pyct encrypt -b --hash-fd 3 3< $p > $passwords-file
            prclose $p
        }
        if $print { print $pass }
    }
} except e {
    try {
        use re
        exception=(re:replace '^\?\(fail (.*)\)$' '$1' (to-string $e))
        if (eq $exception help) {
            echo "Pyct-based password manager"
            echo
            echo "USAGE: passwords [OPTIONS] <SUBCOMMAND>"
            echo
            echo "OPTIONS:"
            echo "    -f, --password-file <FILE>   Use a specific password file [default: ~/.config/passwords]"
            echo "    -h, --help                   Print this help message"
            echo
            echo "SUBCOMMANDS:"
            echo "    list        List all entries"
            echo "    show        Print the password of the specified entry"
            echo "    generate    Randomly generate a password for an entry, and add it to the file"
        } elif (eq $exception help-list) {
            echo "List all entry names in the passwords file"
            echo
            echo "USAGE: passwords list [OPTIONS]"
            echo
            echo "OPTIONS:"
            echo "    -h, --help    Print this help message"
        } elif (eq $exception help-show) {
            echo "Print the password associated with an entry name"
            echo
            echo "USAGE: passwords show [OPTIONS] ENTRY"
            echo
            echo "OPTIONS:"
            echo "    -f, --fuzzy    Perform fuzzy matching of ENTRY. The first match is shown"
            echo "    -h, --help     Print this help message"
        } elif (eq $exception help-generate) {
            echo "Generate a random password for the entry specified, and add it to the passwords file"
            echo
            echo "USAGE: passwords generate [OPTIONS] ENTRY"
            echo
            echo "OPTIONS:"
            echo "    -l, --length <LENGTH>    Generate a password of length LENGTH [default: 16]"
            echo "    -a, --append <TEXT>      Append TEXT to the end of the generated password"
            echo "    -p, --print              Print the generated password"
            echo "    -h, --help               Print this help message"
        } else {
            reason=[
                &generate-exists="That entry already exists"
                &invalid="Invalid argument"
                &missing-arg="Missing argument"
                &missing-password-file="Missing password file"
                &nomatch="No matching entry found"
                &password="Incorrect password"
            ]
            try { echo $reason[$exception] } except _ { echo "Unknown error" }
            exit 1
        }
    }
# dumb trick to avoid huge stack traces when ctrl-c-ing
} finally { } >&2
