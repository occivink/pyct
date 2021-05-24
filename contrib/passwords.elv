#!/usr/bin/env elvish

use re
use str

try {
    var i = 0
    var has-arg = []{ < $i (count $args) }
    var next-arg = []{ put $args[$i]; set i = (+ $i 1) }

    var mode = ''
    var passwords-file = ~/.config/passwords

    while ($has-arg) {
        var arg = ($next-arg)
        if (has-value [-f --password-file] $arg) {
            if (not $has-arg) { fail missing-arg }
            set passwords-file = ($next-arg)
        } elif (has-value [-h --help] $arg) {
            fail help
        } elif (has-value [list show generate] $arg) {
            set mode = $arg
            break
        } else {
            fail unrecognized
        }
    }
    if (eq $mode '') { fail missing-arg }
    if (and (has-value [list show] $mode) (not ?(test -f $passwords-file))) { fail missing-password-file }

    if (eq $mode list) {
        while ($has-arg) {
            set arg = ($next-arg)
            if (has-value [-h --help] $arg) {
                 fail help-list
            } else {
                 fail unrecognized
            }
        }
        var is-key = $true
        try {
            ./pyct decrypt -b < $passwords-file 2>/dev/null | each [line]{
                 if $is-key { echo $line }
                 set is-key = (not $is-key)
            }
        } except _ { fail password }
    } elif (eq $mode show) {
        var name = ''
        var fuzzy = $false
        while ($has-arg) {
            var arg = ($next-arg)
            if (has-value [-f --fuzzy] $arg) {
                set fuzzy = $true
            } elif (has-value [-h --help] $arg) {
                fail help-show
            } elif (eq $name '') {
                set name = $arg
            } else {
                fail unrecognized
            }
        }
        if (eq $name '') { fail missing-arg }

        var match = (if $fuzzy {
             var fuzzed = (put '' (all $name) '' | str:join '.*')
             put [arg]{ re:match $fuzzed $arg }
        } else {
             put [arg]{ eq $arg $name }
        })

        var is-name = $true
        var print = $false
        try {
            ./pyct decrypt -b < $passwords-file 2>/dev/null | each [line]{
                if $print { print $line; break }
                set print = (and $is-name ($match $line))
                set is-name = (not $is-name)
            }
        } except _ { fail password }
        if (not $print) { fail nomatch }
    } elif (eq $mode generate) {
        var name = ''
        var pass = ''
        var length = 16
        var append = ''
        var print = $false
        while ($has-arg) {
            set arg = ($next-arg)
            if (has-value [-l --length] $arg) {
                 if (not ($has-arg)) { fail missing-arg }
                 set length = ($next-arg)
                 if (not (re:match '[1-9]\d*' $length)) { fail invalid }
            } elif (has-value [-h --help] $arg) {
                 fail help-generate
            } elif (has-value [-a --append] $arg) {
                 if (not ($has-arg)) { fail missing-arg }
                 set append = ($next-arg)
            } elif (has-value [-p --print] $arg) {
                 set print = $true
            } elif (eq $name '') {
                 set name = $arg
            } elif (eq $pass '') {
                 set pass = $arg
            } else {
                 fail unrecognized
            }
        }
        if (eq $name '') { fail missing-arg }

        var hash = (./pyct hash --no-confirm)
        if (eq $pass '') {
            set pass = (try { cat /dev/urandom | tr -dc 'A-Za-z0-9-+_' | head -c$length } except _ { })
            if (not-eq (count $pass) $length) { fail unknown }
            set pass = $pass$append
        }

        var dec = ''
        if ?(test -f $passwords-file) {
            var p = (pipe)
            run-parallel {
                print $hash > $p
                pwclose $p
            } {
                try {
                    set dec = (./pyct decrypt -b --hash-fd 3 < $passwords-file 3< $p 2>/dev/null | slurp)
                } except _ { fail password } finally { prclose $p }
            }
            str:split "\n" $dec | each [line]{
                if (eq $name $line) { fail generate-exists }
            }
        }

        var p = (pipe)
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
    var reason = $e[reason][content]
    if (eq $reason help) {
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
    } elif (eq $reason help-list) {
        echo "List all entry names in the passwords file"
        echo
        echo "USAGE: passwords list [OPTIONS]"
        echo
        echo "OPTIONS:"
        echo "    -h, --help    Print this help message"
    } elif (eq $reason help-show) {
        echo "Print the password associated with an entry name"
        echo
        echo "USAGE: passwords show [OPTIONS] ENTRY"
        echo
        echo "OPTIONS:"
        echo "    -f, --fuzzy    Perform fuzzy matching of ENTRY. The first match is shown"
        echo "    -h, --help     Print this help message"
    } elif (eq $reason help-generate) {
        echo "Generate a random password for the entry specified, and add it to the passwords file"
        echo
        echo "USAGE: passwords generate [OPTIONS] ENTRY [PASSWORD]"
        echo
        echo "OPTIONS:"
        echo "    -l, --length <LENGTH>    Generate a password of length LENGTH [default: 16]"
        echo "    -a, --append <TEXT>      Append TEXT to the end of the generated password"
        echo "    -p, --print              Print the generated password"
        echo "    -h, --help               Print this help message"
    } else {
        var friendly-message = [
            &generate-exists="That entry already exists"
            &invalid="Invalid argument"
            &missing-arg="Missing argument"
            &missing-password-file="Missing password file"
            &nomatch="No matching entry found"
            &password="Incorrect password"
        ]
        try { echo $friendly-message[$reason] } except _ { echo "Unknown error" }
        exit 1
    }
}
