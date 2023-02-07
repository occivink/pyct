#!/bin/sh

cd "$(dirname "$0")"
pass_file=~/.config/passwords

command -v gum > /dev/null
has_gum=$?
type printf | grep builtin > /dev/null
printf_is_builtin=$?

if [ "$has_gum" -ne 0 ]; then
    echo "Missing 'gum' binary"
    exit 1
elif [ "$printf_is_builtin" -ne 0 ]; then
    echo "'printf' is not a builtin on this shell, refusing to start"
    exit 1
fi

gum style --bold --border thick --padding "0 1" --margin "1 1" PYCT
rows=$(tput lines)
rows=$((rows - 6))

while :; do
    master_pass=$(gum input --placeholder "Enter your master password" --password)
    if [ "$?" -ne 0 ]; then
        exit 0
    fi
    if [ "$master_pass" = "" ]; then
        continue
    fi
    # gum spin doesn't support passing data over stdin, revisit later
    # hash=$(printf "%s" "$password" | gum spin --title "Decrypting..." -- ../pyct hash --pass-fd 0)
    gum spin --title 'Decrypting...' sleep 100 &
    pid_gum="$!"
    decrypted=$(printf "%s" "$master_pass" | ../pyct dec -b --input-data-fd 3 --pass-fd 0 3< "$pass_file" 2> /dev/null )
    res="$?"
    kill "$pid_gum"
    if [ "$res" -ne 0 ]; then
        printf 'Failed to decrypt, invalid password?\n'
        continue
    fi
    break
done

while :; do
    picked=$(printf "%s\n" "$decrypted" | sed -n 'p;n' | timeout --foreground 5m gum filter --height "$rows")
    res="$?"
    if [ "$res" -ne 0 ]; then
        break
    elif [ "$picked" = "" ]; then
        continue
    fi

    password=$(printf '%s\n%s\n' "$picked" "$decrypted" | awk '
    BEGIN {
        first=""
        next_is_pass=0
    }
    // {
        if (first == "") {
            first=$0
        } else if (next_is_pass == 1) {
            print($0)
            exit(0)
        } else {
            if (first == $0) {
                next_is_pass=1
            }
        }
    }
    ')
    printf '%s' "$password" | wl-copy
    printf 'Password "%s" copied\n' "$picked"
    printf 'Clearing in 10s\n'
    sleep 10
    wl-copy --clear
    tput cuu1 el cuu1 el
done
