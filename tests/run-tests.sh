#!/bin/sh
# -*- coding: utf-8 -*-

basedir="$(realpath "$0" | xargs dirname)"
basedir="$basedir/.."

info()
{
    echo "--- $*"
}

# Configuration de strace
# Si DISABLE_STRACE est défini, n'utilise pas strace pour éviter les conflits avec seccomp
if [ "$DISABLE_STRACE" = "1" ]; then
    info "Désactivation de strace pour éviter les conflits avec seccomp"
    STRACE_CMD=""
    export STRACE_DISABLED=1
else
    # Configuration normale de strace
    STRACE_CMD="strace -f"
    export STRACE_DISABLED=0
fi

# Configuration de seccomp
# Si LETMEIN_DISABLE_SECCOMP est défini, désactiver seccomp pour tous les composants
if [ "$LETMEIN_DISABLE_SECCOMP" = "1" ]; then
    info "Désactivation de seccomp pour tous les composants (letmeind, letmeinfwd, letmein)"
    SECCOMP_OPT="--seccomp off"
else
    SECCOMP_OPT=""
fi

error()
{
    echo "=== ERROR: $*" >&2
}

warning()
{
    echo "=== WARNING: $*" >&2
}

die()
{
    error "$*"
    exit 1
}

build_project()
{
    info "Building project..."
    cd "$basedir" || die "cd failed"
    ./build.sh || die "Build failed"
}

cargo_clippy()
{
    cargo clippy -- --deny warnings || die "cargo clippy failed"
    cargo clippy --tests -- --deny warnings || die "cargo clippy --tests failed"
}

# Vérifie si nftables est disponible et opérationnel sur le système
check_nftables()
{
    info "Vérification de la disponibilité de nftables..."
    
    # Vérifier si on est dans un environnement WSL (où nftables peut ne pas fonctionner correctement)
    if grep -qi 'microsoft\|WSL' /proc/version; then
        warning "Environnement WSL détecté. Les tests de vérification de règles seront désactivés dans WSL."
        return 1
    fi
    
    # Vérifier si la commande système nft est accessible
    # Ignorer la version du projet qui pourrait être dans le PATH
    if [ ! -x "/sbin/nft" ] && [ ! -x "/usr/sbin/nft" ]; then
        warning "La commande système 'nft' (nftables) n'est pas installée ou accessible. Les tests de vérification de règles seront désactivés."
        return 1
    fi
    
    # Vérifier si on peut exécuter la commande système nft avec sudo
    echo "=== Détails de la commande nft ===="
    which nft
    ls -l $(which nft 2>/dev/null || echo "nft non trouvé")
    
    echo "=== Détails du système ===="
    uname -a
    cat /proc/version
    
    echo "=== Essai d'exécution de nft list ruleset ===="
    if command -v sudo > /dev/null; then
        echo "Tentative avec sudo /sbin/nft list ruleset:"
        sudo /sbin/nft list ruleset 2>&1 || echo "Commande échouée avec code: $?"
        
        if [ -x "/usr/sbin/nft" ]; then
            echo "Tentative avec sudo /usr/sbin/nft list ruleset:"
            sudo /usr/sbin/nft list ruleset 2>&1 || echo "Commande échouée avec code: $?"
        fi
    else
        echo "sudo n'est pas installé"
        echo "Tentative sans sudo:"
        /sbin/nft list ruleset 2>&1 || echo "Commande échouée avec code: $?"
    fi
    
    if ! sudo /sbin/nft list ruleset &> /dev/null && ! sudo /usr/sbin/nft list ruleset &> /dev/null; then
        warning "Impossible d'exécuter 'sudo nft list ruleset' avec la commande système. Vérifiez les permissions sudo."
        return 1
    fi
    
    info "nftables système est disponible et opérationnel!"
    return 0
}

# Vérifie la présence d'une règle nftables pour une adresse et un port spécifiques
verify_nft_rule_exists()
{
    local addr="$1"
    local port="$2"
    local proto="$3"
    local comment="letmein_${addr}-${port}/${proto}"
    
    info "Vérification de la présence de la règle nftables pour $addr port $port/$proto..."
    if sudo nft list ruleset | grep -q "comment \"$comment\""; then
        info "OK: Règle nftables trouvée pour $addr port $port/$proto"
        return 0
    else
        info "Ruleset nftables actuel:"
        sudo nft list ruleset
        die "ERREUR: Règle nftables non trouvée pour $addr port $port/$proto"
        return 1
    fi
}

# Vérifie l'absence d'une règle nftables pour une adresse et un port spécifiques
verify_nft_rule_missing()
{
    local addr="$1"
    local port="$2"
    local proto="$3"
    local comment="letmein_${addr}-${port}/${proto}"
    
    info "Vérification de l'absence de règle nftables pour $addr port $port/$proto..."
    if sudo nft list ruleset | grep -q "comment \"$comment\""; then
        info "Ruleset nftables actuel:"
        sudo nft list ruleset
        die "ERREUR: Règle nftables encore présente pour $addr port $port/$proto"
        return 1
    else
        info "OK: Règle nftables bien supprimée pour $addr port $port/$proto"
        return 0
    fi
}

run_tests_genkey()
{
    info "### Running test: gen-key ###"

    local conf="$testdir/conf/udp.conf"

    local res="$("$target/letmein" --config "$conf"  gen-key  --user 12345678)"

    local user="$(echo "$res" | cut -d'=' -f1 | cut -d' ' -f1)"
    local key="$(echo "$res" | cut -d'=' -f2 | cut -d' ' -f2)"

    [ "$user" = "12345678" ] || die "Got invalid user"
}

run_tests_knock()
{
    local test_type="$1"

    info "### Running test: knock $test_type ###"

    rm -rf "$rundir"
    local conf="$testdir/conf/$test_type.conf"

    info "Starting letmeinfwd..."
    "$target/letmeinfwd" \
        --test-mode \
        --no-systemd \
        --rundir "$rundir" \
        --seccomp off \
        --config "$conf" &
    pid_letmeinfwd=$!

    info "Starting letmeind..."
    "$target/letmeind" \
        --no-systemd \
        --rundir "$rundir" \
        --seccomp off \
        --config "$conf" &
    pid_letmeind=$!

    wait_for_pidfile letmeinfwd "$pid_letmeinfwd"
    wait_for_pidfile letmeind "$pid_letmeind"

    info "Knocking IPv6 + IPv4..."
    "$target/letmein" \
        --verbose \
        $SECCOMP_OPT \
        --config "$conf" \
        knock \
        --user 12345678 \
        localhost 42 \
        || die "letmein knock failed"
    info "Knocking IPv4..."
    "$target/letmein" \
        --verbose \
        $SECCOMP_OPT \
        --config "$conf" \
        knock \
        --user 12345678 \
        --ipv4 \
        localhost 42 \
        || die "letmein knock failed"

    info "Knocking IPv6..."
    "$target/letmein" \
        --verbose \
        $SECCOMP_OPT \
        --config "$conf" \
        knock \
        --user 12345678 \
        --ipv6 \
        localhost 42 \
        || die "letmein knock failed"

    kill_all_and_wait
}

run_tests_close()
{
    local test_type="$1"

    info "### Running test: close $test_type ###"

    rm -rf "$rundir"
    local conf="$testdir/conf/$test_type.conf"

    info "Starting letmeinfwd..."
    "$target/letmeinfwd" \
        --test-mode \
        --no-systemd \
        --rundir "$rundir" \
        --seccomp off \
        --config "$conf" &
    pid_letmeinfwd=$!

    info "Starting letmeind..."
    "$target/letmeind" \
        --no-systemd \
        --rundir "$rundir" \
        --seccomp off \
        --config "$conf" &
    pid_letmeind=$!

    wait_for_pidfile letmeinfwd "$pid_letmeinfwd"
    wait_for_pidfile letmeind "$pid_letmeind"

    # First open a port using knock
    info "Opening port with knock IPv6 + IPv4..."
    "$target/letmein" \
        --verbose \
        $SECCOMP_OPT \
        --config "$conf" \
        knock \
        --user 12345678 \
        localhost 42 \
        || die "letmein knock failed"
    
    # Vérifier que les règles ont bien été ajoutées (IPv6 + IPv4)
    if $nftables_available && [ "$test_type" != "test" ]; then  # Vérifier uniquement si nftables est disponible et pas en mode test
        sleep 1  # Attendre que les règles soient bien appliquées
        verify_nft_rule_exists "::1" "42" "tcp"
        verify_nft_rule_exists "127.0.0.1" "42" "tcp"
    fi

    # Then close the port using close command
    info "Closing port with close IPv6 + IPv4..."
    "$target/letmein" \
        --verbose \
        $SECCOMP_OPT \
        --config "$conf" \
        close \
        --user 12345678 \
        localhost 42 \
        || die "letmein close failed"
    
    # Vérifier que les règles ont bien été supprimées (IPv6 + IPv4)
    if $nftables_available && [ "$test_type" != "test" ]; then  # Vérifier uniquement si nftables est disponible et pas en mode test
        sleep 1  # Attendre que les règles soient bien supprimées
        verify_nft_rule_missing "::1" "42" "tcp"
        verify_nft_rule_missing "127.0.0.1" "42" "tcp"
    fi

    # Test with IPv4 only
    info "Opening port with knock IPv4..."
    "$target/letmein" \
        --verbose \
        $SECCOMP_OPT \
        --config "$conf" \
        knock \
        --user 12345678 \
        --ipv4 \
        localhost 42 \
        || die "letmein knock failed"
    
    # Vérifier que la règle IPv4 a bien été ajoutée
    if $nftables_available && [ "$test_type" != "test" ]; then
        sleep 1  # Attendre que les règles soient bien appliquées
        verify_nft_rule_exists "127.0.0.1" "42" "tcp"
    fi

    info "Closing port with close IPv4..."
    "$target/letmein" \
        --verbose \
        $SECCOMP_OPT \
        --config "$conf" \
        close \
        --user 12345678 \
        --ipv4 \
        localhost 42 \
        || die "letmein close failed"
    
    # Vérifier que la règle IPv4 a bien été supprimée
    if $nftables_available && [ "$test_type" != "test" ]; then
        sleep 1  # Attendre que les règles soient bien supprimées
        verify_nft_rule_missing "127.0.0.1" "42" "tcp"
    fi

    # Test with IPv6 only
    info "Opening port with knock IPv6..."
    "$target/letmein" \
        --verbose \
        $SECCOMP_OPT \
        --config "$conf" \
        knock \
        --user 12345678 \
        --ipv6 \
        localhost 42 \
        || die "letmein knock failed"
    
    # Vérifier que la règle IPv6 a bien été ajoutée
    if $nftables_available && [ "$test_type" != "test" ]; then
        sleep 1  # Attendre que les règles soient bien appliquées
        verify_nft_rule_exists "::1" "42" "tcp"
    fi

    info "Closing port with close IPv6..."
    "$target/letmein" \
        --verbose \
        $SECCOMP_OPT \
        --config "$conf" \
        close \
        --user 12345678 \
        --ipv6 \
        localhost 42 \
        || die "letmein close failed"
    
    # Vérifier que la règle IPv6 a bien été supprimée
    if $nftables_available && [ "$test_type" != "test" ]; then
        sleep 1  # Attendre que les règles soient bien supprimées
        verify_nft_rule_missing "::1" "42" "tcp"
    fi

    kill_all_and_wait
}

wait_for_pidfile()
{
    local name="$1"
    local pid="$2"

    for i in $(seq 0 29); do
        if [ -r "$rundir/$name/$name.pid" ]; then
            if [ "$pid" != "$(cat "$rundir/$name/$name.pid")" ]; then
                die "$name: Invalid PID-file."
            fi
            return
        fi
        sleep 0.1
    done
    die "$name PID-file is missing. Did $name fail to start?"
}

kill_all()
{
    kill_letmeind
    kill_letmeinfwd
}

kill_all_and_wait()
{
    kill_all
    wait
}

kill_letmeinfwd()
{
    if [ -n "$pid_letmeinfwd" ]; then
        kill -TERM "$pid_letmeinfwd" >/dev/null 2>&1
        pid_letmeinfwd=
    fi
}

kill_letmeind()
{
    if [ -n "$pid_letmeind" ]; then
        kill -TERM "$pid_letmeind" >/dev/null 2>&1
        pid_letmeind=
    fi
}

cleanup()
{
    kill_all
    if [ -n "$tmpdir" ]; then
        rm -rf "$tmpdir"
        tmpdir=
    fi
}

cleanup_and_exit()
{
    cleanup
    exit 1
}
 
pid_letmeinfwd=
pid_letmeind=

# Fonction pour initialiser nftables avec notre script d'initialisation
initialize_nftables()
{
    # Ne pas exécuter en mode stub
    if [ "$MOCK_NFTABLES" = "1" ]; then
        info "Mode stub nftables activé, pas besoin d'initialiser nftables"
        return 0
    fi
    
    info "Initialisation de nftables pour les tests..."
    if [ -x "$testdir/setup-nftables.sh" ]; then
        "$testdir/setup-nftables.sh" || warning "Erreur lors de l'initialisation de nftables"
    else
        warning "Le script setup-nftables.sh n'existe pas ou n'est pas exécutable"
    fi
}

# Fonction pour initialiser le fichier de configuration avec les clés utilisateur
initialize_config()
{
    local config_dir="/opt/letmein/etc"
    local config_file="$config_dir/letmein.conf"
    local test_user="12345678"
    
    info "Initialisation du fichier de configuration pour les tests..."
    
    # Créer le répertoire si nécessaire
    mkdir -p "$config_dir" || warning "Impossible de créer le répertoire de configuration $config_dir"
    
    # Générer une clé pour l'utilisateur de test si nécessaire
    if ! grep -q "$test_user" "$config_file" 2>/dev/null; then
        # Générer une clé aléatoire pour l'utilisateur
        local key="$(openssl rand -hex 16)"
        echo "$test_user:$key" >> "$config_file" || warning "Impossible d'ajouter la clé au fichier $config_file"
        info "Clé ajoutée pour l'utilisateur $test_user dans $config_file"
    else
        info "La clé pour l'utilisateur $test_user existe déjà dans $config_file"
    fi
    
    # Vérifier que le fichier est utilisable
    if [ ! -r "$config_file" ]; then
        warning "Le fichier de configuration $config_file n'est pas lisible"
    else
        info "Fichier de configuration $config_file initialisé avec succès"
    fi
}

# Variable globale pour déterminer si les vérifications nftables doivent être effectuées
nftables_available=false

[ -n "$TMPDIR" ] || export TMPDIR=/tmp
tmpdir="$(mktemp --tmpdir="$TMPDIR" -d letmein-test.XXXXXXXXXX)"
[ -d "$tmpdir" ] || die "Failed to create temporary directory"
rundir="$tmpdir/run"

target="$basedir/target/debug"
testdir="$basedir/tests"
stubdir="$testdir/stubs"

export PATH="$target:$PATH"

trap cleanup_and_exit INT TERM
trap cleanup EXIT

info "Temporary directory is: $tmpdir"

# Vérifier si on doit utiliser les stubs nftables (MOCK_NFTABLES=1)
if [ "$MOCK_NFTABLES" = "1" ]; then
    info "Mode MOCK_NFTABLES activé, utilisation des stubs nftables"
    export MOCK_NFTABLES=1
    
    # Vérifier si nftables est disponible mais en mode stub
    if check_nftables; then
        nftables_available=true
        info "Les vérifications de règles nftables seront effectuées (mode stub)"
    else
        nftables_available=false
        warning "Les vérifications de règles nftables seront désactivées (mode stub non fonctionnel)"
    fi
else
    info "Mode réel nftables activé (pas de MOCK_NFTABLES)"
    unset MOCK_NFTABLES
    
    # Vérifier si le vrai nftables est disponible et opérationnel
    if check_nftables; then
        nftables_available=true
        info "Les vérifications de règles nftables réelles seront effectuées"
        
        # Initialiser nftables avec notre script
        initialize_nftables
        
        # Initialiser le fichier de configuration
        initialize_config
    else
        nftables_available=false
        warning "Les vérifications de règles nftables réelles seront désactivées"
    fi
fi

build_project
cargo_clippy

# Déterminer quels tests exécuter en fonction des arguments
if [ $# -gt 0 ]; then
    info "Exécution des tests spécifiés: $*"
    for test in "$@"; do
        case "$test" in
            "gen-key")
                run_tests_genkey
                ;;
            "knock")
                run_tests_knock tcp
                run_tests_knock udp
                ;;
            "close")
                run_tests_close tcp
                run_tests_close udp
                ;;
            *)
                warning "Test inconnu: $test"
                ;;
        esac
    done
else
    # Si aucun test n'est spécifié, exécuter tous les tests
    info "Exécution de tous les tests"
    run_tests_genkey
    run_tests_knock tcp
    run_tests_knock udp
    run_tests_close tcp
    run_tests_close udp
fi

info "All tests Ok."

# vim: ts=4 sw=4 expandtab
