#!/bin/sh
# Script de test pour isoler le problème "Bad system call"

echo "=== Préparation de l'environnement ==="
export LETMEIN_DISABLE_SECCOMP=1
export DISABLE_STRACE=1
export STRACE_CMD=""
export STRACE_DISABLED=1

# Déterminer les chemins
BASEDIR="$(pwd)"
TARGETDIR="$BASEDIR/target/debug"

# Créer le répertoire de travail
TMPDIR="$(mktemp -d -t letmein-test.XXXXXXXXXX)"
RUNDIR="$TMPDIR/run"
LOGDIR="$TMPDIR/logs"
mkdir -p "$RUNDIR" "$LOGDIR"

echo "=== Configuration ==="
CONFIG="$BASEDIR/tests/conf/tcp.conf"
echo "Répertoire temporaire: $TMPDIR"
echo "Fichiers de log: $LOGDIR"

echo "=== Démarrage des services ==="
echo "Démarrage de letmeinfwd..."
"$TARGETDIR/letmeinfwd" \
    --test-mode \
    --no-systemd \
    --rundir "$RUNDIR" \
    --seccomp off \
    --config "$CONFIG" > "$LOGDIR/letmeinfwd.out" 2> "$LOGDIR/letmeinfwd.err" &
LETMEINFWD_PID=$!
echo "PID letmeinfwd: $LETMEINFWD_PID"

echo "Démarrage de letmeind..."
"$TARGETDIR/letmeind" \
    --no-systemd \
    --rundir "$RUNDIR" \
    --seccomp off \
    --config "$CONFIG" > "$LOGDIR/letmeind.out" 2> "$LOGDIR/letmeind.err" &
LETMEIND_PID=$!
echo "PID letmeind: $LETMEIND_PID"

# Attendre que les services soient prêts
sleep 2

echo "=== Test de la commande knock ==="
"$TARGETDIR/letmein" \
    --verbose \
    --seccomp off \
    --config "$CONFIG" \
    knock \
    --user 12345678 \
    localhost 42 > "$LOGDIR/knock.out" 2> "$LOGDIR/knock.err"

KNOCK_STATUS=$?
echo "Statut de la commande knock: $KNOCK_STATUS"

# Afficher les logs en cas d'échec
if [ $KNOCK_STATUS -ne 0 ]; then
    echo "=== Contenu des logs d'erreur ==="
    echo "--- letmeinfwd.err ---"
    cat "$LOGDIR/letmeinfwd.err"
    echo "--- letmeind.err ---"
    cat "$LOGDIR/letmeind.err"
    echo "--- knock.err ---"
    cat "$LOGDIR/knock.err"
fi

# Nettoyage
echo "=== Nettoyage ==="
kill $LETMEINFWD_PID
kill $LETMEIND_PID
wait

echo "Logs disponibles dans $LOGDIR"

exit $KNOCK_STATUS
