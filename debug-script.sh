#!/bin/sh
# Script simple pour reproduire l'erreur

# Créer répertoire temporaire
tmpdir=$(mktemp -d)
rundir="$tmpdir/run"
mkdir -p "$rundir"

# Démarrer les services
echo "Démarrage de letmeinfwd..."
/app/target/debug/letmeinfwd --test-mode --no-systemd --rundir "$rundir" --seccomp off --config /app/tests/conf/tcp.conf > "$tmpdir/letmeinfwd.log" 2>&1 &
pid_fwd=$!
echo "PID letmeinfwd: $pid_fwd"

echo "Démarrage de letmeind..."
/app/target/debug/letmeind --no-systemd --rundir "$rundir" --seccomp off --config /app/tests/conf/tcp.conf > "$tmpdir/letmeind.log" 2>&1 &
pid_ind=$!
echo "PID letmeind: $pid_ind"

# Attendre que les services démarrent
echo "Attente de démarrage des services..."
sleep 2

# Vérifier que les services sont en cours d'exécution
ps aux | grep letmein | grep -v grep

# Exécuter la commande knock
echo "Exécution de la commande knock..."
/app/target/debug/letmein --verbose --config /app/tests/conf/tcp.conf knock --user 12345678 localhost 42
knock_status=$?
echo "Statut de retour: $knock_status"

# Afficher les logs en cas d'échec
if [ $knock_status -ne 0 ]; then
    echo "Logs letmeinfwd:"
    cat "$tmpdir/letmeinfwd.log"
    
    echo "Logs letmeind:"
    cat "$tmpdir/letmeind.log"
fi

# Arrêter les services
kill $pid_fwd $pid_ind 2>/dev/null

exit $knock_status
