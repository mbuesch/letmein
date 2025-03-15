#!/bin/sh
# Script d'initialisation nftables pour les tests letmein
set -e

echo "=== Initialisation de nftables pour les tests letmein ==="

# Tentative de chargement des règles nftables
echo "Configuration de nftables..."
nft flush ruleset || echo "Impossible de vider les règles existantes, poursuite..."

# Création d'une table et des chaînes nécessaires avec une politique permissive
echo "Création des tables et chaînes nftables..."
nft add table inet filter || echo "La table inet filter existe peut-être déjà"
nft add chain inet filter input { type filter hook input priority 0\; policy accept\; } || echo "La chaîne input existe peut-être déjà"
nft add chain inet filter output { type filter hook output priority 0\; policy accept\; } || echo "La chaîne output existe peut-être déjà"
nft add chain inet filter forward { type filter hook forward priority 0\; policy accept\; } || echo "La chaîne forward existe peut-être déjà"
nft add chain inet filter letmein-dynamic || echo "La chaîne letmein-dynamic existe peut-être déjà"

echo "Configuration nftables terminée"
exit 0
