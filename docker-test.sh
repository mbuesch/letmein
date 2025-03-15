#!/bin/bash

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Détection des options
DEBUG_MODE=""
REAL_NFTABLES=""
WITH_GEN_KEY=""
SPECIFIC_TESTS=""

# Message d'aide
usage() {
    echo -e "Usage: $0 [OPTIONS] [TESTS]"
    echo -e "Options:"
    echo -e "  --debug           Lance un shell interactif pour le débogage"
    echo -e "  --real-nftables   Utilise le vrai nftables au lieu du stub"
    echo -e "  --with-gen-key    Inclut le test gen-key (désactivé par défaut)"
    echo -e "  --help            Affiche ce message d'aide"
    echo -e "Tests disponibles:"
    echo -e "  knock             Exécute uniquement les tests knock"
    echo -e "  close             Exécute uniquement les tests close"
    echo -e "  gen-key           Exécute uniquement le test gen-key (nécessite --with-gen-key)"
    echo -e "Si aucun test n'est spécifié et --with-gen-key n'est pas utilisé,"
    echo -e "les tests knock et close seront exécutés par défaut."
    exit 0
}

# Analyse des options en ligne de commande
TESTS=()
for arg in "$@"; do
    case $arg in
        --debug)
            DEBUG_MODE="1"
            echo -e "${YELLOW}Mode débogage activé${NC}"
            ;;
        --real-nftables)
            REAL_NFTABLES="1"
            echo -e "${YELLOW}Mode nftables réel activé${NC}"
            ;;
        --with-gen-key)
            WITH_GEN_KEY="1"
            echo -e "${YELLOW}Test gen-key inclus${NC}"
            ;;
        --help)
            usage
            ;;
        knock|close|gen-key)
            TESTS+=("$arg")
            ;;
        -*)
            echo -e "${RED}Option inconnue: $arg${NC}"
            usage
            ;;
    esac
done

echo -e "${YELLOW}Création de l'image Docker pour les tests...${NC}"
docker build -t letmein-test -f Dockerfile.test .

# Exécuter les tests dans Docker
if [ "$DEBUG_MODE" = "1" ]; then
    # Mode débogage - lancer un shell interactif
    echo -e "${YELLOW}Démarrage du conteneur en mode interactif pour le débogage...${NC}"
    docker run --rm -it \
        --privileged \
        --cap-add=NET_ADMIN \
        --cap-add=SYS_ADMIN \
        --security-opt seccomp=unconfined \
        -e MOCK_NFTABLES="1" \
        -e LETMEIN_DISABLE_SECCOMP="1" \
        -v "$(pwd):/app" \
        --entrypoint /bin/sh \
        letmein-test
    exit $?
else
    # Déterminer si on utilise le stub ou le vrai nftables
    if [ "$MOCK_NFTABLES" = "1" ]; then
        echo -e "${YELLOW}Exécution des tests avec le stub nftables (MOCK_NFTABLES=1)...${NC}"
    else
        echo -e "${YELLOW}Exécution des tests avec le vrai nftables...${NC}"
    fi

    # Déterminer quels tests exécuter
    if [ ${#TESTS[@]} -gt 0 ]; then
        # Utiliser les tests spécifiés en ligne de commande
        TEST_ARGS="${TESTS[*]}"
        echo -e "${YELLOW}Exécution des tests spécifiés: ${TEST_ARGS}${NC}"
    elif [ "$WITH_GEN_KEY" = "1" ]; then
        # Exécuter tous les tests y compris gen-key
        TEST_ARGS=""
        echo -e "${YELLOW}Tous les tests seront exécutés, y compris gen-key${NC}"
    else
        # Par défaut, exécuter knock et close seulement
        TEST_ARGS="knock close"
        echo -e "${YELLOW}Exécution des tests par défaut (knock et close)${NC}"
    fi
    
    # Vérifie si gen-key est demandé sans l'option --with-gen-key
    if [[ " ${TESTS[*]} " =~ " gen-key " ]] && [ "$WITH_GEN_KEY" != "1" ]; then
        echo -e "${RED}Le test gen-key a été spécifié mais --with-gen-key n'est pas activé${NC}"
        echo -e "${YELLOW}Utilisez --with-gen-key pour exécuter le test gen-key${NC}"
        exit 1
    fi

    # Préparer les variables d'environnement
    # Désactiver strace quand seccomp est désactivé pour éviter les conflits
    DISABLE_STRACE="1"
    
    # Exécuter les tests
    if [ "$MOCK_NFTABLES" = "1" ]; then
        # Mode mock: passer la variable MOCK_NFTABLES
        docker run --rm \
            --privileged \
            --cap-add=NET_ADMIN \
            --cap-add=SYS_ADMIN \
            --security-opt seccomp=unconfined \
            -e MOCK_NFTABLES=1 \
            -e LETMEIN_DISABLE_SECCOMP=1 \
            -e DISABLE_STRACE="$DISABLE_STRACE" \
            -e RUST_BACKTRACE=0 \
            -e LD_PRELOAD="" \
            -v "$(pwd):/app" \
            --entrypoint ./tests/run-tests.sh \
            letmein-test $TEST_ARGS
    else
        # Mode réel: ne pas passer la variable MOCK_NFTABLES
        docker run --rm \
            --privileged \
            --cap-add=NET_ADMIN \
            --cap-add=SYS_ADMIN \
            --security-opt seccomp=unconfined \
            -e LETMEIN_DISABLE_SECCOMP=1 \
            -e DISABLE_STRACE="$DISABLE_STRACE" \
            -e RUST_BACKTRACE=0 \
            -e LD_PRELOAD="" \
            -v "$(pwd):/app" \
            --entrypoint ./tests/run-tests.sh \
            letmein-test $TEST_ARGS
    fi
    
    # Vérifier le code de sortie
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Tous les tests ont réussi!${NC}"
    else
        echo -e "${RED}Certains tests ont échoué!${NC}"
        echo -e "${YELLOW}Conseils:${NC}"
        echo -e "${YELLOW}1. Lancez './docker-test.sh --debug' pour entrer dans un shell interactif et déboguer.${NC}"
        
        if [ "$REAL_NFTABLES" = "1" ]; then
            echo -e "${YELLOW}2. Essayez sans l'option --real-nftables pour utiliser le stub.${NC}"
        else
            echo -e "${YELLOW}2. Assurez-vous que la variable MOCK_NFTABLES est correctement définie dans les tests.${NC}"
        fi
        
        exit 1
    fi
fi
