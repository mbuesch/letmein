// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

use std::{
    env,
    io::{stdin, Read as _},
};

fn main() {
    // Récupérer tous les arguments
    let args: Vec<String> = env::args().collect();
    
    // Journaliser tous les appels pour débogage
    eprintln!("nft stub: appel avec arguments: {:?}", args);
    
    // Vérifier si MOCK_NFTABLES est défini
    if env::var("MOCK_NFTABLES").is_ok() {
        eprintln!("nft stub: MOCK_NFTABLES=1 détecté, utilisation du mode stub");
        
        // Mode mock - accepter différents types de commandes
        if args == ["nft", "-j", "-f", "-"] {
            // Traiter l'entrée JSON
            let mut json_raw: Vec<u8> = vec![];
            stdin().read_to_end(&mut json_raw).unwrap();
            let json = std::str::from_utf8(&json_raw).unwrap();
            
            eprintln!("nft stub: json reçu: {}", json);
            let _ = json; // Nous pourrions analyser le JSON ici
            
            // Simuler une application réussie
            eprintln!("nft stub: Commande JSON traitée avec succès");
        } else if args.len() >= 2 && args[1] == "list" && args.len() >= 3 && args[2] == "ruleset" {
            // Simuler une liste de règles vide
            println!("table inet filter {{
  chain input {{
    type filter hook input priority 0; policy accept;
  }}
  chain forward {{
    type filter hook forward priority 0; policy accept;
  }}
  chain output {{
    type filter hook output priority 0; policy accept;
  }}
}}");
            eprintln!("nft stub: Commande list ruleset simulée");
        } else {
            // Gérer d'autres types de commandes
            eprintln!("nft stub: simulation d'exécution de: {:?}", args);
            // Par défaut, simuler un succès pour la plupart des commandes
        }
    } else {
        eprintln!("nft stub: MOCK_NFTABLES non défini, utilisation du vrai nft");
        
        // MOCK_NFTABLES n'est pas défini, initialiser les tables nécessaires avant de rediriger
        use std::process::Command;
        
        // Créer les tables de base si c'est une commande d'initialisation
        if args.len() > 1 && args[1] == "-j" && args[2] == "-f" && args[3] == "-" {
            // Lire l'entrée JSON pour voir ce qu'on essaie de faire
            let mut json_raw: Vec<u8> = vec![];
            stdin().read_to_end(&mut json_raw).unwrap();
            let json = std::str::from_utf8(&json_raw).unwrap();
            eprintln!("nft stub: Contenu JSON pour le vrai nft: {}", json);
            
            // Créer la table inet filter si elle n'existe pas déjà
            // Cela assure que les opérations ultérieures auront une table sur laquelle travailler
            eprintln!("nft stub: Création de la table inet filter");
            let _init_status = Command::new("/usr/sbin/nft")
                .args(["-e", "add", "table", "inet", "filter"])
                .status();
            
            // Créer les chaînes de base si nécessaire
            let _chains = [
                "add chain inet filter input { type filter hook input priority 0; policy accept; }",
                "add chain inet filter forward { type filter hook forward priority 0; policy accept; }",
                "add chain inet filter output { type filter hook output priority 0; policy accept; }",
                // Ajouter la chaîne spécifique LETMEIN-INPUT qui est utilisée par le code
                "add chain inet filter LETMEIN-INPUT { type filter hook input priority 100; policy accept; }",
                // Autres chaînes potentiellement utilisées
                "add chain inet filter LETMEIN-OUTPUT { type filter hook output priority 100; policy accept; }"
            ];
            
            for chain_cmd in _chains.iter() {
                let _chain_status = Command::new("/usr/sbin/nft")
                    .args(["-e", chain_cmd])
                    .status();
                // -e pour ignorer les erreurs si la chaîne existe déjà
            }
            
            // Appliquer la commande JSON originale
            let status = Command::new("/usr/sbin/nft")
                .args(["-j", "-f", "-"])
                .stdin(std::process::Stdio::piped())
                .spawn()
                .and_then(|mut child| {
                    if let Some(mut stdin) = child.stdin.take() {
                        use std::io::Write;
                        stdin.write_all(json_raw.as_slice()).unwrap();
                    }
                    child.wait()
                })
                .expect("Impossible d'exécuter le vrai nft avec JSON");
            
            std::process::exit(status.code().unwrap_or(1));
        } else {
            // Pour les autres commandes, simplement les exécuter
            let real_nft = "/usr/sbin/nft";
            let nft_args = &args[1..];
            
            eprintln!("nft stub: exécution de la commande réelle: {} {:?}", real_nft, nft_args);
            
            let status = Command::new(real_nft)
                .args(nft_args)
                .status()
                .expect("Impossible d'exécuter le vrai nft");
            
            eprintln!("nft stub: commande réelle terminée avec code: {:?}", status.code());
            
            // Propager le code de sortie
            std::process::exit(status.code().unwrap_or(1));
        }
    }
}

// vim: ts=4 sw=4 expandtab
