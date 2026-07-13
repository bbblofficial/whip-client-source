# Codes d'erreur serveur Whip

**Sécurité**: Les clients ne reçoivent que le code numérique. Seuls les staff ont accès à cette documentation.

## Erreurs générales (1-9)

| Code | Description | Cause |
|------|-------------|-------|
| 1 | État de session invalide | Le client a envoyé une requête dans un mauvais état de session |
| 2 | Validation du timestamp échouée | Le timestamp de la requête est invalide ou trop ancien |
| 3 | Données de requête malformées | La requête est corrompue ou mal formatée |
| 4 | Limite de taux dépassée | Trop de requêtes en peu de temps |
| 5 | Erreur interne du serveur | Erreur serveur inattendue |

## Erreurs d'authentification (10-19)

| Code | Description | Cause |
|------|-------------|-------|
| 10 | Identifiants invalides | Download ID ou HWID non trouvé/non enregistré |
| 11 | Download ID révoqué | Le download ID a été révoqué |
| 12 | Aucune licence valide | Aucune licence active trouvée pour l'utilisateur |
| 13 | Compte blacklisté | Le compte utilisateur est blacklisté |
| 14 | Permissions insuffisantes | L'opération nécessite des privilèges plus élevés (admin/owner requis pour auth HWID) |
| 15 | HWID ne correspond pas | Le HWID ne correspond à aucune machine enregistrée |

## Erreurs de session (20-29)

| Code | Description | Cause |
|------|-------------|-------|
| 20 | Session expirée | La session a expiré |
| 21 | Session non trouvée | Session introuvable |
| 22 | Token invalide | Token d'authentification invalide |
| 23 | Session déjà existante | Une session active existe déjà |

## Erreurs de produit/licence (30-39)

| Code | Description | Cause |
|------|-------------|-------|
| 30 | Produit non trouvé | Produit demandé introuvable |
| 31 | Licence expirée | La licence a expiré |
| 32 | Licence suspendue | La licence est suspendue |
| 33 | Licence révoquée | La licence a été révoquée |

## Erreurs de téléchargement (40-49)

| Code | Description | Cause |
|------|-------------|-------|
| 40 | Fichier non trouvé | Le fichier demandé n'existe pas |
| 41 | Téléchargement échoué | Échec du téléchargement du fichier |
| 42 | Requête de fichier invalide | Requête de fichier malformée |

## Erreurs de configuration (50-59)

| Code | Description | Cause |
|------|-------------|-------|
| 50 | Configuration non trouvée | Configuration introuvable |
| 51 | Accès à la configuration refusé | Accès refusé à cette configuration |

## Erreurs de machine (60-69)

| Code | Description | Cause |
|------|-------------|-------|
| 60 | Machine non enregistrée | Machine non enregistrée dans le système |
| 61 | Machine révoquée | La machine a été révoquée |
| 62 | Limite de machines atteinte | Nombre maximum de machines atteint |

## Erreurs de sécurité (70-79)

| Code | Description | Cause |
|------|-------------|-------|
| 70 | Attaque par rejeu détectée | Nonce déjà utilisé (replay attack) |
| 71 | Activité suspecte détectée | Comportement suspect détecté |
| 72 | Violation blacklist | Violation des règles de blacklist |
| 73 | Anomalie détectée | Pattern de requêtes anormal détecté |

---

**Note pour les admins**: Les logs serveur contiennent la description complète des erreurs. Les clients voient seulement le numéro.
