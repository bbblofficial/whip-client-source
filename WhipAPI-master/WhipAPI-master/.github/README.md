# WhipAPI

WhipAPI est une librairie Java fournissant les modèles de données et la couche de persistance pour le système de licensing, de gestion des produits et de suivi d'utilisation des logiciels Whip.

| Information               | Valeur                     |
|---------------------------|----------------------------|
| Version de Java           | 21+                        |
| Base de données           | PostgreSQL                 |
| ORM                       | Hibernate 6.4              |
| Gestionnaire de dépendance| Gradle (Groovy)            |

## Fonctionnalités

- Gestion multi-produits (Whip Client, Whip Lite, Whip Autoclicker)
- Système de licensing avec cycle de vie complet (active, suspended, revoked, expired)
- Activation par machine via HWID
- Gestion de sessions avec heartbeat et expiration
- Suivi des téléchargements et de l'utilisation
- Protection contre les attaques de rejeu (nonces & request IDs)
- Intégration Discord optionnelle

## Modèles

| Entité       | Description                                              |
|--------------|----------------------------------------------------------|
| User         | Compte utilisateur avec authentification par mot de passe |
| Product      | Produit logiciel disponible au licensing                  |
| License      | Licence attribuée à un utilisateur pour un produit        |
| Machine      | Machine identifiée par HWID, liée à un utilisateur        |
| Session      | Session active avec token, clé de chiffrement et heartbeat|
| Download     | Suivi d'un téléchargement et de son utilisation           |
| DownloadId   | Identifiant de téléchargement pré-généré                  |
| UsedNonce    | Nonce consommé pour la protection anti-rejeu              |
| UsedRequest  | Requête consommée pour la protection anti-rejeu           |

## Produits supportés

| Code              | Nom               |
|-------------------|--------------------|
| `whip-client`     | Whip Client        |
| `whip-lite`       | Whip Lite          |
| `whip-autoclicker`| Whip Autoclicker   |

## Sécurité

- Stockage des mots de passe sous forme de hash uniquement
- Tokens de session hashés avec clés de chiffrement séparées
- Traçage des adresses IP (sessions et téléchargements)
- Révocation des licences, machines et téléchargements
- Protection anti-rejeu via `UsedNonce` et `UsedRequest`

## As a dependency

### Gradle

**gradle.properties**
```properties
gpr.user=USERNAME
gpr.token=TOKEN
```

**build.gradle**
```groovy
repositories {
    maven {
        url = uri("https://maven.pkg.github.com/Whip-Industries/WhipAPI")
        credentials {
            username = project.findProperty("gpr.user") ?: System.getenv("USERNAME")
            password = project.findProperty("gpr.token") ?: System.getenv("TOKEN")
        }
    }
}

dependencies {
    compileOnly 'fr.whip.api:whip-api:[SEE-IN-PACKAGE]'
}
```
