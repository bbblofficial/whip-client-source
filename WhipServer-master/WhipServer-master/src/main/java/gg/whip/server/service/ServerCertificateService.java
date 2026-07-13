package gg.whip.server.service;

import gg.whip.server.config.ServerProperties;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Service de gestion du certificat permanent du serveur pour certificate pinning.
 * Charge ou génère une paire de clés ECDSA permanente au démarrage.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ServerCertificateService {

    private final CryptoService cryptoService;
    private final ServerProperties serverProperties;

    @Getter
    private KeyPair permanentKeyPair;

    @Getter
    private String certificateHash;

    private static final String PRIVATE_KEY_FILE = "server_private.key";
    private static final String PUBLIC_KEY_FILE = "server_public.key";

    @PostConstruct
    public void initialize() {
        log.info("Initializing server certificate for certificate pinning...");

        // S'assurer que le répertoire de certificats existe
        File certDir = getCertificateDir();
        if (!certDir.exists() && !certDir.mkdirs()) {
            log.error("Failed to create certificate directory: {}", certDir.getAbsolutePath());
        }
        log.info("Certificate directory: {}", certDir.getAbsolutePath());

        // Tenter de charger la clé existante
        if (loadKeyPair()) {
            log.info("Loaded existing server certificate");
        } else {
            // Générer une nouvelle paire de clés
            log.info("No existing certificate found, generating new one...");
            permanentKeyPair = cryptoService.generatePermanentKeyPair();
            if (saveKeyPair()) {
                log.info("Generated and saved new server certificate");
            } else {
                log.warn("Generated new server certificate (in-memory only, will not persist across restarts)");
            }
        }

        // Calculer et afficher le hash pour la configuration client
        byte[] hashBytes = cryptoService.computeCertificateHash(permanentKeyPair.getPublic());
        certificateHash = cryptoService.hashToHex(hashBytes);

        log.info("═══════════════════════════════════════════════════════════════");
        log.info("Server Certificate Hash (for client configuration):");
        log.info("  {}", certificateHash);
        log.info("═══════════════════════════════════════════════════════════════");
    }

    private File getCertificateDir() {
        String dir = serverProperties.getTls().getCertificateDir();
        if (dir == null || dir.isBlank()) {
            dir = "./certs";
        }
        return Path.of(dir).toAbsolutePath().toFile();
    }

    /**
     * Signe des données avec la clé privée permanente
     */
    public byte[] signData(byte[] data) {
        if (permanentKeyPair == null) {
            throw new IllegalStateException("Permanent key pair not initialized");
        }
        return cryptoService.signEcdsa(permanentKeyPair.getPrivate(), data);
    }

    /**
     * Retourne la clé publique encodée (X.509)
     */
    public byte[] getPublicKeyEncoded() {
        if (permanentKeyPair == null) {
            throw new IllegalStateException("Permanent key pair not initialized");
        }
        return permanentKeyPair.getPublic().getEncoded();
    }

    /**
     * Charge la paire de clés depuis les fichiers
     */
    private boolean loadKeyPair() {
        File certDir = getCertificateDir();
        File privateKeyFile = new File(certDir, PRIVATE_KEY_FILE);
        File publicKeyFile = new File(certDir, PUBLIC_KEY_FILE);

        if (!privateKeyFile.exists() || !publicKeyFile.exists()) {
            return false;
        }

        try {
            // Charger la clé privée
            byte[] privateKeyBytes = readFile(privateKeyFile);
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            // Charger la clé publique
            byte[] publicKeyBytes = readFile(publicKeyFile);
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            permanentKeyPair = new KeyPair(publicKey, privateKey);
            return true;

        } catch (Exception e) {
            log.error("Failed to load server certificate", e);
            return false;
        }
    }

    /**
     * Sauvegarde la paire de clés dans des fichiers
     */
    private boolean saveKeyPair() {
        try {
            File certDir = getCertificateDir();

            // Sauvegarder la clé privée (PKCS#8 format)
            byte[] privateKeyBytes = permanentKeyPair.getPrivate().getEncoded();
            writeFile(new File(certDir, PRIVATE_KEY_FILE), privateKeyBytes);

            // Sauvegarder la clé publique (X.509 format)
            byte[] publicKeyBytes = permanentKeyPair.getPublic().getEncoded();
            writeFile(new File(certDir, PUBLIC_KEY_FILE), publicKeyBytes);

            log.info("Saved server certificate to {} and {}", PRIVATE_KEY_FILE, PUBLIC_KEY_FILE);
            return true;

        } catch (IOException e) {
            log.error("Failed to save server certificate", e);
            return false;
        }
    }

    private byte[] readFile(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file)) {
            return fis.readAllBytes();
        }
    }

    private void writeFile(File file, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(data);
        }
    }
}
