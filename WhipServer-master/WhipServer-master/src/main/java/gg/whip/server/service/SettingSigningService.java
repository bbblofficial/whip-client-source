package gg.whip.server.service;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Ed25519 signing oracle for the remote-blessed settings system.
 *
 * The private half lives only here. Clients verify with the public half
 * embedded in their binary (.rdata, covered by self-attestation). A
 * cracker who dumps client memory cannot forge signatures because the
 * private key is never on that side of the wire.
 *
 * Key sourcing (in order):
 *   1. application property whip.setting.ed25519-private-key (PKCS#8 base64)
 *   2. env var WHIP_SETTING_ED25519_PRIVATE_KEY (same format)
 *   3. dev-only fallback: generate a fresh keypair at startup (LOGS the
 *      public part so it can be pasted into ServerPubKey.h client-side)
 *
 * Java 21 has built-in EdDSA (JEP 339), no extra dependency required.
 */
@Service
public class SettingSigningService {

    private static final Logger log = LoggerFactory.getLogger(SettingSigningService.class);
    public static final int PUBKEY_RAW_LEN = 32;
    public static final int SIG_LEN        = 64;
    public static final byte PUBKEY_VERSION = 1;

    @Value("${whip.setting.ed25519-private-key:}")
    private String configuredPrivateKeyBase64;

    private PrivateKey privateKey;
    @Getter
    private byte[] publicKeyRaw;   // 32 raw bytes — what gets embedded in the client

    @PostConstruct
    void init() throws Exception {
        String src = configuredPrivateKeyBase64;
        if (src == null || src.isBlank()) {
            src = System.getenv("WHIP_SETTING_ED25519_PRIVATE_KEY");
        }
        if (src != null && !src.isBlank()) {
            loadFromPkcs8(src);
            log.info("[SettingSigning] loaded Ed25519 keypair from configured PKCS#8");
            return;
        }

        // Dev-only fallback: generate a fresh keypair so the server boots
        // without any setup. This MUST NOT happen in prod — log loudly.
        KeyPairGenerator gen = KeyPairGenerator.getInstance("Ed25519");
        KeyPair kp = gen.generateKeyPair();
        privateKey   = kp.getPrivate();
        publicKeyRaw = extractRawPublicKey(kp.getPublic());
        log.warn("[SettingSigning] NO PRIVATE KEY CONFIGURED — generated ephemeral keypair");
        log.warn("[SettingSigning] Public key (paste into ServerPubKey.h): {}",
                hexFormat(publicKeyRaw));
        log.warn("[SettingSigning] Private key (PKCS#8 base64): {}",
                Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        log.warn("[SettingSigning] Set whip.setting.ed25519-private-key to this value to persist across restarts");
    }

    private void loadFromPkcs8(String base64) throws Exception {
        byte[] der = Base64.getDecoder().decode(base64.trim());
        PrivateKey priv = KeyFactory.getInstance("Ed25519")
                .generatePrivate(new PKCS8EncodedKeySpec(der));
        // Derive the public key from the private. We do this by computing
        // a signature of a known message twice using KeyPairGenerator.
        // The clean way: just keep the configured key as the source of
        // truth and require the operator to also configure the pubkey,
        // OR reconstruct via Ed25519's built-in public-from-private path.
        //
        // JDK 21's Ed25519 KeyFactory exposes EdECPrivateKeySpec which
        // doesn't directly give us the pubkey. Easiest portable approach:
        // require the operator to provide both halves. For now we accept
        // private-only and recover public via a one-time sign+verify
        // ladder using the standard EdDSA pubkey derivation.
        //
        // Phase 1 simplification: operator MUST also set
        // whip.setting.ed25519-public-key (32 raw bytes, base64). Reading
        // that here would couple this method to two properties — instead
        // we generate fresh during dev (above) and require both keys
        // configured during prod. The check below catches the missing
        // pubkey path.
        privateKey = priv;
        if (configuredPublicKeyBase64 == null || configuredPublicKeyBase64.isBlank()) {
            throw new IllegalStateException(
                "whip.setting.ed25519-public-key (raw 32 bytes base64) must also be set " +
                "when whip.setting.ed25519-private-key is provided");
        }
        publicKeyRaw = Base64.getDecoder().decode(configuredPublicKeyBase64.trim());
        if (publicKeyRaw.length != PUBKEY_RAW_LEN) {
            throw new IllegalStateException("ed25519-public-key must decode to 32 bytes");
        }
    }

    @Value("${whip.setting.ed25519-public-key:}")
    private String configuredPublicKeyBase64;

    /**
     * Sign `payload` with the server's Ed25519 private key. Returns 64 raw
     * signature bytes. Throws on any crypto error.
     */
    public byte[] sign(byte[] payload) {
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(privateKey);
            sig.update(payload);
            return sig.sign();
        } catch (Exception e) {
            throw new IllegalStateException("Ed25519 sign failed", e);
        }
    }

    private static byte[] extractRawPublicKey(PublicKey pub) {
        // EdDSA X.509 SubjectPublicKeyInfo for Ed25519 is 44 bytes total:
        //   12-byte ASN.1 header + 32-byte raw key.
        byte[] x509 = pub.getEncoded();
        if (x509.length != 44) {
            throw new IllegalStateException("Unexpected Ed25519 X.509 length: " + x509.length);
        }
        byte[] raw = new byte[PUBKEY_RAW_LEN];
        System.arraycopy(x509, 12, raw, 0, PUBKEY_RAW_LEN);
        return raw;
    }

    private static String hexFormat(byte[] bytes) {
        StringBuilder sb = new StringBuilder("{ ");
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("0x%02X", bytes[i] & 0xFF));
            if (i < bytes.length - 1) sb.append(", ");
            if ((i + 1) % 8 == 0 && i < bytes.length - 1) sb.append("\n  ");
        }
        sb.append(" }");
        return sb.toString();
    }
}
