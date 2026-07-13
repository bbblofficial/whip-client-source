package gg.whip.server.service;

import at.favre.lib.crypto.bcrypt.BCrypt;
import gg.whip.server.exception.CryptoException;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HexFormat;
import java.util.UUID;

@Service
public class CryptoService {

    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final String HMAC_SHA256 = "HmacSHA256";
    private static final String EC_ALGORITHM = "EC";
    private static final String ECDH = "ECDH";
    private static final String EC_CURVE = "secp256r1";
    private static final int GCM_TAG_LENGTH = 128;

    private static final ThreadLocal<Cipher> AES_GCM_CIPHER = ThreadLocal.withInitial(() -> {
        try { return Cipher.getInstance(AES_GCM); } catch (Exception e) { throw new RuntimeException(e); }
    });

    private static final ThreadLocal<Mac> HMAC_MAC = ThreadLocal.withInitial(() -> {
        try { return Mac.getInstance(HMAC_SHA256); } catch (Exception e) { throw new RuntimeException(e); }
    });

    private final SecureRandom secureRandom = new SecureRandom();

    public KeyPair generateEphemeralKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(EC_ALGORITHM);
            keyGen.initialize(new ECGenParameterSpec(EC_CURVE), secureRandom);
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new CryptoException("Failed to generate ephemeral key pair", e);
        }
    }

    public byte[] hkdfSha256(byte[] salt, byte[] inputKeyMaterial, String info, int outputLength) {
        try {
            Mac hmac = HMAC_MAC.get();
            hmac.init(new SecretKeySpec(salt, HMAC_SHA256));
            byte[] prk = hmac.doFinal(inputKeyMaterial);

            hmac.init(new SecretKeySpec(prk, HMAC_SHA256));
            hmac.update(info.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            hmac.update((byte) 1);
            byte[] okm = hmac.doFinal();

            return java.util.Arrays.copyOf(okm, outputLength);
        } catch (Exception e) {
            throw new CryptoException("HKDF failed", e);
        }
    }

    public byte[] deriveSessionKey(PrivateKey serverPrivate, byte[] clientPublicBytes,
                                    byte[] clientNonce, byte[] serverNonce) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(EC_ALGORITHM);
            PublicKey clientPublic = keyFactory.generatePublic(new X509EncodedKeySpec(clientPublicBytes));

            KeyAgreement keyAgreement = KeyAgreement.getInstance(ECDH);
            keyAgreement.init(serverPrivate);
            keyAgreement.doPhase(clientPublic, true);

            byte[] sharedSecret = keyAgreement.generateSecret();

            byte[] salt = new byte[clientNonce.length + serverNonce.length];
            System.arraycopy(clientNonce, 0, salt, 0, clientNonce.length);
            System.arraycopy(serverNonce, 0, salt, clientNonce.length, serverNonce.length);

            return hkdfSha256(salt, sharedSecret, "whip-session-key-v1", 32);
        } catch (Exception e) {
            throw new CryptoException("Failed to derive session key", e);
        }
    }

    public byte[] generateNonce() {
        byte[] nonce = new byte[12];
        secureRandom.nextBytes(nonce);
        return nonce;
    }

    public byte[] generateChallenge() {
        byte[] challenge = new byte[32];
        secureRandom.nextBytes(challenge);
        return challenge;
    }

    public byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    public byte[] generateSessionToken() {
        return generateRandomBytes(32);
    }

    public String generateTempSessionId() {
        byte[] bytes = new byte[16];
        secureRandom.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    public byte[] encrypt(byte[] plaintext, byte[] key, byte[] nonce) {
        try {
            Cipher cipher = AES_GCM_CIPHER.get();
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_LENGTH, nonce));
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new CryptoException("Encryption failed", e);
        }
    }

    public byte[] decrypt(byte[] ciphertext, byte[] key, byte[] nonce) {
        try {
            Cipher cipher = AES_GCM_CIPHER.get();
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_LENGTH, nonce));
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new CryptoException("Decryption failed", e);
        }
    }

    public byte[] hmac(byte[] data, byte[] key) {
        try {
            Mac mac = HMAC_MAC.get();
            mac.init(new SecretKeySpec(key, HMAC_SHA256));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new CryptoException("HMAC computation failed", e);
        }
    }

    public boolean verifyHmac(byte[] data, byte[] key, byte[] expectedHmac) {
        byte[] computed = hmac(data, key);
        return MessageDigest.isEqual(computed, expectedHmac);
    }

    public boolean verifyAuthHmac(byte[] userSecret, short packetType, String requestId, long timestamp, byte[] expectedHmac) {
        try {
            Mac mac = HMAC_MAC.get();
            mac.init(new SecretKeySpec(userSecret, HMAC_SHA256));
            mac.update((byte) ((packetType >> 8) & 0xFF));
            mac.update((byte) (packetType & 0xFF));
            mac.update(requestId.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            mac.update(longToBytes(timestamp));
            byte[] computed = mac.doFinal();
            return MessageDigest.isEqual(computed, expectedHmac);
        } catch (Exception e) {
            throw new CryptoException("Auth HMAC verification failed", e);
        }
    }

    public boolean verifyChallengeResponse(byte[] sessionKey, byte[] challenge, long timestamp, byte[] response) {
        try {
            Mac mac = HMAC_MAC.get();
            mac.init(new SecretKeySpec(sessionKey, HMAC_SHA256));
            mac.update(challenge);
            mac.update(longToBytes(timestamp));
            byte[] expected = mac.doFinal();
            return MessageDigest.isEqual(expected, response);
        } catch (Exception e) {
            throw new CryptoException("Challenge verification failed", e);
        }
    }

    private byte[] longToBytes(long value) {
        byte[] bytes = new byte[8];
        for (int i = 7; i >= 0; i--) {
            bytes[i] = (byte) (value & 0xFF);
            value >>= 8;
        }
        return bytes;
    }

    public String hashNonce(byte[] nonce) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(nonce));
        } catch (Exception e) {
            throw new CryptoException("Nonce hashing failed", e);
        }
    }

    public boolean verifyPassword(String password, String storedHash) {
        return BCrypt.verifyer().verify(password.toCharArray(), storedHash).verified;
    }

    public String generateTokenHash() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(UUID.randomUUID().toString().getBytes());
            return HexFormat.of().formatHex(hash);
        } catch (Exception e) {
            throw new CryptoException("Token hash generation failed", e);
        }
    }

    public KeyPair generatePermanentKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(EC_ALGORITHM);
            keyGen.initialize(new ECGenParameterSpec(EC_CURVE), secureRandom);
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new CryptoException("Failed to generate permanent ECDSA key pair", e);
        }
    }

    public byte[] signEcdsa(PrivateKey privateKey, byte[] data) {
        try {
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(privateKey, secureRandom);
            signature.update(data);
            byte[] derSignature = signature.sign();

            return derSignatureToRaw(derSignature);
        } catch (Exception e) {
            throw new CryptoException("ECDSA signing failed", e);
        }
    }

    private byte[] derSignatureToRaw(byte[] derSig) {
        try {
            if (derSig[0] != 0x30) {
                throw new IllegalArgumentException("Invalid DER signature");
            }

            int pos = 2;

            if (derSig[pos++] != 0x02) {
                throw new IllegalArgumentException("Invalid DER signature - expected INTEGER");
            }
            int lenR = derSig[pos++] & 0xFF;
            byte[] r = new byte[lenR];
            System.arraycopy(derSig, pos, r, 0, lenR);
            pos += lenR;

            if (derSig[pos++] != 0x02) {
                throw new IllegalArgumentException("Invalid DER signature - expected INTEGER");
            }
            int lenS = derSig[pos++] & 0xFF;
            byte[] s = new byte[lenS];
            System.arraycopy(derSig, pos, s, 0, lenS);

            if (lenR == 33 && r[0] == 0x00) {
                byte[] tmp = new byte[32];
                System.arraycopy(r, 1, tmp, 0, 32);
                r = tmp;
                lenR = 32;
            }

            if (lenS == 33 && s[0] == 0x00) {
                byte[] tmp = new byte[32];
                System.arraycopy(s, 1, tmp, 0, 32);
                s = tmp;
                lenS = 32;
            }

            byte[] rawSig = new byte[64];

            int rOffset = 32 - r.length;
            System.arraycopy(r, 0, rawSig, rOffset, r.length);

            int sOffset = 64 - s.length;
            System.arraycopy(s, 0, rawSig, sOffset, s.length);

            return rawSig;
        } catch (Exception e) {
            throw new CryptoException("Failed to convert DER signature to raw format", e);
        }
    }

    public byte[] computeCertificateHash(PublicKey publicKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(publicKey.getEncoded());
        } catch (Exception e) {
            throw new CryptoException("Certificate hash computation failed", e);
        }
    }

    public String hashToHex(byte[] hash) {
        return HexFormat.of().formatHex(hash);
    }
}