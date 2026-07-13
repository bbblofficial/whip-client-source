package fr.whip.bot.util;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Computes the SHA-256 fingerprint of a PE binary's {@code .text} section.
 * <p>
 * The bot calls this on the patched loader bytes and stores the result on the
 * Download entity. The injected loader recomputes the same fingerprint at
 * runtime and mixes it into the auth_tag HMAC key. Any byte modified in the
 * .text section between bot patching and runtime → fingerprint mismatch →
 * server rejects (AUTH_THREAT_MODEL.md §6.2).
 */
public final class PeFingerprint {

    private PeFingerprint() {}

    /**
     * Hash the {@code .text} section of {@code peBytes} with SHA-256.
     *
     * @return 32-byte digest
     * @throws IllegalArgumentException if the PE structure is malformed or no
     *         .text section is found
     */
    public static byte[] hashTextSection(byte[] peBytes) {
        if (peBytes == null || peBytes.length < 0x40) {
            throw new IllegalArgumentException("PE too small");
        }

        ByteBuffer buf = ByteBuffer.wrap(peBytes).order(ByteOrder.LITTLE_ENDIAN);

        if (buf.getShort(0) != 0x5A4D) {
            throw new IllegalArgumentException("Not a PE: missing MZ");
        }

        int peOffset = buf.getInt(0x3C);
        if (peOffset <= 0 || peOffset + 4 > peBytes.length) {
            throw new IllegalArgumentException("Invalid e_lfanew");
        }

        if (buf.getInt(peOffset) != 0x00004550) {
            throw new IllegalArgumentException("Not a PE: missing PE signature");
        }

        int fileHeaderOffset = peOffset + 4;
        short numberOfSections = buf.getShort(fileHeaderOffset + 2);
        short sizeOfOptionalHeader = buf.getShort(fileHeaderOffset + 16);

        int sectionTableOffset = fileHeaderOffset + 20 + sizeOfOptionalHeader;

        for (int i = 0; i < numberOfSections; i++) {
            int sectionOffset = sectionTableOffset + i * 40;
            if (sectionOffset + 40 > peBytes.length) {
                break;
            }

            String name = readSectionName(peBytes, sectionOffset);
            if (".text".equals(name)) {
                int sizeOfRawData = buf.getInt(sectionOffset + 16);
                int pointerToRawData = buf.getInt(sectionOffset + 20);

                if (pointerToRawData < 0 || sizeOfRawData < 0
                        || (long) pointerToRawData + sizeOfRawData > peBytes.length) {
                    throw new IllegalArgumentException(".text section out of bounds");
                }

                return sha256(peBytes, pointerToRawData, sizeOfRawData);
            }
        }

        throw new IllegalArgumentException("No .text section found");
    }

    private static String readSectionName(byte[] pe, int offset) {
        StringBuilder sb = new StringBuilder(8);
        for (int i = 0; i < 8; i++) {
            byte b = pe[offset + i];
            if (b == 0) break;
            sb.append((char) (b & 0xFF));
        }
        return sb.toString();
    }

    private static byte[] sha256(byte[] data, int offset, int length) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(data, offset, length);
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
