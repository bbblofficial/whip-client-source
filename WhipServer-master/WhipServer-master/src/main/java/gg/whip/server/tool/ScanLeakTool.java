package gg.whip.server.tool;

import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.UUID;

/**
 * Standalone leak attribution scanner. Scans an arbitrary binary (DLL,
 * memory dump, .bin) for the WhipClient watermark magic and looks up the
 * embedded session UUID against the {@code dll_watermarks} table — bypasses
 * the Netty/Spring server, runs as a one-shot JDBC client.
 *
 * <p>Run on the VPS:
 * <pre>
 *   java -cp whip-server.jar gg.whip.server.tool.ScanLeakTool \
 *     /path/to/leaked.bin \
 *     "jdbc:postgresql://localhost:5432/whip" whip $PASSWORD
 * </pre>
 *
 * Outputs the user/discord/hwid/ip that received the leaked binary, or
 * "no match" if the magic isn't present (or the row was purged).
 *
 * See {@code WhipLoader/DUMP_THREAT_MODEL.md §5.3}.
 */
public final class ScanLeakTool {

    /** 8-byte sentinel — keep in sync with WatermarkService.MAGIC. */
    private static final byte[] MAGIC = new byte[]{
        (byte)0xC7, (byte)0xA3, (byte)0x91, (byte)0x4E,
        (byte)0xF8, (byte)0x52, (byte)0xB6, (byte)0xD0
    };
    private static final int UUID_BYTES_LEN = 16;

    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            System.err.println("Usage: ScanLeakTool <file> <jdbcUrl> <user> <password>");
            System.err.println("       (jdbcUrl example: jdbc:postgresql://localhost:5432/whip)");
            System.exit(2);
        }

        Path file = Path.of(args[0]);
        if (!Files.isRegularFile(file)) {
            System.err.println("File not found: " + file);
            System.exit(2);
        }

        byte[] bytes = Files.readAllBytes(file);
        StringBuilder hex = new StringBuilder();
        for (byte b : MAGIC) hex.append(String.format("%02x ", b & 0xff));
        System.out.printf("[*] Scanning %d bytes for sentinel %s...%n",
                bytes.length, hex.toString().trim());

        int slot = findMagic(bytes);
        if (slot < 0) {
            System.out.println("[-] No watermark magic found.");
            System.exit(1);
        }
        System.out.printf("[+] Magic found at offset 0x%x%n", slot);

        byte[] uuidBytes = new byte[UUID_BYTES_LEN];
        System.arraycopy(bytes, slot + MAGIC.length, uuidBytes, 0, UUID_BYTES_LEN);
        UUID sessionUuid = bytesToUuid(uuidBytes);
        System.out.println("[+] Embedded session UUID: " + sessionUuid);

        try (Connection conn = DriverManager.getConnection(args[1], args[2], args[3])) {
            String sql = "SELECT u.username, w.user_id, w.discord_id, w.hwid, "
                       + "w.ip, w.pc_name, w.created_at "
                       + "FROM dll_watermarks w "
                       + "LEFT JOIN users u ON u.id = w.user_id "
                       + "WHERE w.session_uuid = ?";
            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                stmt.setString(1, sessionUuid.toString());
                try (ResultSet rs = stmt.executeQuery()) {
                    if (!rs.next()) {
                        System.out.println("[-] No DB row matches — forged uuid"
                                + " or pre-watermarking build.");
                        System.exit(1);
                    }
                    System.out.println();
                    System.out.println("=== LEAK ATTRIBUTION ===");
                    System.out.println("Session UUID: " + sessionUuid);
                    System.out.println("User:         " + rs.getString(1)
                            + "  (id=" + rs.getObject(2, UUID.class) + ")");
                    String discord = rs.getString(3);
                    if (discord != null) System.out.println("Discord:      <@" + discord + ">");
                    String hwid = rs.getString(4);
                    if (hwid != null) System.out.println("HWID:         " + hwid);
                    String ip = rs.getString(5);
                    if (ip != null) System.out.println("IP:           " + ip);
                    String pcName = rs.getString(6);
                    if (pcName != null) System.out.println("PC name:      " + pcName);
                    System.out.println("Watermarked:  " + rs.getTimestamp(7));
                    System.out.println("File offset:  0x" + Integer.toHexString(slot));
                    System.out.println("========================");
                }
            }
        }
    }

    private static int findMagic(byte[] bytes) {
        outer:
        for (int i = 0; i + MAGIC.length + UUID_BYTES_LEN + 8 <= bytes.length; i++) {
            for (int j = 0; j < MAGIC.length; j++) {
                if (bytes[i + j] != MAGIC[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    private static UUID bytesToUuid(byte[] bytes) {
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        return new UUID(bb.getLong(), bb.getLong());
    }

    private ScanLeakTool() {}
}
