package gg.whip.server.network.protocol;

import gg.whip.server.data.ConfigResponseData;
import gg.whip.server.data.FileChunkData;
import gg.whip.server.data.FileChunkMetaData;
import gg.whip.server.data.FileResponseData;
import gg.whip.server.data.ProductInfo;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class PacketWriter {

    public byte[] writeServerHello(byte[] serverNonce, String tempSessionId, byte[] serverPublicKey) {
        return BinaryWriter.write(w -> w
                .writeBytes(serverNonce)
                .writeString(tempSessionId)
                .writeLengthPrefixedBytes(serverPublicKey));
    }

    /**
     * Écrire SERVER_HELLO avec certificate pinning (clé permanente + signature)
     */
    public byte[] writeServerHello(byte[] serverNonce, String tempSessionId, byte[] serverPublicKey,
                                     byte[] serverPermanentPublicKey, byte[] signature) {
        return BinaryWriter.write(w -> w
                .writeBytes(serverNonce)
                .writeString(tempSessionId)
                .writeLengthPrefixedBytes(serverPublicKey)
                .writeLengthPrefixedBytes(serverPermanentPublicKey)
                .writeLengthPrefixedBytes(signature));
    }

    public byte[] writeAuthSuccess(byte[] token, int permissions, long expiresAt, byte[] challenge) {
        return BinaryWriter.write(w -> w
                .writeBoolean(true)
                .writeBytes(token)
                .writeInt(permissions)
                .writeLong(expiresAt)
                .writeBytes(challenge));
    }

    public byte[] writeAuthSuccessWithTempToken(byte[] token, int permissions, long expiresAt, byte[] challenge, byte[] temporaryClientToken) {
        return BinaryWriter.write(w -> w
                .writeBoolean(true)
                .writeBytes(token)
                .writeInt(permissions)
                .writeLong(expiresAt)
                .writeBytes(challenge)
                .writeBytes(temporaryClientToken));
    }

    public byte[] writeAuthSuccessWithTempTokenAndSecret(byte[] token, int permissions, long expiresAt, byte[] challenge, byte[] temporaryClientToken, byte[] userSecret, byte[] clientAttestationToken) {
        return BinaryWriter.write(w -> w
                .writeBoolean(true)
                .writeBytes(token)
                .writeInt(permissions)
                .writeLong(expiresAt)
                .writeBytes(challenge)
                .writeBytes(temporaryClientToken)
                .writeBytes(userSecret)
                .writeBytes(clientAttestationToken));
    }

    public byte[] writeAuthError(int code, String message) {
        return BinaryWriter.write(w -> w
                .writeBoolean(false)
                .writeInt(code)
                .writeString(message));
    }

    public byte[] writeClientAuthSuccess(byte[] sessionToken, int permissions, long expiresAt, byte[] challenge, String username) {
        return BinaryWriter.write(w -> w
                .writeBoolean(true)
                .writeString(username)
                .writeBytes(sessionToken)
                .writeInt(permissions)
                .writeLong(expiresAt)
                .writeBytes(challenge));
    }

    public byte[] writeClientAuthSuccessWithSecret(byte[] sessionToken, int permissions, long expiresAt, byte[] challenge, String username, byte[] userSecret) {
        return BinaryWriter.write(w -> w
                .writeBoolean(true)
                .writeString(username)
                .writeBytes(sessionToken)
                .writeInt(permissions)
                .writeLong(expiresAt)
                .writeBytes(challenge)
                .writeBytes(userSecret));
    }

    public byte[] writeClientAuthError(String message) {
        return BinaryWriter.write(w -> w
                .writeBoolean(false)
                .writeString(message));
    }

    public byte[] writeHeartbeatAck(byte[] nextChallenge, long serverTime) {
        return BinaryWriter.write(w -> w
                .writeBoolean(true)
                .writeBytes(nextChallenge)
                .writeLong(serverTime));
    }

    public byte[] writeHeartbeatNack(long serverTime) {
        return BinaryWriter.write(w -> w
                .writeBoolean(false)
                .writeLong(serverTime));
    }

    public byte[] writeSessionRevoked(long serverTime, String reason) {
        return BinaryWriter.write(w -> w
                .writeLong(serverTime)
                .writeString(reason));
    }

    public byte[] writeMachineInfoResponse(boolean success) {
        return BinaryWriter.write(w -> w.writeBoolean(success));
    }

    public byte[] writeError(int code, String message) {
        return BinaryWriter.write(w -> w
                .writeInt(code)
                .writeString(message));
    }

    public byte[] writeInitSuccess(String username, List<ProductInfo> products) {
        return BinaryWriter.write(w -> {
            w.writeBoolean(true);
            w.writeString(username);
            w.writeInt(products.size());
            for (ProductInfo p : products) {
                w.writeString(p.code().name());
                w.writeString(p.name());
                w.writeString(p.description() != null ? p.description() : "");
                w.writeLong(p.expiresAt());
                w.writeBoolean(p.lifetime());
            }
        });
    }

    public byte[] writeInitError(int code, String message) {
        // Client receives only the error code (no descriptive message for security)
        // Format: bool(false) + string(errorCode) + int(0)
        // Compatible with InitResponseData: success=false, username=errorCode, productCount=0
        return BinaryWriter.write(w -> w
                .writeBoolean(false)
                .writeString(String.valueOf(code))
                .writeInt(0));
    }

    public byte[] writeInitErrorWithReason(int code, String reason) {
        // Extended format: bool(false) + string("code|reason") + int(0)
        // Loader parses the pipe separator and displays the reason string to the user.
        return BinaryWriter.write(w -> w
                .writeBoolean(false)
                .writeString(code + "|" + reason)
                .writeInt(0));
    }

    public byte[] writeFileResponse(FileResponseData response) {
        return BinaryWriter.write(w -> {
            w.writeBoolean(response.success());
            if (response.success()) {
                // New layout: success | compressed | originalSize | compressedSize | bytes.
                // Loader + client readers are updated in lockstep — old binaries on
                // dev will fail to parse, which is the right signal during a wire
                // protocol bump.
                w.writeBoolean(response.compressed());
                w.writeInt(response.originalSize());
                w.writeInt(response.compressedSize());
                w.writeLengthPrefixedBytes(response.encryptedData());
            } else {
                w.writeBoolean(false);
                w.writeInt(0);
                w.writeInt(0);
                w.writeLengthPrefixedBytes(new byte[0]);
                w.writeString(response.errorMessage() != null ? response.errorMessage() : "Unknown error");
            }
        });
    }

    public byte[] writeConfigResponse(ConfigResponseData response) {
        return BinaryWriter.write(w -> {
            w.writeBoolean(response.success());
            w.writeBytes(new byte[]{ response.operation() });
            w.writeString(response.message() != null ? response.message() : "");
            if (response.configData() != null) {
                w.writeLengthPrefixedBytes(response.configData());
            } else {
                w.writeLengthPrefixedBytes(new byte[0]);
            }
            // Entries for LIST operation
            if (response.entries() != null) {
                w.writeInt(response.entries().size());
                for (ConfigResponseData.ConfigEntry entry : response.entries()) {
                    w.writeString(entry.id());
                    w.writeString(entry.name());
                    w.writeString(entry.description() != null ? entry.description() : "");
                    w.writeString(entry.author() != null ? entry.author() : "");
                    w.writeString(entry.createdDate() != null ? entry.createdDate() : "");
                    w.writeString(entry.modifiedDate() != null ? entry.modifiedDate() : "");
                }
            } else {
                w.writeInt(0);
            }
        });
    }

    public byte[] writeFileChunkMeta(FileChunkMetaData meta) {
        return BinaryWriter.write(w -> w
                .writeString(meta.fileKey())
                .writeInt(meta.totalSize())
                .writeInt(meta.compressedSize())
                .writeInt(meta.chunkCount())
                .writeInt(meta.chunkSize())
                .writeBoolean(meta.compressed())
                .writeLong(meta.timestamp()));
    }

    public byte[] writeFileChunk(FileChunkData chunk) {
        return BinaryWriter.write(w -> w
                .writeString(chunk.fileKey())
                .writeInt(chunk.chunkIndex())
                .writeLengthPrefixedBytes(chunk.chunkData())
                .writeLong(chunk.timestamp()));
    }
}
