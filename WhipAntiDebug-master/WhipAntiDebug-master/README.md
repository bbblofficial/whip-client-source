# WhipAntiDebugger

Framework anti-debug / anti-reverse / anti-tamper pour Windows x64, conçu pour rendre une cible virtuellement impossible à analyser, attacher, dumper ou patcher.

Header-only C17 (un seul `.cpp` pour le bridge WhipSysCall), zéro CRT dans le framework, zéro import ntdll côté binaire (tout passe par syscalls directs via WhipSysCall + JIT/transient gadgets polymorphes).

CTF mode : un flag est XOR-chiffré avec une clé dérivée du score agrégé. `score == 0` ⇒ flag correct. Tout indice de debugger / VM / hook / patch ⇒ score ≠ 0 ⇒ keystream différent ⇒ garbage.

---

## Architecture

```
WhipAntiDebugger/
├── antidebug/
│   ├── core/                Infrastructure & cryptographie
│   │   ├── types.h, macros.h, config.h
│   │   ├── syscall_bridge.h / .cpp     Bridge C → WhipSysCall
│   │   ├── poly_syscall.h              T3 JIT + T5 transient pages
│   │   ├── string_encrypt.h            XOR compile-time char-par-char
│   │   ├── strenc_extra.h, text_encrypt.h
│   │   ├── mem_encrypt.h               Vault XOR clé RDTSC split
│   │   ├── value_guard.h               Guarded int/float, opaque CMP
│   │   ├── int_spoof.h, opaque.h
│   │   ├── self_protect.h              State MAC, flow chain, canary
│   │   ├── score_vault.h               Score chiffré + obfuscation
│   │   ├── api_guard.h, api_hash.h     Resolver guard, FNV-1a hashes
│   │   ├── syscall_guard.h             SSN integrity
│   │   ├── latent_tamper.h / 2.h       Booby-trap différé (post-init)
│   │   ├── hyperion_blob.h             Code chiffré décrypté in-place
│   │   ├── tamper_trip.h               Tripwires multipoint
│   │   ├── stealth_wipe.h              Wipe stack/heap après usage
│   │   ├── flag_honeypot.h             Faux flag visible en mémoire
│   │   ├── sentinels.h, watchdog.h, heartbeat.h
│   │   ├── witness_chain.h             Chaîne de témoins (log MAC)
│   │   ├── stack_anchor.h, veh_dispatch.h
│   │   ├── guardian_matrix.h, guardian_meta.h, guardian_ring.h, guardian_watchdog.h
│   │   ├── whip_hostile.h, whip_meta.h
│   │   └── vmp_markers.h               VMProtect Ultimate hints
│   │
│   ├── checks/              Modules de détection
│   │   ├── debug/           PEB, NtGlobalFlag, HeapFlags, DebugPort, DebugFlags,
│   │   │                    debug_object_remove, parent_process, se_debug,
│   │   │                    handle_scan, suspicious_dlls, process_scan,
│   │   │                    process_sig_scan, dbgui_patch, handle_trace,
│   │   │                    system_info, kd_deep, kd_extra, al_khaser_classics,
│   │   │                    debugger_behavior, remote_debug, sandbox_checks,
│   │   │                    window_scan
│   │   ├── debugger/        int3_pockets (poison pages PAGE_NOACCESS)
│   │   ├── timing/          rdtsc, loops, qpc_timing, cross_timer,
│   │   │                    total_elapsed, tsc_qpc_drift
│   │   ├── breakpoints/     hardware (DR0–DR3/DR7), hardware_via_exc, int3_scan
│   │   ├── exceptions/      seh, trap_flag, veh_decoy, veh_encrypted_cfg
│   │   ├── threads/         hide_thread (+ verify), orphan_threads
│   │   ├── runtime/         anti_attach, anti_breakin, anti_dump, drop_privs,
│   │   │                    fake_hwbp, frida_thread_scan, vad_ldr_diff,
│   │   │                    page_guard_trap, guard_pages, tls_check,
│   │   │                    etw_detect, etw_ti_detect, hook_detect,
│   │   │                    instrumentation, kernel_callback_indirect,
│   │   │                    private_exec_scan, raise_hard_error,
│   │   │                    halos_gate_desync, heavens_gate, write_watch,
│   │   │                    thread_monitor, wireshark_detect
│   │   ├── integrity/       code_hash, anti_patch, anti_tamper, nop_patrol,
│   │   │                    stack_unwind_check, critical_scan,
│   │   │                    self_disk_mem, ept_split, exc_dispatcher_patch,
│   │   │                    iat_target, memory_bp_detect, ntdll_dispatchers,
│   │   │                    ntdll_full_text, section_protection,
│   │   │                    universal_hook_scan
│   │   ├── vm/              vm_detect, vm_master, vm_cpuid_deep,
│   │   │                    vm_device_artifacts, vm_firmware_scan,
│   │   │                    vm_io_backdoor, vm_memory_anomaly,
│   │   │                    vm_timing_vmexit, anti_emulation, hwid_fingerprint
│   │   ├── advanced/        advanced_master, ghost_breakpoints,
│   │   │                    pipeline_desync, scheduler_sync,
│   │   │                    exception_fingerprint, exception_rip_anchor,
│   │   │                    impossible_states, selfmod_race, pressure_test,
│   │   │                    temporal_traps, cross_process, heisenberg,
│   │   │                    anti_scyllahide, deep_scyllahide, anti_titanhide,
│   │   │                    syscall_verify, working_set_probe, btb_triangulate,
│   │   │                    decoy_honeypot
│   │   ├── hardened.h       Triple-read + cross-validation
│   │   ├── correlation.h    Distributed Truth Engine (scoring exponentiel)
│   │   ├── deep_checks.h    Self-mapping, poisoning, cache, variance
│   │   ├── exotic.h         Trap flag, INT 2D, KUSD, anti-attach, timing bomb
│   │   ├── extra_master.h   Wrapper supplémentaire post-hardened
│   │   └── decoy_checks.h   Fausses détections pour épuiser l'analyste
│   │
│   ├── dispatcher/
│   │   └── dispatcher.h     XORSHIFT64, Fisher-Yates, skip probabiliste, flow chain
│   │
│   ├── stack/               Stack spoofing
│   │   ├── moonwalk.h / moonwalk_asm.h / moonwalk_stub.asm
│   │   ├── phantom_call.h           Exception div/0 + XOR fn ptr
│   │   ├── stack_desync.h           XOR scramble + shadow space pollution
│   │   ├── gadget_chain.h           Post-CALL return addresses ntdll
│   │   ├── stack_flood.h            Flood stack entière + 8 frames decoy
│   │   ├── syscall_spoof.h          syscall;ret gadget rotation
│   │   ├── cloaked_call.h / .asm    Trampoline cloaké
│   │   ├── stealth_exec.h           Exec via thread fantôme RWX
│   │   ├── thread_noise.h           Threads bruit pour brouiller le scheduler
│   │   ├── main_ra_spoof.h          Spoof de la return address de main
│   │   └── fake_decrypt_thread.h    Thread fantoche qui « décrypte » du garbage
│   │
│   ├── vm/                  Custom bytecode VM (WhipVM v3)
│   │   ├── vm_interp.h              Semantic drift, history chain, entanglement
│   │   └── vm_programs.h            Bytecode builder + flag derive/decrypt
│   │
│   ├── honeypot/
│   │   ├── ai_decoys.h              Section .ainotic + 14 export tripwires
│   │   └── ai_symbols.c             Faux symboles « lisibles » pour LLM-RE
│   │
│   ├── static_analysis_*.h          Anti-static-analysis suite
│   ├── basic_static_checks.h, advanced_static_traps.h, additional_static_checks.h
│   ├── binary_integrity_paranoid.h, bypass_detection_ultimate.h
│   ├── comprehensive_static_detection.h, sandbox_analysis_detection.h
│   ├── ai_confusion_tricks.h
│   ├── early_warning.c / .h         Sentinelles armées avant main
│   ├── tls_callback.c               TLS callback pre-main detect
│   └── syscall_bridge.cpp           Seul fichier C++ (bridge WhipSysCall)
│
├── main_example.c           Cible CTF — flag chiffré par le score
├── dll_example.c            Variante DLL injection
├── tools/
│   ├── pe_harden.c                  Post-build PE hardening (TLS, headers…)
│   └── gen_strenc.py                Générateur de strings chiffrées
├── tests/                   ~30 harnesses unitaires (boss, blackbox, reverse,
│                            wh / wm / gw / gr / gm / gmeta, uhs, sp, iat,
│                            sdm, ot, nft, ndt, xdp, hw_via_exc, btb,
│                            tsc_qpc_drift, kd_classics, vm_checks, vm_perf,
│                            vm_drift, vm_bench, dll_loader, spoof,
│                            thread_noise, wireshark, moonwalk, new_checks…)
│
└── CMakeLists.txt           C17 + C++20 + MASM, MSVC + Ninja
```

---

## Couches de protection

### Couche 0 — Invisibilité statique

| Protection | Détail |
|---|---|
| String encryption | Toutes les strings NT (`NtQueryInformationProcess`, `NtClose`, etc.) XOR-chiffrées char par char sur la stack. Jamais en `.rdata`. Clé dérivée de `__LINE__`. Wipe après usage. |
| Constant derivation | Constantes (seuils timing, magic numbers) stockées en `(encoded, mask)`, dérivées au runtime. Aucune immédiate reconnaissable. |
| Opaque comparisons | Remplacent `CMP imm` par de l'arithmétique de bits — pas de `cmp rax, 0x7D0` dans le disasm. |
| PE header erasure | Au démarrage : zero du PE header + `PAGE_NOACCESS`. Tout dump produit un PE corrompu. SizeOfImage gonflé ⇒ dumpers tronqués. |
| Hyperion blob | Code chiffré, déchiffré in-place, ré-encrypté juste après exécution. |
| AI-decoy honeypot | Section `.ainotic` + 14 exports tripwire ciblés sur LLM-RE / Ghidra plugins / IDA scripts. |
| `pe_harden` post-build | Renforce le PE final (TLS, debug dirs, checksum, section flags). |

### Couche 1 — Détection observable (60+ checks)

Chaque check est **hardened** : triple-read avec barriers, cross-validation, et alimente le moteur de corrélation.

Catégories : PEB / NtGlobalFlag / HeapFlags · DebugPort (classes 7, 30, 31, 35) · KdDebuggerEnabled / KdDebuggerNotPresent (KUSD, unhookable) · DbgBreakPoint audit · NtClose trap · Hide-thread + verify · Hardware BP (DR0–DR3 + DR7) · INT3 scan · RDTSC single + double · QPC + cross-timer (RDTSC × QPC × NtQueryPerformanceCounter) · Loop timing (LCG) · TSC/QPC drift (VM/TTD) · SEH asymmetry · VM (CPUID hyper-bit + vendor + RDTSC overhead + IO backdoor + firmware + device artifacts + memory anomaly + VMEXIT timing + CPUID deep) · HWID fingerprint · Anti-emulation · Kernel debugger · DebugObject remove · Hook detect (ntdll stubs) · Universal hook scan (toutes les exports) · Guard page trap · DR canary · Suspicious modules (Frida, Pin, DynamoRIO, Sandboxie, VBox…) · Frida thread scan · Instrumentation callback · Parent process · SeDebug · WriteWatch · DbgUi patch · Handle scan (foreign debug handles) · ETW + ETW-TI · Trap flag · ScyllaHide / TitanHide / Deep ScyllaHide · BTB triangulation · Ghost breakpoints (CoW) · Pipeline desync · Scheduler sync · Exception fingerprint + RIP anchor · Impossible states · Selfmod race · Pressure test · Temporal traps · Cross-process · Heisenberg · Working-set probe · Halos Gate desync · Heaven's Gate · `NtRaiseHardError` probe · Kernel-callback indirect · Private-exec scan · `MEM_WRITE_WATCH` · Window scan · Remote debug · Sandbox checks · al-khaser classics · kd_deep / kd_extra · debugger_behavior · Wireshark / tshark · IAT target validation · Self disk-vs-memory · Orphan threads · ntdll full-text + multi-point · KiUserExceptionDispatcher · Section protection drift · EPT split · Memory BP detect · TLS check · Critical scan · Total elapsed time · Anti-breakin trampoline · Anti-attach (NoInherit + auto-debug-object) · Drop SeDebug · Fake HW-BP squat · VAD-LDR diff · Stack unwind · VEH decoy · VEH-encrypted CFG · INT3 pockets…

### Couche 2 — Corrélation (Distributed Truth Engine)

Au lieu de scorer chaque check isolé, on détecte les **contradictions physiquement impossibles**. ~13 règles : `NtGlobalFlag=debug ∧ PEB.BeingDebugged=0` (PEB patché), `syscall lent ∧ ntdll clean` (hooks user-mode), `KUSD KdEnabled ∧ PEB clean` (kernel debugger stealth), `ThreadHide success ∧ DebugPort clean` (ScyllaHide-class bypass), etc.

Scoring : `severity_totale × 2^contradictions`. Un bypass partiel **explose** le score.

### Couche 3 — Deep reality checks

Self-mapping (read direct vs `NtReadVirtualMemory` ⇒ EPT hooks) · Information poisoning PEB / NtGlobalFlag (set value, observe correction) · Multi-source timing ratio · CPUID consistency · Cache timing L1 (Pin/DynamoRIO) · Scheduling variance.

### Couche 4 — Exotic & extra masters

Trap flag · INT 2D · ProcessDebugObjectHandle · Nested SEH · `NtIsProcessInJob` · `NtYieldExecution` latency · `NtCreateDebugObject` self-attach · KUSER_SHARED_DATA timing (kernel-mapped, unhookable) · Environment cleanliness · Timing bomb · Plus le `extra_master` qui regroupe DbgUiRemoteBreakin, ETW hook, fake HW-BP verify, anti-attach verify, cross-timer, VAD-LDR, stack unwind, VEH decoy, PAGE_GUARD sentinel.

### Couche 5 — Self-protection

| Mécanisme | Cible | Poison |
|---|---|---|
| State MAC (FNV-1a + memkey) | Cheat Engine modifie `ad_state` | +0x8000 |
| Resolver guard (CRC32 SyscallStub) | Hook sur le bridge | +0x4000 |
| Flow chain | NOP d'un check individuel | +0x2000 |
| Init canary (chiffré) | NOP de `ad_init` | +0xFFFF |
| Hide verify | ScyllaHide fake `STATUS_SUCCESS` | +0x100 |
| NOP patrol | NOP d'un CALL site enregistré | exponentiel |
| Latent tamper | Booby-trap armé post-init, déclenché plus tard | variable |
| Witness chain | Log MAC chaîné — break = poison | exponentiel |
| Guardian matrix / meta / ring / watchdog | Surveillance croisée multi-couches | exponentiel |

**Tout est branchless** — aucun `if (tampered) exit()` à NOPer. Le poison s'ajoute arithmétiquement au score.

### Couche 6 — Stack spoofing (multi-stratégies)

Moonwalk classique · Gadget chain (post-CALL ntdll) · Phantom call (exception + XOR fn ptr) · Stack scramble · Shadow space pollution · Total flood (TEB bounds, 8 frames decoy imbriqués) · Cloaked call · Stealth-exec via thread fantôme RWX · Thread noise (bruit scheduler) · Main RA spoof.

Stratégie choisie aléatoirement par le PRNG à chaque pass — chemin imprédictible. Résultat dans x64dbg : 19+ frames de gibberish XOR-scrambled.

### Couche 7 — Mémoire chiffrée

`ad_vault_t` (XOR clé RDTSC split) · `ad_guarded_u32/u64` (clé rotative + MAC FNV) · `ad_enc_result_t` (résultat chiffré, déchiffré bref sur stack, wipe) · PRNG state chiffré · decoy table chiffrée · `score_vault` (score lui-même chiffré).

### Couche 8 — WhipVM (Chaotic Deterministic VM)

VM custom où tourne la logique critique (dérivation clé, XOR du flag). Propriétés :
- **Semantic drift** — l'opcode `0x05` = XOR maintenant, MUL dans 8 instructions (sem_table tournante)
- **History chain** — chaque opcode dérive sa clé des 4 précédents
- **Observer effect** — single-step ⇒ shift sem_table ⇒ résultat faux sans crash
- **Entangled registers** — écrire R1 modifie silencieusement R4
- **Ghost registers** — 8 visibles + 8 shadow, swap atomique via VM_GHOST
- **Dual accumulator** — ACC + XACC, fusion VM_MERGE
- **Memory aliasing** — même adresse ↦ valeurs différentes (compteur interne)

IDA voit : `while (!halted) switch (bytecode[pc] ^ key) { 24 cases }`. La logique du flag est invisible.

### Couche 9 — Polymorphic syscalls

`AD_ENABLE_POLY_TRANSIENT` (T5) — page fraîche allouée par appel, nouvelle adresse à chaque fois, défait tout hook-by-address.
`AD_ENABLE_POLY_JIT` (T3, fallback) — `0F 05` présent uniquement durant la fenêtre d'appel, `90 90` au repos. ~3–4 syscalls supplémentaires par syscall réel.

### Couche 10 — Sentinelles & honeypots

Sentinelles détachées armées avant `main` (TLS callback + early_warning) · Faux flag visible en mémoire (`flag_honeypot`) · Decoy checks qui produisent du faux positif sur les bypass tools · AI-decoy section + exports tripwire ciblés sur les outils LLM-assisted RE.

---

## Flux d'exécution (`main_example.c`)

1. `whip_bridge_init()` — resolver SyscallStub
2. `ad_init()` — state, memkey, MAC, PRNG, code hash, hide thread, PEB tripwires, canary, resolver guard
3. `ad_decoy_table_init()` + `ad_gadget_table_init()` — scan ntdll
4. `ad_self_hash_init()` — CRC32 fonctions critiques
5. **Install block** (VMP Ultra) : VEH install · drop SeDebug · fake HW-BP · anti-attach NoInherit · anti-breakin trampoline · latent tamper · VEH-CFG · decoy honeypot · PAGE_GUARD sentinel
6. `ad_anti_tamper_baseline()` — CRC32 après hooks
7. `ad_erase_pe_header()` — anti-dump
8. Stack flood + phantom call → `ad_run_hardened()`
9. Encrypt result · NOP patrol · `ad_run_supplemental()` (60+ checks)
10. Score obfusqué → `derive_key_stream(score)` → flag décrypté **dans la VM** → `write_console`

---

## Scoring

```
score = correlation_score      // 2^N contradictions
      + deep_score             // shadow exec, poisoning, cache, variance
      + cross_score            // PEB cross-validation
      + patch_score            // CRC32, prologues, page, INT3
      + exotic_score           // trap flag, INT2D, KUSD, timing bomb
      + advanced_score         // ghost BP, BTB, Heisenberg, ScyllaHide…
      + extra_score            // DbgUi, ETW, fake HW-BP, VEH decoy…
      + supplemental_score     // VM master, halo, heaven, hardened-syscall…
      + self_poison            // state MAC, resolver, canary, NOP patrol,
                               // latent tamper, witness chain, guardians
```

---

## Build

```bash
cmake -B build -G Ninja
cmake --build build --target WhipAntiDebugger_Example
```

Cibles principales :

| Target | Rôle |
|---|---|
| `WhipAntiDebugger_Example` | Production CTF binary |
| `WhipAntiDebugger_TestMode` | `AD_TESTING_MODE=1` + `AD_DEBUG_BREAKDOWN` — sentinelles latentes désarmées, dump détaillé score (à utiliser sous x64dbg pour vérifier Meta-A→E) |
| `WhipAntiDebugger_DLL` | Variante DLL injectable (dll_example.c) |
| `MoonwalkTest`, `BossTest`, `TestBlackbox`, `TestReverse`, `TestKdClassics`, `TestVmChecks`… | ~30 harnesses unitaires |

Recommandé : passer le binaire final par **VMProtect Ultimate** (mutation + virtualization sur `main`, `derive_key_stream`, `ghost_*`, `ad_run_*`) pour empiler la couche VMP au-dessus.

Prérequis :
- MSVC (Visual Studio 2022+)
- WhipSysCall (`C:/Users/Java/Desktop/whip/WhipSysCall`)
- VMProtectSDK64.lib
- CMake 3.20+, C17, C++20, MASM, Ninja

---

## Coût du bypass

Pour faire afficher le bon flag, un reverseur doit **simultanément** :

1. Neutraliser `ThreadHideFromDebugger` *et* sa vérification post-Set
2. Faker PEB / NtGlobalFlag / HeapFlags / KUSD de manière cohérente (sinon corrélation explose)
3. Ne pas trigger NtClose trap, guard page, PAGE_GUARD sentinel, SEH asymmetry
4. Ne déclencher aucun timing trap (RDTSC, QPC, cross-timer, TSC/QPC drift, KUSD timing, timing bomb)
5. Battre la détection de hooks (ntdll, universal, IAT, ETW, ETW-TI, DbgUi…)
6. Survivre au moteur de corrélation : *toute* contradiction ⇒ scoring exponentiel
7. Empêcher NOP patrol, latent tamper, witness chain, guardians de se déclencher
8. Mettre à jour state MAC + resolver CRC + flow chain + score MAC + score vault correctement
9. Reverse la WhipVM (semantic drift + history chain + entanglement) pour comprendre la dérivation du flag
10. Ne pas trigger les sentinelles latentes / honeypot AI / decoy checks
11. Ignorer les ~30 advanced checks (BTB, ghost BP, Heisenberg, impossible states, ScyllaHide, TitanHide, working set, exception fingerprint…)
12. Atterrir sur un score final de **exactement 0**

Chaque check supplémentaire corrélé multiplie le coût. La conception est branchless de bout en bout — il n'existe aucun `JE` à patcher.
