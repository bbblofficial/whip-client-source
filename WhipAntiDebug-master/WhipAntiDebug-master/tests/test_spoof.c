// Minimal test for int_spoof.h — compile and load in x64dbg
#include <stdio.h>
#include <intrin.h>
#include "../antidebug/core/int_spoof.h"

#pragma comment(lib, "kernel32.lib")
__declspec(dllimport) void __stdcall Sleep(unsigned long ms);

// Force these to be global so they're easy to find in memory
volatile ad_spoof_u32   g_health;
volatile ad_spoof_f32   g_threshold;
volatile ad_spoof_str   g_secret;
volatile ad_spoof_ptr   g_ptr;

static const char g_real_data[] = "REAL_SECRET_KEY";
static const char g_fake_data[] = "placeholder_value";

// Marker to find in memory
static volatile char g_marker[] = "SPOOF_MARKER_HERE";

int main(void) {
    ad_spoof32_init((ad_spoof_u32*)&g_health, 1, 15);
    ad_spoof_f32_init((ad_spoof_f32*)&g_threshold, 0.001f, 3.14f);
    ad_spoof_str_init((ad_spoof_str*)&g_secret, "FLAG{s3cr3t}", "Access Denied");
    ad_spoof_ptr_init((ad_spoof_ptr*)&g_ptr, g_real_data, g_fake_data);

    printf("[*] marker  @ %p\n", (void*)g_marker);
    printf("[*] health  @ %p  .state=%u\n", (void*)&g_health, g_health.state);
    printf("[*] thresh  @ %p  .state=%f\n", (void*)&g_threshold, g_threshold.state);
    printf("[*] secret  @ %p  .text=\"%.13s\"\n", (void*)&g_secret, (const char*)g_secret.text);
    printf("[*] ptr     @ %p  .ref=%p\n", (void*)&g_ptr, (void*)g_ptr.ref);
    fflush(stdout);

    // Short sleep for quick test (use 120000 for real inspection)
    Sleep(100);

    // Decode
    u32   rh = ad_spoof32_load((ad_spoof_u32*)&g_health);
    float rt = ad_spoof_f32_load((ad_spoof_f32*)&g_threshold);
    char  buf[AD_SPOOF_STR_CAP];
    const char* rs = ad_spoof_str_load((ad_spoof_str*)&g_secret, buf);
    const char* rp = (const char*)ad_spoof_ptr_load((ad_spoof_ptr*)&g_ptr);

    printf("\n[+] REAL health    = %u  (decoy was 15)\n", rh);
    printf("[+] REAL threshold = %f  (decoy was 3.14)\n", rt);
    printf("[+] REAL string    = \"%s\"  (decoy was \"Access Denied\")\n", rs);
    printf("[+] REAL pointer   = \"%s\"  (decoy was \"placeholder_value\")\n", rp);

    AD_ZERO_BUF(buf, AD_SPOOF_STR_CAP);
    return 0;
}
