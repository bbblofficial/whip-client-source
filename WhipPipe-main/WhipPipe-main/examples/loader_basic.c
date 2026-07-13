#include <whippipe.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    WhipLoader loader = whipLoaderCreate(9910, "127.0.0.1");
    if (!loader) {
        printf("[Loader] Erreur allocation\n");
        return 1;
    }

    if (!whipLoaderStart(loader)) {
        printf("[Loader] Erreur demarrage\n");
        whipLoaderDestroy(loader);
        return 1;
    }

    printf("[Loader] En ecoute sur 127.0.0.1:9910\n");
    printf("[Loader] En attente de DLL...\n");

    if (!whipLoaderAccept(loader)) {
        printf("[Loader] Accept echoue\n");
        whipLoaderDestroy(loader);
        return 1;
    }

    printf("[Loader] DLL connectee !\n\n");

    while (whipLoaderIsConnected(loader))
    {
        WhipMessage msg = { 0 };

        if (!whipLoaderReceive(loader, &msg)) break;

        printf("[Loader] Recu %s", whipMessageTypeStr(msg.type));
        if (msg.data && msg.len > 0)
            printf(" : %.*s", (int)msg.len, msg.data);
        printf("\n");

        if (msg.type == IpcReady) {
            const char* reply = "Config data...";
            whipLoaderSend(loader, IpcConfig, (const unsigned char*)reply, (unsigned int)strlen(reply));
            printf("[Loader] Envoye IPC_CONFIG\n");
        }
        else if (msg.type == IpcError) {
            printf("[Loader] ERREUR DLL : %.*s\n", (int)msg.len, msg.data);
        }

        whipLoaderFreeMessage(&msg);
    }

    printf("\n[Loader] DLL deconnectee.\n");
    whipLoaderDestroy(loader);
    return 0;
}