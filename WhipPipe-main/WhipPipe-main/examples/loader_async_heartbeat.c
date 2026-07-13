#include <whippipe.h>
#include <stdio.h>

static void on_message(const WhipMessage* msg, void* user)
{
    if (msg->type == IpcPing || msg->type == IpcPong)
        return;

    printf("[Loader Async] Recu %s", whipMessageTypeStr(msg->type));
    if (msg->data && msg->len > 0)
        printf(" : %.*s", (int)msg->len, msg->data);
    printf("\n");
}

static void on_connect(void* user)
{
    printf("[Loader Async] DLL connectee\n");
}

static void on_disconnect(void* user)
{
    printf("[Loader Async] DLL deconnectee\n");
}

static void on_error(const char* error, void* user)
{
    printf("[Loader Async] Erreur : %s\n", error);
}

int main(void)
{
    WhipLoader loader = whipLoaderCreate(9910, "127.0.0.1");
    if (!loader) {
        printf("[Loader] Erreur allocation\n");
        return 1;
    }

    whipLoaderEnableHeartbeat(loader, 2000);

    if (!whipLoaderListenAsync(loader, on_message, on_connect, on_disconnect, on_error, NULL)) {
        printf("[Loader] Erreur listen_async\n");
        whipLoaderDestroy(loader);
        return 1;
    }

    printf("[Loader] En ecoute sur 127.0.0.1:9910\n");
    printf("[Loader] Heartbeat actif (2s)\n");
    printf("[Loader] Appuyez sur Entree pour arreter...\n");

    getchar();

    whipLoaderStop(loader);
    whipLoaderDestroy(loader);

    printf("[Loader] Arrete.\n");
    return 0;
}