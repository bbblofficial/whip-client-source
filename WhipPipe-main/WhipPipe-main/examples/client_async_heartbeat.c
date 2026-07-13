#include <whippipe.h>
#include <stdio.h>

static void on_message(const WhipMessage* msg, void* user)
{
    if (msg->type == IpcPing || msg->type == IpcPong)
        return;

    printf("[Client Async] Recu %s", whipMessageTypeStr(msg->type));
    if (msg->data && msg->len > 0)
        printf(" : %.*s", (int)msg->len, msg->data);
    printf("\n");
}

static void on_connect(void* user)
{
    printf("[Client Async] Connecte\n");

    WhipClient* pc = (WhipClient*)user;
    whipClientSend(*pc, IpcReady, NULL, 0);
    printf("[Client Async] Envoye IPC_READY\n");
}

static void on_disconnect(void* user)
{
    printf("[Client Async] Deconnecte\n");
}

static void on_error(const char* error, void* user)
{
    printf("[Client Async] Erreur : %s\n", error);
}

int main(void)
{
    WhipClient client = whipClientCreate("127.0.0.1", 9910);
    if (!client) {
        printf("[Client] Erreur allocation\n");
        return 1;
    }

    whipClientEnableHeartbeat(client, 2000);

    printf("[Client] Connexion a 127.0.0.1:9910...\n");
    if (!whipClientListenAsync(client, on_message, on_connect, on_disconnect, on_error, &client, 5000)) {
        printf("[Client] Erreur listen_async\n");
        whipClientDestroy(client);
        return 1;
    }

    printf("[Client] Heartbeat actif (2s)\n");
    printf("[Client] Appuyez sur Entree pour quitter...\n");

    getchar();

    whipClientStop(client);
    whipClientDestroy(client);

    printf("[Client] Arrete.\n");
    return 0;
}