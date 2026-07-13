#include <whippipe.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    WhipClient client = whipClientCreate("127.0.0.1", 9910);
    if (!client) {
        printf("[Client] Erreur allocation\n");
        return 1;
    }

    printf("[Client] Connexion a 127.0.0.1:9910 (timeout 5s)...\n");
    if (!whipClientConnect(client, 5000)) {
        printf("[Client] Timeout - assurez-vous que le loader est lance\n");
        whipClientDestroy(client);
        return 1;
    }

    printf("[Client] Connecte !\n\n");

    whipClientSend(client, IpcReady, NULL, 0);
    printf("[Client] Envoye IPC_READY\n");

    WhipMessage msg = { 0 };
    if (whipClientReceive(client, &msg)) {
        printf("[Client] Recu %s", whipMessageTypeStr(msg.type));
        if (msg.data && msg.len > 0)
            printf(" : %.*s", (int)msg.len, msg.data);
        printf("\n");
        whipClientFreeMessage(&msg);
    }

    const char* status = "DLL running OK";
    whipClientSend(client, IpcStatus, (const unsigned char*)status, (unsigned int)strlen(status));
    printf("[Client] Envoye IPC_STATUS\n");

    printf("[Client] Appuyez sur Entree pour quitter...\n");
    getchar();

    whipClientDisconnect(client);
    whipClientDestroy(client);
    printf("[Client] Deconnecte.\n");
    return 0;
}