/******************************************************************************
 * Test de honeypot enregistreur SSH tout simple
 * Bertrand sept 2024
 ******************************************************************************/


/* sys */
#define _XOPEN_SOURCE
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <sys/time.h>
#include <malloc.h>
#include <wait.h>
#include <termios.h>


/* libc */
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>


/* local */



/******************************************************************************
 * Lecture d'un fichier d'enregistrement
 */


/* à déplacer en fichier d'entête */
struct ttyRecordEntry_s {
    time_t       tv_sec;
    suseconds_t  tv_usec;
    int          type;
    size_t       len;
    char         data[];
};


#define TTY_RECORD_STDIN       0
#define TTY_RECORD_STDOUT      1
#define TTY_RECORD_STDERR      2

#define TTY_RECORD_SERVER_TO_CLIENT  3 
#define TTY_RECORD_CLIENT_TO_SERVER  4
#define TTY_RECORD_NONE              5 /* il ne se passe rien, log juste pour vérifier que rien n'est mort. En lien avec le timeout de poll() */

#define TTY_RECORD_START       21 /* lancement du bastion */
#define TTY_RECORD_EXIT        22 /* le terminal se ferme, le shell fils a fait exit()      data=son code de retour */

#define TTY_RECORD_FILE_UPLOAD   11  /* cas à préciser par la suite */
#define TTY_RECORD_FILE_DOWNLOAD 12


struct ttyRecordEntry_s* ttyRecordRead(int fd)  {
    struct ttyRecordEntry_s record;
    struct ttyRecordEntry_s *result = NULL;

    size_t nlu = read(fd, &record, sizeof(record));

    /* Soit lu 0 si c'est le dernier, soit moins = cas bizarre*/
    if (nlu != sizeof(record)) return NULL;


    /* reprend le struct au début de la valeur en retour */
    result = (struct ttyRecordEntry_s *)malloc(record.len+sizeof(record));
    memcpy(result, &record, sizeof(record));
    

    /* lit la partie données */
    if (record.len != 0) {
        nlu = read(fd, ((void*)result) + sizeof(record), record.len);        
        /* attention à l'addition de pointeurs ! */
    }

    return result;
}

void printColorTitle(char* s, int fg, int bg ) {
    printf("\033[%d;%d;52m", fg+30, bg+40);
    printf("%s\033[0K",s);
    printf("\033[0m\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("%s <nom de fichier>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd <0) {
        perror("Impossible d'ouvrir le fichier");
        abort();
    }

    char bufferStrftime[64];
    char bufferTitle[128];
    struct tm tm;
                
    struct ttyRecordEntry_s* record;
    while (true) {
        record = ttyRecordRead(fd);
        if (record == NULL) break;

        /* tv_usec en fait pas utilisable avec localtime() ... */
        localtime_r(&record->tv_sec, &tm);
        strftime(bufferStrftime, 128, "%FT%T%z", &tm);

        switch (record->type) {
            case TTY_RECORD_SERVER_TO_CLIENT:
                snprintf(bufferTitle, 127, "server->client %s", bufferStrftime);
                printColorTitle(bufferTitle, 7, 1);
                puts(record->data);
                break;

            case TTY_RECORD_CLIENT_TO_SERVER:
                snprintf(bufferTitle, 127, "client->server %s", bufferStrftime);
                printColorTitle(bufferTitle, 7, 4);
                puts(record->data);
                break;

            case TTY_RECORD_NONE: break;
            case TTY_RECORD_START:
                snprintf(bufferTitle, 127, "session start %s", bufferStrftime);
                printColorTitle(bufferTitle, 7, 2);
                puts(record->data);
                break;

            case TTY_RECORD_EXIT:
                snprintf(bufferTitle, 127, "session end %s", bufferStrftime);
                printColorTitle(bufferTitle, 7, 2);
                puts(record->data);
                break;

            default: printf("Type inconnu %d\n", record->type);
        }
        free(record);
    }
}