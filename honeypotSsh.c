/******************************************************************************
 * Test de honeypot enregistreur SSH tout simple
 * Bertrand sept 2024
 * 
 * TODO :
 *  - gestion des logs, messages d'erreur du programme (printf pour l'insant)
 *  - emplacement des enregistrements de session SSH
 * 
 * Peut servir de début pour un bastin SSH. Manque :
 *  - sécurité et cloisonnement, setuid
 *  - est invoqué par l'utilisateur lambda, et inséré entre 2 processus
 *    possédés par l'utilisateur lambda : besoin de renforcement
 *****************************************************************************/

/* syscall */
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
#include <signal.h>
//#include <asm/termbits.h>  /* ioctl() redimensionnement tty - erreur déjà inclus/défini ! */
#include <sys/ioctl.h>       /* ioctl() redimensionnement tty */

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
 * Configuration locale
 ******************************************************************************/
#define BUFFERSIZE    65536 /* pour le passe-plat */



/******************************************************************************
 * Fonctions utilitaires
 ******************************************************************************/

/* pour pouvoir compiler... n'existe que Linux >= 5.3 !!!! Bullseye forensic ok, WSL nok */
int pidfd_open(pid_t pid, unsigned int flags) { return 99; }




/******************************************************************************
 * Gestion de l'enregistrement
 ******************************************************************************/

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

struct ttyRecordEntry_s {
    time_t       tv_sec;
    suseconds_t  tv_usec;
    int          type;
    size_t       len;
    char         data[];
};

void ttyRecordWrite(int fd, int type, int len, char* data) {
    struct ttyRecordEntry_s record;
    struct timeval tv;
    gettimeofday(&tv, NULL);

    record.tv_sec  = tv.tv_sec;
    record.tv_usec = tv.tv_usec;
    record.type    = type;
    record.len     = len;

    write(fd, &record, sizeof(record));
    if (len>0) write(fd, data, len);
    
}

char* ttyRecordFilename() {
    static char r[1024] = ""; // /home/ber/truc";
    if (r[0]) return r; /* a déjà été appelé - Pas du tout thread safe !*/
    struct tm tm;
    time_t t = time(NULL);
    localtime_r(&t, &tm);
    strftime(r, 1023, "/tmp/ttyrecord-%FT%T%z", &tm);
    return r;
}

int ttyRecordOpen() {
    int r = open(ttyRecordFilename(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    printf("Nom de l'enregistrement : %s\n", ttyRecordFilename() );
    if (r < 0) {
        perror("open() sur le fichier d'enregistrement tty");
        printf("Erreur sur : %s\n", ttyRecordFilename() );
        abort();
    }
    return r;
}


/* 
  Mise en forme puis enregistrement du message demarrage de la session
 */
void ttyRecordStartMessage(int fd, char* argv0, char* childShell) {
    char buffer[1024];
    char *dest = buffer;  
    size_t r, reste=1023;
    memset(buffer, 0, sizeof(buffer));


    /* les trucs numériques */
    r = snprintf(dest, reste, "pid: %d\nppid: %d\nuid: %d\nsid: %d\npgid: %d\n",getpid(), getppid(), getuid(), getsid(0), getpgid(0));
    dest  += r;
    reste -= r;

    /* les noms d'executables */
    r = snprintf(dest, reste, "argv0: %s\nchildShell: %s\n", argv0, childShell);
    dest  += r;
    reste -= r;



    /* quelques variables d'env */
    const char* vars[] = { 
        "SSH_CONNECTION", "SSH_TTY", "SSH_CLIENT",
        "WAYLAND_DISPLAY", "DISPLAY", 
        "USERNAME", "LOGNAME", "USER", 
        "SHELL", "HOME", 
    NULL };

    for (int i=0; vars[i]; i++) {
        char* val = getenv(vars[i]);
        if (val) {
            r = snprintf(dest, reste, "%s: %s\n", vars[i], val);
            dest  += r;
            reste -= r;
        }
        if (reste <=0) break;
    }

    ttyRecordWrite(fd, TTY_RECORD_START, (dest-buffer), buffer);

}


/******************************************************************************
 * Gestion du mode raw sur notre pts reçu de sshd
 * https://www.cs.uleth.ca/~holzmann/C/system/ttyraw.c
 ******************************************************************************/

static struct termios orig_termios;  /* TERMinal I/O Structure */

int tty_reset(int ttyfd) {
    /* flush and reset */
    if (tcsetattr(ttyfd,TCSAFLUSH,&orig_termios) < 0) return -1;
    return 0;
}

void tty_raw(int ttyfd) {
    struct termios raw;

    if (tcgetattr(ttyfd,&orig_termios) <0) {
        perror("Can't get pts initial parameters");
        abort();        
    } 

    raw = orig_termios;  /* copy original and then modify below */

    /* input modes - clear indicated ones giving: no break, no CR to NL, 
       no parity check, no strip char, no start/stop output (sic) control */
    raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);

    /* output modes - clear giving: no post processing such as NL to CR+NL */
    raw.c_oflag &= ~(OPOST);

    /* control modes - set 8 bit chars */
    raw.c_cflag |= (CS8);

    /* local modes - clear giving: echoing off, canonical off (no erase with 
       backspace, ^U,...),  no extended functions, no signal chars (^Z,^C) */
    raw.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);

    /* control chars - set return condition: min number of bytes and timer */
    raw.c_cc[VMIN] = 5; raw.c_cc[VTIME] = 8; /* after 5 bytes or .8 seconds
                                                after first byte seen      */
    raw.c_cc[VMIN] = 0; raw.c_cc[VTIME] = 0; /* immediate - anything       */
    raw.c_cc[VMIN] = 2; raw.c_cc[VTIME] = 0; /* after two bytes, no timer  */
    raw.c_cc[VMIN] = 0; raw.c_cc[VTIME] = 8; /* after a byte or .8 seconds */

    /* put terminal in raw mode after flushing */
    if (tcsetattr(ttyfd,TCSAFLUSH,&raw) < 0) {
        perror("Can't set pts in raw mode");
        abort();
    }    
}



/******************************************************************************
 * Gestion du redimensionnement du TTY amont 
 * https://unix.stackexchange.com/questions/580362/how-are-terminal-information-such-as-window-size-sent-to-a-linux-program
 * https://www.man7.org/linux/man-pages/man2/sigaction.2.html  
 ******************************************************************************/
/*
TIOCGWINSZ
TIOCSWINSZ
ioctl_tty(2) manpage
SIGWINCH
*/

static int redimensionnementAfaire = 1; /* sera fait lors de la première boucle de poll() */

void sigwinchHandler (int sig, siginfo_t *info, void *ucontext)
{
    redimensionnementAfaire = 1;
}

void installeSigwinchHandler() {
    struct sigaction act = { 0 };

    act.sa_flags = SA_SIGINFO;
    act.sa_sigaction = &sigwinchHandler;

    if (sigaction(SIGWINCH, &act, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

/******************************************************************************
 * Gestion du processus fils, polling, état du bastion
 ******************************************************************************/
struct bastionState_s {
    pid_t     childPid;         /* PID du shell lancé en tant qu'enfant */
    int       childPollableFd;  /* pour inclure le polling du child avec celui du pts*/
    char*     ptsName;
    int       ptsMasterFd;
    int       ptsSlaveFd;
    int       ttyRecordFd;
    size_t    bytesFromServer;
    size_t    bytesFromClient;
};


int lanceFils(char* childShell, int argc, char* argv[]) {
    int r, fd; /* utilisé à courte portée pour les valeurs de retour, mais à plusieurs endroits  */
    struct bastionState_s state;
    memset((void*)&state, 0, sizeof(state));
    

    /* Préparation du pts */
    state.ptsMasterFd = open("/dev/ptmx", O_RDWR ); 
       /* Est-ce utile/nécessaire ? O_NOCTTY If pathname refers to a terminal device—see tty(4)—it will not become the process's controlling terminal even if the process does not have one. 
          O_DIRECT créé un EINVAL dans ce contexte...
       */
    if (state.ptsMasterFd <0) {
        perror("Erreur sur open(ptmx)");
        abort();  
    }

    char* s = ptsname(state.ptsMasterFd);
    if (s == NULL) {
        /* Cas d'erreur */
        perror("Erreur sur ptsname()");
        abort();
    }
    state.ptsName = strdup(s);

    /* lancement du sous process */
    state.childPid = fork();
    if (state.childPid == -1) {
       /* Cas d'erreurs possibles d'après man : EAGAIN ENOMEM ENOSYS ERESTARTNOINTR */
       perror("Erreur sur le fork()");
       abort(); /* TODO à gérer mieux ! */

    } else if (state.childPid == 0) {
        /* Cas fils : débloquer, ouvrir et utiliser le pts slave */
        r = grantpt(state.ptsMasterFd);
        if (r == -1) {
            perror("Erreur fatale sur grantpt() "); // serait capté dans le canal vers le parent
            abort();

        }
        r = unlockpt(state.ptsMasterFd);
        if (r == -1) {
            perror("Erreur fatale sur unlockpt() "); // serait capté dans le canal vers le parent
            abort();
        }

        /* Ferme les descripteurs standard */
        close(0);
        close(1);
        close(2);
        close(state.ptsMasterFd);

        
        /* Ouvre le pts à la place */
        state.ptsSlaveFd=open(state.ptsName, O_RDWR);
        dup2(state.ptsSlaveFd, 0);
        dup2(state.ptsSlaveFd, 1);
        dup2(state.ptsSlaveFd, 2);
       
        setsid();

 
        /* Et lance le process fils */
        argv[0] = childShell;
        execv(childShell, argv);
        perror("Erreur sur execve()");  // serait capté dans le canal vers le parent
        abort();

    } else {
        /* cas parent : utiliser le pts master et faire suivre les données en enregistrant */
        state.childPollableFd = pidfd_open(state.childPid, 0);

        printf("Le shell fils a le PID %d\n", state.childPid);
        printf("Notre PID est %d\n", getpid() );

        /* prépare l'enregistrement tty*/
        state.ttyRecordFd = ttyRecordOpen();
        ttyRecordStartMessage(state.ttyRecordFd, argv[0], childShell);


        /* Buffer principal, pour les transferts dans les deux sens, et autres. Courte portée */
        void* buffer = malloc(BUFFERSIZE);
        if (buffer == NULL) {
            perror("Erreur sur malloc() ");
            abort();
        }

        ssize_t nlu;    /* Combien a été lu, donc à renvoyer*/
        ssize_t necrit; /* valeur de retour des write(), mais on s'attend à ce que les buffers soient toujours intégralement ingérés */
        bool encore = true;
        int exitStatus=0;

        tty_raw(0);

        installeSigwinchHandler(); /* captation du signal pour redimensionnement */

        while (encore) {

            /* prépare la structure de poll() */
            struct pollfd fds[3];
            memset((void*) fds, 0, sizeof(fds));
            fds[0].fd = state.childPollableFd;
            fds[0].events = POLLIN;

            fds[1].fd = state.ptsMasterFd;
            fds[1].events = POLLIN; /* POLL_PRI permettrait peut-être de détecter la mort du fils */

            fds[2].fd = 0; /* notre stdin */
            fds[2].events = POLLIN;  

            r = poll(&fds[1], 2, 10000); /* timeout en ms */
            
            if (r == 0) {
                /* Poll a retourné sur timeout : on log un truc vide, juste pour voir que tout fonctionne */
                ttyRecordWrite(state.ttyRecordFd, TTY_RECORD_NONE, 0, NULL);

            } else {
                if (fds[0].revents & POLLIN) {                   
                    /* Process enfant a eu qqch */

                    int wstatus;
                    waitpid(state.childPid, &wstatus, WNOHANG);
                    if (WIFEXITED(wstatus)) {
                        exitStatus = WEXITSTATUS(wstatus);
                    } else {
                        printf("poll() a déclenché sur le process fils, mais celui-ci n'a pas exit()é   wstatus=0x%x\n", wstatus);
                    }
                }

                if (fds[1].revents & POLLIN) {
                    /* Données disponibles en lecture sur le pts master, à renvoyer sur notre stdout */
                    nlu = read(state.ptsMasterFd, buffer, BUFFERSIZE);
                    necrit = write(1, buffer, nlu);
                    state.bytesFromServer += nlu;
                    if (nlu != necrit) {
                        printf("Erreur, on a pas pu écrire autant qu'on voulait sur notre stdout nlu=%d necrit=%d\n", nlu, necrit);
                    }

                    ttyRecordWrite(state.ttyRecordFd, TTY_RECORD_SERVER_TO_CLIENT, nlu, buffer);

                }

                if (fds[2].revents & POLLIN) {
                    /* Données disponibles en lecture sur notre stdin, à renvoyer sur le pts master */
                    nlu = read(0, buffer, BUFFERSIZE);
                    necrit = write(state.ptsMasterFd, buffer, nlu);
                    state.bytesFromClient += nlu;
                    if (nlu != necrit) {
                        printf("Erreur, on a pas pu écrire autant qu'on voulait sur le pts master nlu=%d necrit=%d\n", nlu, necrit);
                    }
                    ttyRecordWrite(state.ttyRecordFd, TTY_RECORD_CLIENT_TO_SERVER, nlu, buffer);

                    /* Gestion du Ctrl-C Si un caractère ETX End-of-Text \x03 est détecté, envoie SIGINT au groupe de process d'avant plan */
                    char *c = buffer;
                    for (int i=0; i<nlu; i++) {
                        if (*c == 0x03) {
                            fd = open(state.ptsName, O_PATH);
                            pid_t fg_pgid = tcgetpgrp(fd); // getpgrp();
                            close(fd);
                            killpg(fg_pgid, SIGINT);
                        }
                        c++;
                    }
                }

                if (fds[1].revents & POLLHUP) {
                    /* le process enfant a fermé son pts */
                    printf("Le process enfant a fermé son pts");
                    encore = false;
                }

                if (fds[2].revents & POLLHUP) {
                    /* sshd nous a fermé le stdin */
                    printf("sshd a fermé notre stdin");
                    encore = false;
                }
            }

            /* Gestion du redimensionnement */
            if (redimensionnementAfaire) { /* flag levé via signal SIGWINCH*/
                /* TIOCGWINSZ TIOCSWINSZ  ioctl_tty(2) manpage   https://www.man7.org/linux/man-pages/man2/TIOCGWINSZ.2const.html */
                struct winsize ws;
                r = ioctl(0,  TIOCGWINSZ, &ws);
                if (r == -1) {
                    perror("ioctl() pour TIOCGWINSZ ");
                } else {
                    fd = open(state.ptsName, O_RDWR /*O_PATH ne suffit pas !*/ );
                    if (fd < 0) {
                        perror("open() du pts pour faire un TIOCSWINSZ");
                    } else {
                        r = ioctl(fd, TIOCSWINSZ, &ws);
                        if (r == -1) {
                            close(fd);
                            perror("Sur set window size TIOCSWINSZ ");
                        } else {
                            pid_t fg_pgid = tcgetpgrp(fd); // getpgrp();
                            close(fd);
                            killpg(fg_pgid, SIGWINCH);
                        }
                    }
                }
                redimensionnementAfaire = 0;
            }


        } /* while (encore)*/

        /* message de fin, fermeture pts master et enregistrement tty */
        close(state.ptsMasterFd);
        r = snprintf(buffer, BUFFERSIZE-1, "exitStatus: %d\nbytesServerToClient: %lld\nbytesClientToServer: %lld", exitStatus, state.bytesFromServer, state.bytesFromClient);
        ttyRecordWrite(state.ttyRecordFd, TTY_RECORD_EXIT, r+1, buffer);
        close(state.ttyRecordFd);
        free(buffer);
        
        tty_reset(0);
        return exitStatus;

    } /* if (fork() == ) */

    /* Tous les cas de retour sont gérés plus haut */
    abort();
}


/******************************************************************************
 * Programme principal
 ******************************************************************************/
int main(int argc, char*argv[]) {
    char *childShell = getenv("SHELL");
    if (childShell == NULL) childShell = "/bin/bash";

    int r = lanceFils(childShell, argc, argv); 
    return r;
}



/*

https://github.com/fish-shell/fish-shell/issues/4929
Piping interactive bash to a function stops the process

Semble indiquer que c'est à nous de détecter Ctrl-C / ETX  et de passer sigint à l'enfant :
https://stackoverflow.com/questions/45993444/in-detail-what-happens-when-you-press-ctrl-c-in-a-terminal

ETX = End-of-Text = 0x03 = Ctrl-C



Comment connaître la taille du terminal pts ? 3 méthodes :
1 - getenv("COLUMNS")
2 - TIOCWINSZ ioctl
3 - \x1b[9999;9999H    puis   "Device Status Report" \x1b[6n 





Sur la gestion des Ctrl-C :
---------------------------

https://stackoverflow.com/questions/45993444/in-detail-what-happens-when-you-press-ctrl-c-in-a-terminal

Whenever an ASCII ETX character (^C) is written to the master, the kernel translates that into sending SIGINT 
to the foreground process group with the corresponding controlling terminal. This is actually a pty setting. 
You can run stty -a and see that the default is intr = ^C;, meaning ^C or ETX is the "SIGINT" character. 
This can be changed to a different character or disabled entirely.

A more complex example would be how Ctrl-C works through an interactive SSH session. 
Interactive SSH sessions allocate a pty on the server side. 
The client side pty is set to raw mode, meaning that the client side kernel will not translate ETX into SIGINT. 
Instead, the client side kernel passes the ETX along to the slave. 
In this case, the ssh client process takes that ETX and passes it along to the server sshd process. 
If the server sshd pty is not in raw mode, then the server's kernel will translate that ETX into 
a SIGINT to its foreground process group. 
This is how Ctrl-C sends SIGINT to the process running on the server instead of killing your client 
side SSH and leaving you hanging.




https://biriukov.dev/docs/fd-pipe-session-terminal/3-process-groups-jobs-and-sessions/

A process group has its process group identificator PGID and a leader who created this group. 
The PID of the group leader is equal to the corresponding PGID

a signal can be sent to all members of a process group by using killpg()

setpgid() 
setpgrp()
man 2 getpgrp()
tcgetpgrp()



Sur la gstion du redimensionnement à la volée :
-----------------------------------------------

https://unix.stackexchange.com/questions/580362/how-are-terminal-information-such-as-window-size-sent-to-a-linux-program

The size of a terminal is kept in kernel-internal structure, and can be queried by the TIOCGWINSZ and set by TIOCSWINSZ ioctls. 
See the ioctl_tty(2) manpage for details.

Each time the window size is set via TIOCSWINSZ (eg. by xterm when its GUI window was resized) 
the kernel will send a SIGWINCH signal to the foreground process group of that terminal.





Sur l'accès concurrentiel au TTY, foreground/background, qui a le droit de read()...
-------------------------------------------------------------------------------------
http://curiousthing.org/sigttin-sigttou-deep-dive-linux

Signaux SIGTTOU et SIGTTIN


*/

