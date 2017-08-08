/**
 * Utility intended for proxying/duplicating/multiplexing single TTY
 * device into multiple PTY devices. Provided backend TTY device and
 * one or more frontend PTY devices are linked together thus whole
 * traffic is mirrored.
 * Original idea and concepts are borrowed from interceptty utility
 * maintained by Chris Wilson and adapted to my needs. Credits for
 * TTY/PTY management code forwarding to him.
 *
 * Edvinas Stunžėnas <edvinas@8devices.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <termios.h>
#include <pty.h>
#include <sys/types.h>
#include <sys/stat.h>

#define TTYNAMSZ	16
#define TTY_BUFF_SIZE	4096
#define TTY_DEVS_MAX	8

#define max(x,y)       ((x) > (y) ? (x) : (y))

enum {
	FAIL_NONE,
	FAIL_USAGE,
	FAIL_BACKEND,
	FAIL_FRONTEND,
	FAIL_OTHER
};

struct ttydevice {
	char td_path[TTYNAMSZ];
	int td_fd;
	struct termios td_origattr;
	int td_pts_fd;
	char td_pts_link[TTYNAMSZ];
};

#if 0
/* Code lended from stty */
/* TODO(edzius): configure TTY baud rate for multi TTY support */
struct speed_map
{
	const char *string;		/* ASCII representation. */
	speed_t speed;		/* Internal form. */
	unsigned long int value;	/* Numeric value. */
};

static struct speed_map const speeds[] =
{
	{"0", B0, 0},
	{"50", B50, 50},
	{"75", B75, 75},
	{"110", B110, 110},
	{"134", B134, 134},
	{"134.5", B134, 134},
	{"150", B150, 150},
	{"200", B200, 200},
	{"300", B300, 300},
	{"600", B600, 600},
	{"1200", B1200, 1200},
	{"1800", B1800, 1800},
	{"2400", B2400, 2400},
	{"4800", B4800, 4800},
	{"9600", B9600, 9600},
	{"19200", B19200, 19200},
	{"38400", B38400, 38400},
	{"exta", B19200, 19200},
	{"extb", B38400, 38400},
	{"57600", B57600, 57600},
	{"115200", B115200, 115200},
	{"230400", B230400, 230400},
	{"460800", B460800, 460800},
	{"500000", B500000, 500000},
	{"576000", B576000, 576000},
	{"921600", B921600, 921600},
	{"1000000", B1000000, 1000000},
	{"1152000", B1152000, 1152000},
	{"1500000", B1500000, 1500000},
	{"2000000", B2000000, 2000000},
	{"2500000", B2500000, 2500000},
	{"3000000", B3000000, 3000000},
	{"3500000", B3500000, 3500000},
	{"4000000", B4000000, 4000000},
	{NULL, 0, 0}
};

static speed_t
string_to_baud (const char *arg)
{
	int i;

	for (i = 0; speeds[i].string != NULL; ++i)
		if (STREQ (arg, speeds[i].string))
			return speeds[i].speed;
	return (speed_t) -1;
}
#endif

static int verbose = 0;
static int quit = 0;

static void sigdeath(int sig)
{
	quit = 1;
}

static void warn(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fflush(stderr);
}

static void die(int code, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fflush(stderr);
	exit(code);
}

static ssize_t xread(int fd, void *buf, size_t count)
{
	int nread;

	do {
		nread = read(fd, buf, count);
	} while (nread < 0 && errno == EINTR);

	if (nread < 0 && errno != EINTR && errno != EAGAIN) {
		fprintf(stderr, "read(): %s\n", strerror(errno));
	}

	return nread;
}

static ssize_t xwrite(int fd, const void *buff, size_t size)
{
	ssize_t nbytes = 0;

	while (size > 0) {
		ssize_t n;
		do {
			n = write(fd, buff, size);
		} while (n < 0 && errno == EINTR);

		if (n < 0) {
			fprintf(stderr, "write(): %s\n", strerror(errno));
			return -1;
		} else if (n == 0) {
			fprintf(stderr, "huh? out-of-space ?\n");
			break;
		} else {
			buff += n;
			nbytes += n;
			size -= n;
		}
	}

	return nbytes;
}

static int tty_set_raw(int fd)
{
	struct termios tty_state;

	if (tcgetattr(fd, &tty_state) < 0)
		return -1;

	tty_state.c_lflag &= ~(ICANON | IEXTEN | ISIG | ECHO);
	tty_state.c_iflag &= ~(ICRNL | INPCK | ISTRIP | IXON | BRKINT);
	tty_state.c_oflag &= ~OPOST;
	tty_state.c_cflag |= CS8;

	tty_state.c_cc[VMIN]  = 1;
	tty_state.c_cc[VTIME] = 0;

	if (tcsetattr(fd, TCSAFLUSH, &tty_state) < 0)
		return -1;

	return 0;
}

static int tty_set_speed(int fd)
{
	struct termios tp;

	if (tcgetattr(fd, &tp) < 0)
		return -1;

	cfsetispeed(&tp, B115200);
	cfsetospeed(&tp, B115200);

	if (tcsetattr(fd, TCSAFLUSH, &tp) < 0)
		return -1;

	return 0;
}

static void hexdump(char *ttyname, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n",len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
	    printf ("%-16s", ttyname);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}

static void setup_back_tty(struct ttydevice *td, const char *ttyfile)
{
	/* Open the serial port */
	td->td_fd = open(ttyfile, O_RDWR | O_NOCTTY | O_SYNC);
	if (td->td_fd < 0)
		die(FAIL_BACKEND, "open(%s) failed: %s\n", ttyfile, strerror(errno));

	/* Capture current settings to restore them on exti */
	if (tcgetattr(td->td_fd, &td->td_origattr))
		die(FAIL_BACKEND, "tcgetattr(%s) failed: %s\n", ttyfile, strerror(errno));

	/* Update TTY mode settings */
	if (tty_set_raw(td->td_fd))
		die(FAIL_BACKEND, "Failed setup TTY '%s' RAW mode\n", td->td_path);
	if (tty_set_speed(td->td_fd))
		die(FAIL_BACKEND, "Failed setup TTY '%s' baud rate\n", td->td_path);

	/* Extra copy tty device file name, for debugging */
	strncpy(td->td_path, ttyfile, TTYNAMSZ);
}

static void setup_front_tty(struct ttydevice *td, const char *ttyfile, const struct stat *ttyst)
{
	struct stat ptsst;
	int ptsfd;

	/*
	 * PTS tty FD is not required, we we don't ever plan to read
	 * or write any data, so we needn't remember it.
	 */

	if (openpty(&td->td_fd, &ptsfd, NULL, NULL, NULL) < 0)
		die(FAIL_FRONTEND, "openpty() failed: %s\n", strerror(errno));

	if (ttyname_r(ptsfd, td->td_path, TTYNAMSZ))
		die(FAIL_FRONTEND, "ttyname() failed: %s\n", strerror(errno));

	if (tty_set_raw(ptsfd))
		die(FAIL_FRONTEND, "Failed setup TTY '%s' RAW mode\n", td->td_path);

	/* Now set permissions, owners, etc. */
	if (stat(td->td_path, &ptsst) < 0)
		die(FAIL_FRONTEND, "stat(%s) failed: %s\n",
		    td->td_path, strerror(errno));

	if (chown(td->td_path, ttyst->st_uid, ttyst->st_gid) < 0)
		warn("chown() '%s' failed: %s\n", td->td_path, strerror(errno));
	if (chmod(td->td_path, ttyst->st_mode & 07777) < 0)
		warn("chmod() '%s' failed: %s\n", td->td_path, strerror(errno));

	/* Make user requested symlink */
	unlink(ttyfile);
	if (!symlink(td->td_path, ttyfile)) {
		strncpy(td->td_pts_link, ttyfile, TTYNAMSZ);
	} else {
		warn("symlink() '%s' -> '%s' failed: %s\n", td->td_pts_link, ttyfile, strerror(errno));
	}
}

static void usage(char *name)
{
	fprintf(stderr, "Usage: %s back-device front-device [front-device2 ...]\n", name);
	exit(FAIL_USAGE);
}

struct ttypxy {
	struct ttydevice backdev;
	struct ttydevice *frontdevs;
	int frontdev_cnt;
};

static void ttypxy_init(struct ttypxy *ctx, int argc, char *argv[])
{
	int i, c, showhelp = 0;
	struct stat backdev_st;
	struct sigaction sigact;
	sigset_t sigmask;

	/* Process options */
	while ((c = getopt(argc, argv, "hv")) != EOF)
		switch (c) {
		case 'v':
			verbose = 1;
			break;
		case 'h':
		case '?':
		default:
			showhelp = 1;
			break;
		}

	ctx->frontdev_cnt = argc - optind - 1;
	if (showhelp || (ctx->frontdev_cnt < 2))
		usage(argv[0]);

	/* Prepare back TTY */
	setup_back_tty(&ctx->backdev, argv[optind]);
	optind++;
	if (stat(ctx->backdev.td_path, &backdev_st))
		die(FAIL_OTHER, "stat(%s) failed (wuh!?): %s\n", ctx->backdev.td_path, strerror(errno));

	/* Prepare front TTYs */
	ctx->frontdevs = calloc(ctx->frontdev_cnt, sizeof(*ctx->frontdevs));
	if (!ctx->frontdevs)
		die(FAIL_OTHER, "calloc() failed: %s\n", strerror(errno));

	for (i = 0; i < ctx->frontdev_cnt; i++)
		setup_front_tty(&ctx->frontdevs[i], argv[optind+i], &backdev_st);

	if (chroot("/"))
		warn("chroot() failed: %s\n", strerror(errno));

	sigemptyset(&sigmask);
	memset(&sigact, 0, sizeof(sigact));
	sigact.sa_handler = sigdeath;
	sigact.sa_mask = sigmask;

	sigaction(SIGHUP,&sigact,NULL);
	sigaction(SIGINT,&sigact,NULL);
	sigaction(SIGQUIT,&sigact,NULL);
	sigaction(SIGPIPE,&sigact,NULL);
	sigaction(SIGTERM,&sigact,NULL);
}

static void ttypxy_shutdown(struct ttypxy *ctx)
{
	int i;

	for (i = 0; i < ctx->frontdev_cnt; i++)
		unlink(ctx->frontdevs[i].td_pts_link);
	free(ctx->frontdevs);
	tcsetattr(ctx->backdev.td_fd, TCSAFLUSH, &ctx->backdev.td_origattr);
}

static void ttypxy_run(struct ttypxy *ctx)
{
	int i;
	char buffer[TTY_BUFF_SIZE];

	while (!quit) {
		int rv, n = 0;
		int maxfd = 0;
		fd_set rfds;

		FD_ZERO (&rfds);

		FD_SET (ctx->backdev.td_fd, &rfds);
		maxfd = max(maxfd, ctx->backdev.td_fd);

		for (i = 0; i < ctx->frontdev_cnt; i++) {
			FD_SET(ctx->frontdevs[i].td_fd, &rfds);
			maxfd = max(maxfd, ctx->frontdevs[i].td_fd);
		}

		rv = select(maxfd + 1, &rfds, NULL, NULL, NULL);
		if (rv < 0) {
			if (errno == EINTR)
				continue;
			warn("select() failed: %s\n", strerror(errno));
			break;
		}

		if (rv == 0)
			continue;

		if (FD_ISSET(ctx->backdev.td_fd, &rfds)) {
			n = xread(ctx->backdev.td_fd, buffer, sizeof(buffer));
			if (n <= 0)
				break;

			if (verbose)
				hexdump(ctx->backdev.td_path, buffer, n);
		}

		for (i = 0; i < ctx->frontdev_cnt; i++) {
			if (n > 0)
				if (xwrite(ctx->frontdevs[i].td_fd, buffer, n) != n)
					warn("write(%s) front TTY failed: %s\n",
					     ctx->frontdevs[i].td_pts_link,
					     strerror(errno));

			if (FD_ISSET(ctx->frontdevs[i].td_fd, &rfds)) {
				n = xread(ctx->frontdevs[i].td_fd, buffer, sizeof(buffer));
				if (n <= 0)
					continue;

				if (xwrite(ctx->backdev.td_fd, buffer, n) != n)
					warn("write(%s) back TTY failed: %s\n",
					     ctx->backdev.td_path,
					     strerror(errno));

				if (verbose)
					hexdump(ctx->frontdevs[i].td_pts_link, buffer, n);
			}
		}
	}
}

int main (int argc, char *argv[])
{
	struct ttypxy ctx;

	memset(&ctx, 0, sizeof(ctx));
	ttypxy_init(&ctx, argc, argv);
	ttypxy_run(&ctx);
	ttypxy_shutdown(&ctx);

	return 0;
}
