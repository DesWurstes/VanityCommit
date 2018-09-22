#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <pthread.h>
#include <string.h>
#include <time.h>

#ifdef _MSC_VER
#	include <windows.h>
#	define popen(a, b) _popen(a, b)
#	define pclose(a, b) _pclose(a, b)
#	define setenv(a, b, c) _putenv_s(a, b)
#	define likely(exp) exp
#	define unlikely(exp) exp
#else
#	define likely(exp) __builtin_expect((exp), 1)
#	define unlikely(exp) __builtin_expect((exp), 0)
#endif

#include "sha1.c"

typedef int (*test_func_t)(
	const unsigned char *, const unsigned char *, int, char);

static pthread_mutex_t solution_being_sent_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t solution_being_read_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t solution_fully_sent_cond = PTHREAD_COND_INITIALIZER;

static void *thread(void *ptr);

typedef struct {
	char author_timestamp[10];
	char committer_timestamp[10];
	char calculated_hash[20];
} solution_t;

typedef struct {
	test_func_t prefix_func;
	const char *prefix;
	int prefix_len;
	char last_char;
	const SHA1_CTX *precalc;
	const char *commit_continue;
	int commit_continue_length;
	int author_timestamp_offset;
	int committer_timestamp_offset;
	solution_t *solution_output;
	int *is_solved;
	int thread_count;
	int delta;
} common_knowledge_t;

typedef struct {
	const common_knowledge_t* common;
	int thread_id;
} thread_knowledge_t;

inline static char decode_hex_char(char s) {
	switch (s) {
	case '0': return 0;
	case '1': return 1;
	case '2': return 2;
	case '3': return 3;
	case '4': return 4;
	case '5': return 5;
	case '6': return 6;
	case '7': return 7;
	case '8': return 8;
	case '9': return 9;
	case 'a': return 10;
	case 'b': return 11;
	case 'c': return 12;
	case 'd': return 13;
	case 'e': return 14;
	case 'f': return 15;
	default: return -1;
	}
}

static int decode_hex(const char *hex, unsigned char *output, int hex_len) {
	for (int i = 0; i + 1 < hex_len; i += 2) {
		char a = decode_hex_char(hex[i]);
		char b = decode_hex_char(hex[i + 1]);
		if (unlikely(a == -1 || b == -1)) {
			return 1;
		}
		output[i / 2] = a * 16 + b;
	}
	return 0;
}

static int prefix_test(const unsigned char *hash, const unsigned char *prefix,
	int prefix_len, char last) {
	(void) last;
	for (int i = 0; i < prefix_len; i++) {
		if (likely(hash[i] != prefix[i])) {
			return 0;
		}
	}
	return 1;
}

static int prefix_half_test(const unsigned char *hash,
	const unsigned char *prefix, int prefix_len, char last) {
	for (int i = 0; i < prefix_len; i++) {
		if (likely(hash[i] != prefix[i])) {
			return 0;
		}
	}
	if (likely((hash[prefix_len] / 16) != (unsigned char) last)) return 0;
	return 1;
}

static void get_current_hash(unsigned char hash[20]) {
	unsigned char temp[128];
	FILE *fp = popen("git rev-parse HEAD", "r");
	fgets((char *) temp, 80, fp);
	if (unlikely(decode_hex((const char *) temp, hash, 40) == 1))
		fprintf(stderr, "Git error: %s\n", temp);
	pclose(fp);
}

static int get_commit_data(char output[1024]) {
	FILE *fp;
	int commit_len;
	if (unlikely((fp = popen("git cat-file -p HEAD", "r")) == NULL ||
		    !(commit_len = fread(output, 1, 999, fp)))) {
		fprintf(stderr, "Unable to run commands!\n");
		return 1;
	}
	pclose(fp);
	if (unlikely(commit_len > 990)) {
		fprintf(stderr, "Commit message too long!\n");
		return 1;
	}
	output[commit_len] = 0;
	return 0;
}

static int check_timezone(const char timezone[5]) {
	if (unlikely(timezone[0] != '+' && timezone[0] != '-')) {
		fprintf(stderr,
			"First character of the timezone must be '+' or '-'\n");
		return 1;
	}
	for (int i = 1; i < 5; i++) {
		if (unlikely(!('0' <= timezone[i] && timezone[i] <= '9'))) {
			fprintf(stderr, "Timezone must be numerical!\n");
			return 1;
		}
	}
	if (unlikely(timezone[1] == '2' && timezone[2] >= '4')) {
		// Actually, it can be equal. Just for simplicity.
		fprintf(stderr,
			"Numerical part of timezone can't be equal to or bigger than 2400\n");
		return 1;
	}
	return 0;
}

static void epoch_to_date(const char epoch_str[10], char date[32]) {
	char tmp_epoch_str[11];
	strncpy(tmp_epoch_str, epoch_str, 10);
	time_t epoch = strtol(tmp_epoch_str, NULL, 10);
	strftime(date, 32, "%c", localtime (&epoch));
}

static int get_threads() {
	int threads;
#ifdef _WIN32
	{
		SYSTEM_INFO sysinfo;
		GetSystemInfo(&sysinfo);
		threads = sysinfo.dwNumberOfProcessors;
	}
#else
	threads = sysconf(_SC_NPROCESSORS_ONLN);
#endif
	if (unlikely(threads == -1)) {
		fprintf(stderr, "Couldn't determine the number of threads\n");
		return 0;
	}
	return threads;
}

// Partially unrolled
static void decrement_string_num(char num[10]) {
	if (likely(num[9] > '0')) {
		num[9]--;
		return;
	}
	if (likely(num[8] > '0')) {
		num[9] = '9';
		num[8]--;
		return;
	}
	if (likely(num[7] > '0')) {
		num[8] = num[9] = '9';
		num[7]--;
		return;
	}
	for (int i = 6; i > 0; i--) {
		if (likely(num[i] > '0')) {
			for (int k = 9; k > i; k--)
				num[k] = '9';
			num[i]--;
			return;
		}
	}
}

static void prepare_env(const char* commit_template, const char *committer_date) {
	// TODO: https://github.com/clickyotomy/vanity-commit/blob/master/commit.py#L217
	// TODO: here
	char commit[999];
	strcpy(commit, commit_template);
	//setenv("GIT_AUTHOR_NAME", committer_date, 1);
	//setenv("GIT_AUTHOR_EMAIL", committer_date, 1);
	// broken: setenv("GIT_AUTHOR_DATE", author_date, 1);
	setenv("GIT_COMMITTER_DATE", committer_date, 1);
	//setenv("GIT_COMMITTER_EMAIL", committer_date, 1);
	//setenv("GIT_COMMITTER_NAME", committer_date, 1);
}

int main(int argc, char **argv) {
	int threads;
	char *prefix = argv[1];
	int prefix_len = 0;
	test_func_t prefix_check;
	char last;
	char commit_data[999];
	char *end_of_first_mail_space;
	SHA1_CTX precalc;
	int is_solved = 0;

	if (unlikely(argc != 2 && argc != 3)) {
		fprintf(stderr, "Usage: %s <hex prefix> [<timezone +0100>]\n",
			argv[0]);
		return 1;
	}
	if (!(threads = get_threads())) return 1;

	// For the main thread + search thread
	threads -= 2;
	if (likely(threads > 4)) threads -= 1;
	if (unlikely(threads > 7)) threads -= 1;
	if (unlikely(threads <= 0)) threads = 1;
	while ((unsigned char) (prefix[prefix_len]) > 32) {
		prefix_len++;
	}
	unsigned char prefix_bytes[prefix_len / 2];
	if (unlikely(decode_hex(prefix, prefix_bytes, prefix_len) == 1)) {
	no_hex:
		fprintf(stderr,
			"Prefix contains a character that is not lowercase hex: %s\n",
			prefix);
		return 1;
	}
	if (unlikely(prefix_len > 20)) {
		fprintf(stderr, "Impractical prefix length!\n");
		return 1;
	}
	if (likely(prefix_len % 2)) {
		prefix_check = prefix_half_test;
		last = decode_hex_char(prefix[prefix_len - 1]);
		if (unlikely(last == -1)) {
			goto no_hex;
		}
	} else {
		prefix_check = prefix_test;
		last = 0;
	}
	if (unlikely(get_commit_data(commit_data) == 1)) return 1;
	// ......ga.com> 1413579916 -0700
	//  The space after '>'
	end_of_first_mail_space = strchr((char *) commit_data, '>') + 1;
	SHA1_NEW(&precalc);
	// multiple of 64, size of a chunk
	const int precalc_chars =
		(end_of_first_mail_space - (char *) commit_data) &
		~((1 << 6) - 1);
	char precalc_buf[precalc_chars];
	memcpy(precalc_buf, "commit ", 7);
	sprintf(&precalc_buf[7], "%ld", strlen(commit_data));
	precalc_buf[10] = 0;
	memcpy(&precalc_buf[11], commit_data, precalc_chars - 11);
	SHA1_WRITE(
		&precalc, (const unsigned char *) precalc_buf, precalc_chars);
	char *first_byte_after_precalc = commit_data + precalc_chars - 11;
	char *end_of_second_mail_space = strchr(end_of_first_mail_space + 26, '>') + 1;

	solution_t solution_output;
	const common_knowledge_t common = {.prefix_func = prefix_check,
		.prefix = (const char *) prefix_bytes,
		.prefix_len = prefix_len / 2,
		.last_char = last,
		.precalc = &precalc,
		.commit_continue = &commit_data[precalc_chars - 11],
		.commit_continue_length = strlen(&commit_data[precalc_chars - 11]),
		.author_timestamp_offset =
			end_of_first_mail_space + 1 - first_byte_after_precalc,
		.committer_timestamp_offset =
			end_of_second_mail_space + 1 - first_byte_after_precalc,
		.solution_output = &solution_output,
		.is_solved = &is_solved,
		// TODO: tune
		.delta = 1 << (4 * prefix_len) / (threads + 1) << 6,
		.thread_count = threads};
	puts("Starting...");
	if (argc == 3) {
		if (unlikely(check_timezone(argv[2]) == 1)) return 1;
		memcpy(end_of_first_mail_space + 12, argv[2], 5);
		memcpy(end_of_second_mail_space + 12, argv[2], 5);
	}
	thread_knowledge_t thread_data[threads];
	for (int i = 0; i < threads; i++) {
		thread_data[i].common = &common;
		thread_data[i].thread_id = i;
	}
	pthread_mutex_init(&solution_being_sent_lock, NULL);
	pthread_mutex_init(&solution_being_read_lock, NULL);
	pthread_cond_init(&solution_fully_sent_cond, NULL);

	pthread_t pthreads[threads];
	for (int i = 0; i < threads; i++)
		pthread_create(&pthreads[i], NULL, thread, (void *) &thread_data[i]);

	pthread_mutex_lock(&solution_being_read_lock);

	pthread_cond_wait(&solution_fully_sent_cond,
		&solution_being_read_lock);

	printf("A solution has been found. Waiting for threads to terminate.\n");
	for (int i = 0; i < threads; i++)
		pthread_join(pthreads[i], NULL);

	char temporary_date[32];
	epoch_to_date(solution_output.author_timestamp, temporary_date);
	printf("Author date: %s\n", temporary_date);
	epoch_to_date(solution_output.committer_timestamp, temporary_date);
	printf("Commit date: %s\n", temporary_date);
	printf("Found hash: \x1b[32m%.*s\x1b[0m", prefix_len, prefix);
	if (prefix_len % 2) {
		printf("%x", (unsigned char) (solution_output.calculated_hash[prefix_len / 2]) % 16);
	}
	for (int i = prefix_len / 2 + prefix_len % 2; i < 20; i++) {
		printf("%.2x", (unsigned char) solution_output.calculated_hash[i]);
	}
	printf("\n");
	char prompt;
	if (0) {
		confirm:
		printf("\r");
	}
	printf("Do you want to apply the date changes? Y/n: ");
	prompt = fgetc(stdin);
	if ((prompt | 32) == 'n') {
		return 0;
	} else if ((prompt | 32) != 'y') goto confirm;

	char author_date[17];
	char committer_date[17];

#define date(x, y, z) \
memcpy(x, y, 10); \
	x[10] = ' '; \
	memcpy(x + 11, z + 12, 5); \
	x[16] = 0;

	date(author_date, solution_output.author_timestamp, end_of_first_mail_space)
	date(committer_date, solution_output.committer_timestamp, end_of_second_mail_space);
	prepare_env(commit_data, committer_date);
	char amend_input[64];
	sprintf(amend_input, "git commit --amend --file=- --date=\"%s\"", author_date);
	//FILE *amend = popen("git commit --amend --file=-", "w");
	FILE *amend = popen(amend_input, "w");
	fwrite(end_of_second_mail_space + 19, 1, strlen(end_of_second_mail_space + 19), amend);
	pclose(amend);
	system("git log --pretty=fuller -1 HEAD");

	char final_hash[20];
	get_current_hash((unsigned char *) final_hash);
	if (memcmp(final_hash, solution_output.calculated_hash, 20)) {
		fprintf(stderr, "Calculated hash doesn't match the final hash!!! :(\n");
	}
	return 0;
}

static void *thread(void *ptr) {
	const thread_knowledge_t *const thread = (const thread_knowledge_t *) ptr;
	const common_knowledge_t *const common = thread->common;

	const int thread_id = thread->thread_id;
	const int prefix_len = common->prefix_len;
	char prefix[prefix_len];
	memcpy(prefix, common->prefix, prefix_len);
	const test_func_t prefix_func = common->prefix_func;
	const char last_char = common->last_char;
	const int commit_continue_length = common->commit_continue_length;
	char commit_continue[commit_continue_length];
	memcpy(commit_continue, common->commit_continue, commit_continue_length);
	const int author_timestamp_offset = common->author_timestamp_offset;
	const int committer_timestamp_offset = common->committer_timestamp_offset;
	int *halt = common->is_solved;
	const int thread_count = common->thread_count;
	const int delta = common->delta;
	SHA1_CTX hash;
	SHA1_COPY(&hash, common->precalc);

	// Recall that normally "author_timestamp <= committer_timestamp"
	char *const author_timestamp_loc = commit_continue + author_timestamp_offset;
	char *const committer_timestamp_loc = commit_continue + committer_timestamp_offset;

	for (int i = 0; i < thread_id; i++)
		decrement_string_num(committer_timestamp_loc);
	memcpy(author_timestamp_loc, committer_timestamp_loc, 10);

	SHA1_CTX temp_hash;
	char hash_out[20];
	while (!*halt) {
		for (int i = 0; i < delta; i++) {
			decrement_string_num(author_timestamp_loc);
			SHA1_COPY(&temp_hash, &hash);
			SHA1_WRITE(&temp_hash, (const unsigned char *) commit_continue, commit_continue_length);
			SHA1_FINALIZE(&temp_hash, (unsigned char *) hash_out);
			if (prefix_func((const unsigned char *) hash_out, (const unsigned char *) prefix, prefix_len, last_char)) {
					if (pthread_mutex_trylock(&solution_being_sent_lock) || *halt) return NULL;
					*halt = 1;
					memcpy(common->solution_output->author_timestamp, author_timestamp_loc, 10);
					memcpy(common->solution_output->committer_timestamp, committer_timestamp_loc, 10);
					memcpy(common->solution_output->calculated_hash, hash_out, 20);
					pthread_cond_signal(&solution_fully_sent_cond);
					return NULL;
			}
		}
		for (int i = 0; i < thread_count; i++)
			decrement_string_num(committer_timestamp_loc);
		memcpy(author_timestamp_loc, committer_timestamp_loc, 10);
	}
	return NULL;
}
