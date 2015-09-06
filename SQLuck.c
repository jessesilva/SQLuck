
/*
** SQLuck - Ferramenta utilizada para encontrar sites vulneráveis a SQL Injection.
** Autor: Constantine - https://github.com/jessesilva
** P0cL4bs Team - https://github.com/P0cL4bs
** Data: 04/09/2015.
** Compilar: gcc --std=c99 -lpthread sqluck.c -o sqluck ; ./sqluck
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define WARNINGS \
	"mysql_num_rows", "mysql_fetch_array", \
	"SQL syntax error", "ODBC SQL Server Driver", \
	"mysql_fetch_assoc", "Warning: ", \
	"mysql_result", "mysql_query", \
	"array_merge", "preg_match", \
	"SQL Syntax", "mysql_numrows", \
	"mysql_preg_match"

#define say printf
#define die(STR,ERROR) {printf(STR);exit(ERROR);}
#define MAX 256
#ifndef TRUE
#define TRUE 0
#endif
#ifndef FALSE
#define FALSE 1
#endif

typedef struct {
	char *input;
	char *output;
	int threads;
} instance_t;

typedef struct {
	int index;
	char *url;
} param_t;

typedef struct {
	unsigned int status;
	unsigned int length;
	unsigned char *content;
} http_request_t;

typedef struct {
	unsigned int port;
	unsigned int length;
	unsigned char *content;
	unsigned char *domain;
	unsigned char *path;
} url_t;

instance_t *instance;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static url_t *http_request_parse_url(const unsigned char *url);
static http_request_t *http_request_free(http_request_t *request);
static http_request_t *http_get_request(const unsigned char *url);
static void *scanner (void *tparam);
static void core (void);
static void save_vuln_link (const char *link);
static void show_banner(void);

int main (int argc, char **argv) {
	if (argc != 4) {
		show_banner();
		say(" Use...\n  %s list-of-links.txt output-file.txt number-of-threads\n\n", argv[0]);
	}
	else {
		if (!(instance = (instance_t *) malloc(sizeof(instance_t))))
			die("Error to alloc memory.\n", 1)
		if (!(instance->input = (char *) malloc(sizeof(char)*strlen(argv[1])+1)))
			die("Error to alloc memory.\n", 1)
		memset(instance->input, '\0', sizeof(char)*strlen(argv[1])+1);
		memcpy(instance->input, argv[1], strlen(argv[1]));
		if (!(instance->output = (char *) malloc(sizeof(char)*strlen(argv[2])+1)))
			die("Error to alloc memory.\n", 1)
		memset(instance->output, '\0', sizeof(char)*strlen(argv[2])+1);
		memcpy(instance->output, argv[2], strlen(argv[2]));
		instance->threads = atoi(argv[3]);
		if (!instance->input || !instance->output || !instance->threads) 
			die("Invalid value.\n", 0)
		else {
			show_banner();
			core();
		}
	}
	return (0);
}

static void *scanner (void *tparam) {
	param_t *param = (param_t *) tparam;
	if (!param) return (NULL);
	if (!param->url) return (NULL);
	say(" [%d] -> %s\n", param->index, param->url);
	http_request_t *request = http_get_request(param->url);
	if (request != NULL) {
		if (request->status == TRUE)
			if (request->content) {
				char *sql_injection_warning_list [] = { WARNINGS, NULL };
				for (int i=0; sql_injection_warning_list[i]!=NULL; i++) {
					if (strstr(request->content, sql_injection_warning_list[i])) {
						pthread_mutex_lock(&mutex);
						save_vuln_link(param->url);
						pthread_mutex_unlock(&mutex);
						break;
					}
				}
			}
		http_request_free(request);
	}
}

static void save_vuln_link (const char *link) {
	FILE *fp = NULL;
	if (!(fp = fopen(instance->output, "a+")))
		die("Erro to open output file.\n", 1);
	fprintf(fp, "%s\n", link);
	fclose(fp);
}

static void core (void) {
	FILE *fp = NULL;
	char line [MAX+1];
	pthread_t **thread;
	int counter = 0, result = 0;
	if (!(fp = fopen(instance->input, "r")))
		die("Input file not exists.\n", 0);
	if (!(thread = (pthread_t **) malloc((sizeof(pthread_t)*instance->threads)+1)))
			die("Error to alloc thread memory.\n", 1)
	if (pthread_mutex_init(&mutex, NULL) != 0)
		die("Error to initialize mutex.\n", 1)
	say("\n Started...\n\n");
	while (1) {
		for (int i=0; i<instance->threads; i++) {
			memset(line, '\0', MAX+1);
			result = fgets(line, MAX, fp);
			if (!result) break;
			for (int a=0; line[a]!='\0'; a++)
				if (line[a] == '\n')
					line[a] = '\0';
			param_t *param;
			if (!(param = (param_t *) malloc(sizeof(param_t))))
				die("Erro to alloc memory.\n", 1);
			if (!(param->url = (char *) malloc((sizeof(char)*strlen(line))+1)))
				die("Erro to alloc memory.\n", 1);
			memset(param->url, '\0', (sizeof(char)*strlen(line))+1);
			memcpy(param->url, line, strlen(line));
			param->index = counter++;
			pthread_create(&thread[i], NULL, &scanner, (void *)param);
		}
		if (!result) break;
		for (int i=0; i<instance->threads; i++)
			pthread_join(thread[i], NULL);
	}
	fclose(fp);
	say("\n Finished.\n\n");
	pthread_exit(NULL);
	pthread_mutex_destroy(&mutex);
}

static url_t *http_request_parse_url(const unsigned char *url) {
	if (!url) return (url_t *) NULL;
	
	url_t *new_url = (url_t *) malloc(sizeof(url_t));
	if (!new_url) 
		return (url_t *) NULL;
	
	new_url->port = 80;
	new_url->length = 0;
	new_url->content = NULL;
	new_url->domain = NULL;
	new_url->path = NULL;
	
	if (!(new_url->content = (unsigned char *) malloc(strlen(url) + 1))) {
		free(new_url);
		return (url_t *) NULL;
	}
	
	memset(new_url->content, '\0', strlen(url) + 1);
	memcpy(new_url->content, url, strlen(url));
	new_url->length = strlen(new_url->content);
	
	if (!new_url->length > 0 || !strlen(new_url->content) > 0) {
		if (new_url->content != NULL) 
			free(new_url->content);
		free(new_url);
		return (url_t *) NULL;
	}
	
	unsigned int start_pointer = 0;
	unsigned char *u_ptr = new_url->content;
	if (strstr(u_ptr, "://")) {
		if (!(u_ptr[0] == 'h' && u_ptr[1] == 't' && u_ptr[2] == 't' && u_ptr[3] == 'p' && 
			  u_ptr[4] == ':' && u_ptr[5] == '/' && u_ptr[6] == '/')) {
			free(new_url->content);
			free(new_url);
			return (url_t *) NULL;
		} else 
			start_pointer = strlen("http://");
	}
	
	u_ptr += start_pointer;
	unsigned int counter = 0;
	unsigned char *c_port = NULL;
	unsigned char *p_ptr = NULL;
	if ((p_ptr = strstr(u_ptr, ":")) != NULL && ++p_ptr) {
		if ((c_port = (unsigned char *) malloc(sizeof(unsigned char) * 10)) != NULL) {
			for (int a=0; p_ptr[a]!='\0'; a++) {
				counter = 0;
				for (int b='0'; b<='9' ; b++)
					if (p_ptr[a] == b)
						counter++;
				if (!counter > 0) {
					c_port[a] = '\0';
					break;
				}
				c_port[a] = p_ptr[a];
			}
			if (c_port != NULL)
				new_url->port = (int) strtol(c_port, NULL, 10);
			free(c_port);
		}
	}
	
	if (new_url->port == 0)
		new_url->port = 80;
	
	if (!new_url->port > 0) {
		if (c_port)
			free(c_port);
		if (new_url->content != NULL) 
			free(new_url->content);
		free(new_url);
		return (url_t *) NULL;
	}
	
	unsigned char *c_domain = NULL;
	if ((c_domain = (unsigned char *) malloc(sizeof(unsigned char) * (256*2))) != NULL) {
		memset(c_domain, '\0', sizeof(unsigned char) * (256*2));
		for (int d=0; d<256; d++) {
			counter = 0;
			for (int a='a',b='A',c='0'; a<='z'; a++,b++) {
				if (u_ptr[d] == a || u_ptr[d] == b || u_ptr[d] == c || 
					u_ptr[d] == '.' || u_ptr[d] == '-')
					counter++;
				if (c <= '9')
					b++;
			}
			if (counter == 0) {
				c_domain[d] = '\0';
				if ((new_url->domain = (unsigned char *) malloc(sizeof(unsigned char) * (d + 1))) != NULL) {
					memset(new_url->domain, '\0', sizeof(unsigned char) * (d + 1));
					memcpy(new_url->domain, c_domain, d);
				}
				break;
			}
			c_domain[d] = u_ptr[d];
		}
		free(c_domain);
	}
	
	if (new_url->domain == NULL) {
		if (c_domain)
			free(c_domain);
		if (c_port)
			free(c_port);
		if (new_url->content != NULL) 
			free(new_url->content);
		free(new_url);
		return (url_t *) NULL;
	}
	
	unsigned char *c_path = NULL;
	if ((c_path = (unsigned char *) malloc( sizeof(unsigned char) * (new_url->length + (256*2)) )) != NULL) {
		memset(c_path, '\0', sizeof(unsigned char) * (new_url->length + (256*2)));
		counter = 0;
		for (int a=0; u_ptr[a]!='\0'; a++) {
			if (u_ptr[a] == '/') {
				counter++;
				break;
			}
		}
		if (counter > 0) {
			unsigned char *p_ptr = strstr(u_ptr, "/");
			if (p_ptr != NULL) {
				unsigned int a = 0;
				for (; p_ptr[a]!='\0'; a++)
					c_path[a] = p_ptr[a];
				if ((new_url->path = (unsigned char *) malloc(sizeof(unsigned char) * (a + 1))) != NULL) {
					memset(new_url->path, '\0', sizeof(unsigned char) * (a + 1));
					memcpy(new_url->path, c_path, a);
				}
			}
		} else {
			unsigned char bar [] = "/";
			if ((new_url->path = (unsigned char *) malloc(sizeof(unsigned char) * (strlen(bar) + 1))) != NULL) {
				memset(new_url->path, '\0', sizeof(unsigned char) * (strlen(bar) + 1));
				memcpy(new_url->path, bar, strlen(bar));
			}
		}
		free(c_path);
	}
	
	if (new_url->path == NULL) {
		if (c_path)
			free(c_path);
		if (c_domain)
			free(c_domain);
		if (c_port)
			free(c_port);
		if (new_url->content != NULL) 
			free(new_url->content);
		free(new_url);
		return (url_t *) NULL;
	}
	
	if (new_url != NULL)
		return new_url;
	
	return (url_t *) NULL;
}

#define FREE_URL_FORMATED \
	url_formated->port = 0;\
	url_formated->length = 0;\
	if (url_formated->content != NULL)\
		url_formated->content = NULL;\
	if (url_formated->domain != NULL)\
		url_formated->domain = NULL;\
	if (url_formated->path != NULL)\
		url_formated->path = NULL
static http_request_t *http_get_request(const unsigned char *url) {
	if (!url) return (http_request_t *) NULL;
	
	url_t *url_formated = http_request_parse_url(url);
	if (url_formated == NULL) 
		return (http_request_t *) NULL;
	
	struct hostent *host_information = gethostbyname(url_formated->domain);
	if (host_information == NULL) {
		FREE_URL_FORMATED;
		return (http_request_t *) NULL;
	}
	
	struct sockaddr_in address;
	address.sin_family      = AF_INET;
	address.sin_port        = htons(url_formated->port);
	address.sin_addr.s_addr = *(unsigned long *) host_information->h_addr_list[0];
	
	int sock = (int)(-1);
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		FREE_URL_FORMATED;
		return (http_request_t *) NULL;
	}
	
	const struct timeval timeout = { .tv_sec=3, .tv_usec=0};
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
	
	int result = (int)(-1);
	if ((result = connect(sock, (struct sockaddr *)&address, sizeof(address))) < 0) {
		FREE_URL_FORMATED;
		close(sock);
		return (http_request_t *) NULL;
	}
	
	unsigned char *header = NULL;
	if (!(header = (unsigned char *) malloc(sizeof(unsigned char) * ((256*5) + strlen(url) + 1)))) {
		FREE_URL_FORMATED;
		close(sock);
		return (http_request_t *) NULL;
	}
	memset(header, '\0', sizeof(unsigned char) * ((256*5) + strlen(url) + 1));
	sprintf(header, 
		"GET %s' HTTP/1.1\r\n"
		"Host: %s\r\n"
		"Connection: close\r\n\r\n", url_formated->path, url_formated->domain);
	
	if (send(sock, header, strlen(header), 0) == -1) {
		FREE_URL_FORMATED;
		free(header);
		close(sock);
		return (http_request_t *) NULL;
	}
	
	result = 0;
	unsigned int is_going = 1;
	unsigned int total_length = 0;
	unsigned char *response = (unsigned char *) malloc(sizeof(unsigned char) * (256*2));
	unsigned char *response_final = (unsigned char *) malloc(sizeof(unsigned char) * (256*2));
	
	if (!response || !response_final) {
		FREE_URL_FORMATED;
		free(header);
		if (response)
			free(response);
		if (response_final)
			free(response_final);
		close(sock);
		return (http_request_t *) NULL;
	}
	
	memset(response, '\0', sizeof(unsigned char) * (256*2));
	memset(response_final, '\0', sizeof(unsigned char) * (256*2));
	
	while (is_going) {
		result = recv(sock, response, (sizeof(unsigned char) * (256*2)) - 1, 0);
		if (result == 0 || result < 0)
			is_going = 0;
		else {
			if ((response_final = (unsigned char *) realloc(response_final, total_length + 
				(sizeof(unsigned char) * (256*2)))) != NULL) {
				memcpy(&response_final[total_length], response, result);
				total_length += result;
			}
		}
	}
	
	unsigned int result_flag = FALSE;
	http_request_t *request = (http_request_t *) malloc(sizeof(http_request_t));
	if (request != NULL) {
		memset(request, 0, sizeof(http_request_t));
		request->status = FALSE;
		request->length = 0;
		request->content = NULL;
		
		if (total_length > 0) {
			request->length = total_length;
			if ((request->content = (unsigned char *) malloc(sizeof(unsigned char) * (request->length+1))) != NULL) {
				memset(request->content, '\0', sizeof(unsigned char) * (request->length+1));
				memcpy(request->content, response_final, request->length);
				request->status = TRUE;
				result_flag = TRUE;
			}
		}
	}
	
	close(sock);
	free(header);
	free(response);
	free(response_final);
	
	url_formated->port = 0;
	url_formated->length = 0;
	if (url_formated->content)
		free(url_formated->content);
	if (url_formated->domain)
		free(url_formated->domain);
	if (url_formated->path)
		free(url_formated->path);
	free(url_formated);
	
	if (result_flag == TRUE)
		return request;
	else {
		if (request != NULL)
			free(request);
	}
	
	return (http_request_t *) NULL;
}

static http_request_t *http_request_free(http_request_t *request) {
	if (!request) return (http_request_t *) NULL;
	
	request->length = 0;
	request->status = FALSE;
	free(request->content);
	free(request);
	
	return (http_request_t *) NULL;
}

static void show_banner(void) {
say ("\n\
   ____    _____   __                      __         \n\
  /\\  _`\\ /\\  __`\\/\\ \\                    /\\ \\     v1.0\n\
  \\ \\,\\L\\_\\ \\ \\/\\ \\ \\ \\      __  __    ___\\ \\ \\/'\\    \n\
   \\/_\\__ \\\\ \\ \\ \\ \\ \\ \\  __/\\ \\/\\ \\  /'___\\ \\ , <    \n\
     /\\ \\L\\ \\ \\ \\\\'\\\\ \\ \\L\\ \\ \\ \\_\\ \\/\\ \\__/\\ \\ \\\\`\\  \n\
     \\ `\\____\\ \\___\\_\\ \\____/\\ \\____/\\ \\____\\\\ \\_\\ \\_\\\n\
      \\/_____/\\/__//_/\\/___/  \\/___/  \\/____/ \\/_/\\/_/\n\
                                                      \n\
                     C0d3d by C0nsT4nt1n3\n\
                    Gr3aTz f0r Und3rgr0Und\n\n");
}
