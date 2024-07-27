// cmake . -DLWS_WITH_SSL=NO -DLWS_WITH_LIBEV=YES -DLWS_WITH_LIBUV=YES -DLWS_WITH_EVLIB_PLUGINS=OFF [-DLIBEV_INCLUDE_DIRS=libev/include -DLIBUV_INCLUDE_DIRS=libuv/include -DLIBEV_LIBRARIES=libev/lib/libev.* -DLIBUV_LIBRARIES=libuv/lib/libuv.*]
// cc -Ilibwebsockets/include [-Ilibuv/include] ttyd.c libwebsockets.a libev.a libuv.a -o ttyd

#include <errno.h>
#include <libwebsockets.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <uv.h>

#if defined(__OpenBSD__) || defined(__APPLE__)
#include <util.h>
#else
#include <pty.h>
#endif

char gbuf[256];
char *credential = 0;
char socket_path[255] = "";
uv_loop_t loop;
struct lws_context *context = 0;

const char *cwd;
char *args[] = {0, 0};

struct pss_tty;
struct pty_process {
	int pid, exit_code;
	pid_t pty;
	uv_thread_t tid;
	uv_async_t async;
	uv_pipe_t in;
	uv_pipe_t out;
	struct pss_tty *pss;
	int ws_closed;
};

struct pss_tty {
	int initialized;
	int authenticated;
	int receiving;
	struct lws *wsi;
	struct pty_process *process;
	uv_buf_t pty_buf;
	int lws_close_status;
};

void alloc_cb(uv_handle_t *unused, size_t suggested_size, uv_buf_t *buf) {
	char *message = malloc(LWS_PRE + suggested_size);
	buf->base = message + LWS_PRE;
	buf->len = suggested_size;
}

void async_free_cb(uv_handle_t *handle) {
	free(handle -> data);
}

int process_running(struct pty_process *process) {
	return process && process->pid > 0 && uv_kill(process->pid, 0) == 0;
}

void pty_resume(struct pty_process *);
void read_cb(uv_stream_t *stream, ssize_t n, const uv_buf_t *buf) {
	uv_read_stop(stream);
	struct pty_process *process = (struct pty_process *) stream->data;
	if(process->ws_closed) {
		if(buf->base) free(buf->base - LWS_PRE);
		pty_resume(process);
		return;
	}
	if(n > 0) {
		process->pss->pty_buf.base = buf->base;
		process->pss->pty_buf.len = n;
	} else {
		if (n == UV_ENOBUFS || n == 0) return;
		if (!process_running(process))
			process->pss->lws_close_status = process->exit_code == 0 ? 1000 : 1006;
		free(buf->base - LWS_PRE);
	}
	lws_callback_on_writable(process->pss->wsi);
}

void write_cb(uv_write_t *req, int unused) {
	free(req->data);
	free(req);
}

void process_free(struct pty_process *process) {
	if (!process) return;
	close(process->pty);
	uv_thread_join(&process->tid);
	uv_close((uv_handle_t *) &process->in, 0);
	uv_close((uv_handle_t *) &process->out, 0);
}

void pty_resume(struct pty_process *process) {
	process->out.data = process;
	uv_read_start((uv_stream_t *) &process->out, alloc_cb, read_cb);
}

int fd_set_cloexec(const int fd) {
	int flags = fcntl(fd, F_GETFD);
	if (flags < 0) return 0;
	return (flags & FD_CLOEXEC) == 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != -1;
}

int fd_duplicate(int fd, uv_pipe_t *pipe) {
	int fd_dup = dup(fd);
	if (fd_dup < 0) return 0;

	if (!fd_set_cloexec(fd_dup)) return 0;

	int status = uv_pipe_open(pipe, fd_dup);
	if (status) close(fd_dup);
	return status == 0;
}

void wait_cb(void *arg) {
	struct pty_process *process = (struct pty_process *) arg;

	pid_t pid;
	int stat;
	do
		pid = waitpid(process->pid, &stat, 0);
	while (pid != process->pid && errno == EINTR);

	if (WIFEXITED(stat)) {
		process->exit_code = WEXITSTATUS(stat);
	}
	if (WIFSIGNALED(stat)) {
		int sig = WTERMSIG(stat);
		process->exit_code = 128 + sig;
	}

	uv_async_send(&process->async);
}

void async_cb(uv_async_t *async) {
	struct pty_process *process = (struct pty_process *) async->data;
	if (process->ws_closed) {
		lwsl_notice("process killed, pid: %d\n", process->pid);
	} else {
		lwsl_notice("process exited with code %d, pid: %d\n", process->exit_code, process->pid);
		process->pss->process = NULL;
		process->pss->lws_close_status = process->exit_code == 0 ? 1000 : 1006;
		lws_callback_on_writable(process->pss->wsi);
	}

	uv_close((uv_handle_t *) async, async_free_cb);
	process_free(process);
}

int pty_spawn(struct pty_process *process, uint16_t rows, uint16_t cols) {
	int status = 0;

	uv_disable_stdio_inheritance();

	int master, pid;
	struct winsize size = {rows, cols, 0, 0};
	pid = forkpty(&master, NULL, NULL, &size);
	if (pid < 0) {
		return -errno;
	} else if (pid == 0) {
		setsid();
		int ret = execvp(args[0], (char * const *)args);
		if (ret < 0) {
			perror("execvp failed\n");
			_exit(-errno);
		}
	}

	uv_pipe_init(&loop, &process->in, 0);
	uv_pipe_init(&loop, &process->out, 0);

	int flags;
	if((flags = fcntl(master, F_GETFL)) == -1 || fcntl(master, F_SETFL, flags | O_NONBLOCK) == -1 || !fd_set_cloexec(master) || !fd_duplicate(master, &process->in) || !fd_duplicate(master, &process->out)) {
		close(master);
		uv_kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		return -errno;
	}

	process->pty = master;
	process->pid = pid;
	process->async.data = process;
	uv_async_init(&loop, &process->async, async_cb);
	uv_thread_create(&process->tid, wait_cb, process);

	return 0;
}

int spawn_process(struct pss_tty *pss, uint16_t rows, uint16_t cols) {
	struct pty_process *process = malloc(sizeof(struct pty_process));
	memset(process, 0, sizeof(struct pty_process));
	process->pss = pss;
	process->exit_code = -1;

	if (pty_spawn(process, rows, cols) != 0) {
		lwsl_err("pty_spawn: %d (%s)\n", errno, strerror(errno));
		process_free(process);
		return 0;
	}
	lwsl_notice("started process, pid: %d\n", process->pid);
	pss->process = process;
	lws_callback_on_writable(pss->wsi);

	return 1;
}

int callback_tty(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
	struct pss_tty *pss = (struct pss_tty *)user;
	char *buffer = (char *)in;

	switch (reason) {
		case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
			if (credential) {
				size_t n = lws_hdr_copy(wsi, gbuf, sizeof(gbuf), WSI_TOKEN_HTTP_AUTHORIZATION);
				pss->authenticated = (n >= 7 && !strncmp("Basic ", gbuf, 6) && !strcmp(gbuf + 6, credential));
			}
			break;
			
		case LWS_CALLBACK_ESTABLISHED:
			pss->initialized = 0;
			pss->wsi = wsi;
			pss->lws_close_status = LWS_CLOSE_STATUS_NOSTATUS;
			break;

		case LWS_CALLBACK_SERVER_WRITEABLE:
			if (!pss->initialized) {
				pss->initialized = 1;
				if(pss->process) pty_resume(pss->process);
				break;
			}

			if (pss->lws_close_status > LWS_CLOSE_STATUS_NOSTATUS) {
				lws_close_reason(wsi, pss->lws_close_status, NULL, 0);
				return 1;
			}

			if (pss->pty_buf.base) {
				lws_write(wsi, (unsigned char *)pss->pty_buf.base, pss->pty_buf.len, LWS_WRITE_BINARY);
				free(pss->pty_buf.base - LWS_PRE);
				pss->pty_buf.base = NULL;
				if(pss->process) pty_resume(pss->process);
			}
			break;

		case LWS_CALLBACK_RECEIVE:
			if(lws_is_first_fragment(wsi)) {
				if((pss->receiving=(buffer[0]==0))) {
					++buffer;
					if(--len == 0) break;
				} else if(buffer[0]==1 && lws_is_final_fragment(wsi) && len>5) {
					uint16_t rows = *(uint16_t *)&buffer[1];
					uint16_t cols = *(uint16_t *)&buffer[3];
					if(!pss->process) {
						if(credential && !pss->authenticated) {
							buffer[len-1] = 0;
							char *token = buffer+5;
							if (!strcmp(token, credential))
								pss->authenticated = 1;
							else {
								lwsl_warn("WS authentication failed with token: %s\n", token);
								lws_close_reason(wsi, LWS_CLOSE_STATUS_POLICY_VIOLATION, NULL, 0);
								return -1;
							}
						}
						spawn_process(pss, rows, cols);
					} else {
						struct winsize size = {rows, cols, 0, 0};
						ioctl(pss->process->pty, TIOCSWINSZ, &size);
					}
				}
			}
			if(pss->receiving && pss->process && (!credential || pss->authenticated)) {
				uv_buf_t buf = { .base = buffer, .len = len };
				int n = uv_try_write((uv_stream_t *)&pss->process->in, &buf, 1);
				if(n != len) {
					uv_write_t *req = malloc(sizeof(uv_write_t));
					if(n>0){ buffer += n; buf.len -= n; }
					req->data = buf.base = malloc(buf.len);
					memcpy(buf.base, buffer, buf.len);
					uv_write(req, (uv_stream_t *) &pss->process->in, &buf, 1, write_cb);
				}
			}
			break;

		case LWS_CALLBACK_CLOSED:
			if (!pss->wsi) break;
			if (pss->pty_buf.base) free(pss->pty_buf.base - LWS_PRE);
			if (pss->process) {
				pss->process->ws_closed = 1;
				if (process_running(pss->process)) {
					lwsl_notice("killing process, pid: %d\n", pss->process->pid);
					uv_kill(-pss->process->pid, SIGHUP);
				}
			}
			break;

		default:
			break;
	}

	return 0;
}

const struct lws_protocols protocols[] = {{"tty", callback_tty, sizeof(struct pss_tty), 0}, {NULL, NULL, 0, 0}};

const uint32_t backoff_ms[] = {1000, 2000, 3000, 4000, 5000};
lws_retry_bo_t retry = {
		.retry_ms_table = backoff_ms,
		.retry_ms_table_count = LWS_ARRAY_SIZE(backoff_ms),
		.conceal_count = LWS_ARRAY_SIZE(backoff_ms),
		.secs_since_valid_ping = 5,
		.secs_since_valid_hangup = 10,
		.jitter_percent = 0,
};

void signal_cb(uv_signal_t *watcher, int signum) {
	switch (watcher->signum) {
		case SIGINT:
		case SIGTERM:
			break;
		default:
			signal(SIGABRT, SIG_DFL);
			abort();
	}

	lws_cancel_service(context);
	uv_stop(&loop);
}

int main(int argc, char **argv) {
	uv_loop_init(&loop);

	cwd = getenv("HOME");
	args[0] = getenv("SHELL");
	if(chdir(cwd) == -1) {}
	putenv("TERM=xterm-256color");
	putenv("LANG=en_US.UTF-8");

	struct lws_context_creation_info info;
	memset(&info, 0, sizeof(info));
	info.port = 7681;
	info.iface = NULL;
	info.protocols = protocols;
	info.gid = -1;
	info.uid = -1;
	info.options = LWS_SERVER_OPTION_LIBUV | LWS_SERVER_OPTION_VALIDATE_UTF8;

	char iface[128] = "";
	char socket_owner[128] = "";
	int is_socket = 0;

	int i;
	for(i = 1; i < argc; ++i) {
		char *arg = argv[i];
		if(!strcmp(arg, "-p") && ++i<argc) {
			info.port = atoi(argv[i]);
		}else if((!strcmp(arg, "-i")||!strcmp(arg, "-is")) && ++i<argc) {
			strncpy(iface, argv[i], sizeof(iface) - 1);
			iface[sizeof(iface) - 1] = '\0';
			is_socket = !strcmp(arg, "-is");
		}else if(!strcmp(arg, "-U") && ++i<argc) {
			strncpy(socket_owner, argv[i], sizeof(socket_owner) - 1);
			socket_owner[sizeof(socket_owner) - 1] = '\0';
		}else if(!strcmp(arg, "-c") && ++i<argc) {
			char *argopt = argv[i];
			credential = malloc(256);
			lws_b64_encode_string(argopt, strlen(argopt), credential, 256);
		}else if(!strcmp(arg, "-P") && ++i<argc) {
			int interval = atoi(argv[i]);
			retry.secs_since_valid_ping = interval;
			retry.secs_since_valid_hangup = interval + 7;
		}else break;
	}

	info.retry_and_idle_policy = &retry;

	if (strlen(iface) > 0) {
		info.iface = iface;
		if (is_socket) {
			info.options |= LWS_SERVER_OPTION_UNIX_SOCK;
			info.port = 0;
			strncpy(socket_path, info.iface, sizeof(socket_path) - 1);
			if (strlen(socket_owner) > 0) {
				info.unix_socket_perms = socket_owner;
			}
		}
	}

	void *foreign_loops[1];
	foreign_loops[0] = &loop;
	info.foreign_loops = foreign_loops;
	info.options |= LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (context == NULL) {
		lwsl_err("libwebsockets context creation failed\n");
		return 1;
	}

	struct lws_vhost *vhost = lws_create_vhost(context, &info);
	if (vhost == NULL) {
		lwsl_err("libwebsockets vhost creation failed\n");
		return 1;
	}
	int port = lws_get_vhost_listen_port(vhost);
	lwsl_notice(" Listening on port: %d\n", port);

	int sig_nums[] = {SIGINT, SIGTERM};
	uv_signal_t signals[2];
	for (int i = 0; i < 2; i++) {
		uv_signal_init(&loop, &signals[i]);
		uv_signal_start(&signals[i], signal_cb, sig_nums[i]);
	}

	lws_service(context, 0);

	for (int i = 0; i < 2; i++) {
		uv_signal_stop(&signals[i]);
	}

	lws_context_destroy(context);

	if (credential) free(credential);
	if (strlen(socket_path)) {
		struct stat st;
		if (!stat(socket_path, &st)) {
			unlink(socket_path);
		}
	}

	uv_loop_close(&loop);

	return 0;
}

// vi:ts=2:sw=2:fdm=indent
