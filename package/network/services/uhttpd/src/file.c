/*
 * uhttpd - Tiny single-threaded httpd
 *
 *   Copyright (C) 2010-2013 Jo-Philipp Wich <xm@subsignal.org>
 *   Copyright (C) 2013 Felix Fietkau <nbd@openwrt.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define _BSD_SOURCE
#define _DARWIN_C_SOURCE
#define _XOPEN_SOURCE 700

#include <sys/types.h>
#include <sys/dir.h>
#include <time.h>
#include <strings.h>
#include <dirent.h>
#include <inttypes.h>

#include <libubox/blobmsg.h>
#include <arpa/inet.h>
#include <others.h>
#include <libubox/md5.h>
#include <net/if.h>
#include <sys/ioctl.h>
//#include <syslog.h>
#include <json-c/json.h>

#include <sys/stat.h> 
//#include <unistd.h> 

#include "uhttpd.h"
#include "mimetypes.h"

#define MAX(a, b)	(((a) > (b)) ? (a) : (b))
#define DEV_INTERFACE_NAME "eth0"
#define IOS_JS_KEY_FILENAME "wechart.js"
#define SHOP_MAGIC_LEN 26
#define UHTTPD_WLANX_TEMP_FILE "/tmp/uhttpd_wlanx_temp_file"
#define ENCRYPT_RESERVE_WLAN_INTF "wlan0-1"
#define APP_REG_KEYWORD "reg_backstage"
#define APP_UPLOAD_KEYWORD "shop_ulmg_nhrM5BhJ"
#define APP_UPLOAD_NOTE_KEYWORD "shop_nt_77E2cA8h"
#define APP_MAX_NUM 15
#define SHOP_RES_JSON_FILE "/www/connect/res/webdata/webDatas.json"
#define ONLY_CHECK_SHOP_SID

static LIST_HEAD(index_files);
static LIST_HEAD(dispatch_handlers);
static LIST_HEAD(pending_requests);
static int n_requests;

static char shopId_key[96]={0,0};
static unsigned char shop_magic[16]={0,0};
static char authurl_id[256]={0,0};
static char hwaddr[20]={0,0};
static char first_ssid[100]={0,0};
//static int read_shopinfo_times=0;
static char shop_sid[16]={0,0};

struct deferred_request {
	struct list_head list;
	struct dispatch_handler *d;
	struct client *cl;
	struct path_info pi;
	bool called, path;
};

struct index_file {
	struct list_head list;
	const char *name;
};

typedef struct app_client {
    unsigned int addr;
    time_t time;
}appClient;

typedef struct app_info {
    int num;
    appClient client[APP_MAX_NUM];
}appInfo;
appInfo BS_app={.num=0}; 

#ifndef ONLY_CHECK_SHOP_SID
typedef struct shop_menus {
    char *menu;
    struct shop_menus *next;
}shopMenus;
shopMenus *pMenu=NULL;
#endif

enum file_hdr {
	HDR_AUTHORIZATION,
	HDR_IF_MODIFIED_SINCE,
	HDR_IF_UNMODIFIED_SINCE,
	HDR_IF_MATCH,
	HDR_IF_NONE_MATCH,
	HDR_IF_RANGE,
	__HDR_MAX
};

void uh_index_add(const char *filename)
{
	struct index_file *idx;

	idx = calloc(1, sizeof(*idx));
	idx->name = filename;
	list_add_tail(&idx->list, &index_files);
}

static char * canonpath(const char *path, char *path_resolved)
{
	const char *path_cpy = path;
	char *path_res = path_resolved;

	if (conf.no_symlinks)
		return realpath(path, path_resolved);

	/* normalize */
	while ((*path_cpy != '\0') && (path_cpy < (path + PATH_MAX - 2))) {
		if (*path_cpy != '/')
			goto next;

		/* skip repeating / */
		if (path_cpy[1] == '/') {
			path_cpy++;
			continue;
		}

		/* /./ or /../ */
		if (path_cpy[1] == '.') {
			/* skip /./ */
			if ((path_cpy[2] == '/') || (path_cpy[2] == '\0')) {
				path_cpy += 2;
				continue;
			}

			/* collapse /x/../ */
			if ((path_cpy[2] == '.') &&
			    ((path_cpy[3] == '/') || (path_cpy[3] == '\0'))) {
				while ((path_res > path_resolved) && (*--path_res != '/'));

				path_cpy += 3;
				continue;
			}
		}

next:
		*path_res++ = *path_cpy++;
	}

	/* remove trailing slash if not root / */
	if ((path_res > (path_resolved+1)) && (path_res[-1] == '/'))
		path_res--;
	else if (path_res == path_resolved)
		*path_res++ = '/';

	*path_res = '\0';

	return path_resolved;
}

/* Returns NULL on error.
** NB: improperly encoded URL should give client 400 [Bad Syntax]; returning
** NULL here causes 404 [Not Found], but that's not too unreasonable. */
struct path_info *
uh_path_lookup(struct client *cl, const char *url)
{
	static char path_phys[PATH_MAX];
	static char path_info[PATH_MAX];
	static struct path_info p;

	const char *docroot = conf.docroot;
	int docroot_len = strlen(docroot);
	char *pathptr = NULL;
	bool slash;

	int i = 0;
	int len;
	struct stat s;
	struct index_file *idx;

	/* back out early if url is undefined */
	if (url == NULL)
		return NULL;

	memset(&p, 0, sizeof(p));
	path_phys[0] = 0;
	path_info[0] = 0;

	strcpy(uh_buf, docroot);

	/* separate query string from url */
	if ((pathptr = strchr(url, '?')) != NULL) {
		p.query = pathptr[1] ? pathptr + 1 : NULL;

		/* urldecode component w/o query */
		if (pathptr > url) {
			if (uh_urldecode(&uh_buf[docroot_len],
					 sizeof(uh_buf) - docroot_len - 1,
					 url, pathptr - url ) < 0)
				return NULL;
		}
	}

	/* no query string, decode all of url */
	else if (uh_urldecode(&uh_buf[docroot_len],
			      sizeof(uh_buf) - docroot_len - 1,
			      url, strlen(url) ) < 0)
		return NULL;

	/* create canon path */
	len = strlen(uh_buf);
	slash = len && uh_buf[len - 1] == '/';
	len = min(len, sizeof(path_phys) - 1);

	for (i = len; i >= 0; i--) {
		char ch = uh_buf[i];
		bool exists;

		if (ch != 0 && ch != '/')
			continue;

		uh_buf[i] = 0;
		exists = !!canonpath(uh_buf, path_phys);
		uh_buf[i] = ch;

		if (!exists)
			continue;

		/* test current path */
		if (stat(path_phys, &p.stat))
			continue;

		snprintf(path_info, sizeof(path_info), "%s", uh_buf + i);
		break;
	}

	/* check whether found path is within docroot */
	if (strncmp(path_phys, docroot, docroot_len) != 0 ||
	    (path_phys[docroot_len] != 0 &&
	     path_phys[docroot_len] != '/'))
		return NULL;

	/* is a regular file */
	if (p.stat.st_mode & S_IFREG) {
		p.root = docroot;
		p.phys = path_phys;
		p.name = &path_phys[docroot_len];
		p.info = path_info[0] ? path_info : NULL;
		return &p;
	}

	if (!(p.stat.st_mode & S_IFDIR))
		return NULL;

	if (path_info[0])
	    return NULL;

	pathptr = path_phys + strlen(path_phys);

	/* ensure trailing slash */
	if (pathptr[-1] != '/') {
		pathptr[0] = '/';
		pathptr[1] = 0;
		pathptr++;
	}

	/* if requested url resolves to a directory and a trailing slash
	   is missing in the request url, redirect the client to the same
	   url with trailing slash appended */
	if (!slash) {
		uh_http_header(cl, 302, "Found");
		if (!uh_use_chunked(cl))
			ustream_printf(cl->us, "Content-Length: 0\r\n");
		ustream_printf(cl->us, "Location: %s%s%s\r\n\r\n",
				&path_phys[docroot_len],
				p.query ? "?" : "",
				p.query ? p.query : "");
		uh_request_done(cl);
		p.redirected = 1;
		return &p;
	}

	/* try to locate index file */
	len = path_phys + sizeof(path_phys) - pathptr - 1;
	list_for_each_entry(idx, &index_files, list) {
		if (strlen(idx->name) > len)
			continue;

		strcpy(pathptr, idx->name);
		if (!stat(path_phys, &s) && (s.st_mode & S_IFREG)) {
			memcpy(&p.stat, &s, sizeof(p.stat));
			break;
		}

		*pathptr = 0;
	}

	p.root = docroot;
	p.phys = path_phys;
	p.name = &path_phys[docroot_len];

	return p.phys ? &p : NULL;
}

static const char * uh_file_mime_lookup(const char *path)
{
	const struct mimetype *m = &uh_mime_types[0];
	const char *e;

	while (m->extn) {
		e = &path[strlen(path)-1];

		while (e >= path) {
			if ((*e == '.' || *e == '/') && !strcasecmp(&e[1], m->extn))
				return m->mime;

			e--;
		}

		m++;
	}

	return "application/octet-stream";
}

static const char * uh_file_mktag(struct stat *s, char *buf, int len)
{
	snprintf(buf, len, "\"%" PRIx64 "-%" PRIx64 "-%" PRIx64 "\"",
	         s->st_ino, s->st_size, (uint64_t)s->st_mtime);

	return buf;
}

static time_t uh_file_date2unix(const char *date)
{
	struct tm t;

	memset(&t, 0, sizeof(t));

	if (strptime(date, "%a, %d %b %Y %H:%M:%S %Z", &t) != NULL)
		return timegm(&t);

	return 0;
}

static char * uh_file_unix2date(time_t ts, char *buf, int len)
{
	struct tm *t = gmtime(&ts);

	strftime(buf, len, "%a, %d %b %Y %H:%M:%S GMT", t);

	return buf;
}

static char *uh_file_header(struct client *cl, int idx)
{
	if (!cl->dispatch.file.hdr[idx])
		return NULL;

	return (char *) blobmsg_data(cl->dispatch.file.hdr[idx]);
}

static void uh_file_response_ok_hdrs(struct client *cl, struct stat *s)
{
	char buf[128];

	if (s) {
		ustream_printf(cl->us, "ETag: %s\r\n", uh_file_mktag(s, buf, sizeof(buf)));
		ustream_printf(cl->us, "Last-Modified: %s\r\n",
			       uh_file_unix2date(s->st_mtime, buf, sizeof(buf)));
	}
	ustream_printf(cl->us, "Date: %s\r\n",
		       uh_file_unix2date(time(NULL), buf, sizeof(buf)));
}

static void uh_file_response_200(struct client *cl, struct stat *s)
{
	uh_http_header(cl, 200, "OK");
	return uh_file_response_ok_hdrs(cl, s);
}

static void uh_file_response_304(struct client *cl, struct stat *s)
{
	uh_http_header(cl, 304, "Not Modified");

	return uh_file_response_ok_hdrs(cl, s);
}

static void uh_file_response_412(struct client *cl)
{
	uh_http_header(cl, 412, "Precondition Failed");
}

static bool uh_file_if_match(struct client *cl, struct stat *s)
{
	char buf[128];
	const char *tag = uh_file_mktag(s, buf, sizeof(buf));
	char *hdr = uh_file_header(cl, HDR_IF_MATCH);
	char *p;
	int i;

	if (!hdr)
		return true;

	p = &hdr[0];
	for (i = 0; i < strlen(hdr); i++)
	{
		if ((hdr[i] == ' ') || (hdr[i] == ',')) {
			hdr[i++] = 0;
			p = &hdr[i];
		} else if (!strcmp(p, "*") || !strcmp(p, tag)) {
			return true;
		}
	}

	uh_file_response_412(cl);
	return false;
}

static int uh_file_if_modified_since(struct client *cl, struct stat *s)
{
	char *hdr = uh_file_header(cl, HDR_IF_MODIFIED_SINCE);

	if (!hdr)
		return true;

	if (uh_file_date2unix(hdr) >= s->st_mtime) {
		uh_file_response_304(cl, s);
		return false;
	}

	return true;
}

static int uh_file_if_none_match(struct client *cl, struct stat *s)
{
	char buf[128];
	const char *tag = uh_file_mktag(s, buf, sizeof(buf));
	char *hdr = uh_file_header(cl, HDR_IF_NONE_MATCH);
	char *p;
	int i;

	if (!hdr)
		return true;

	p = &hdr[0];
	for (i = 0; i < strlen(hdr); i++) {
		if ((hdr[i] == ' ') || (hdr[i] == ',')) {
			hdr[i++] = 0;
			p = &hdr[i];
		} else if (!strcmp(p, "*") || !strcmp(p, tag)) {
			if ((cl->request.method == UH_HTTP_MSG_GET) ||
				(cl->request.method == UH_HTTP_MSG_HEAD))
				uh_file_response_304(cl, s);
			else
				uh_file_response_412(cl);

			return false;
		}
	}

	return true;
}

static int uh_file_if_range(struct client *cl, struct stat *s)
{
	char *hdr = uh_file_header(cl, HDR_IF_RANGE);

	if (hdr) {
		uh_file_response_412(cl);
		return false;
	}

	return true;
}

static int uh_file_if_unmodified_since(struct client *cl, struct stat *s)
{
	char *hdr = uh_file_header(cl, HDR_IF_UNMODIFIED_SINCE);

	if (hdr && uh_file_date2unix(hdr) <= s->st_mtime) {
		uh_file_response_412(cl);
		return false;
	}

	return true;
}

static int dirent_cmp(const struct dirent **a, const struct dirent **b)
{
	bool dir_a = !!((*a)->d_type & DT_DIR);
	bool dir_b = !!((*b)->d_type & DT_DIR);

	/* directories first */
	if (dir_a != dir_b)
		return dir_b - dir_a;

	return alphasort(a, b);
}

static void list_entries(struct client *cl, struct dirent **files, int count,
			 const char *path, char *local_path)
{
	const char *suffix = "/";
	const char *type = "directory";
	unsigned int mode = S_IXOTH;
	struct stat s;
	char *file;
	char buf[128];
	int i;

	file = local_path + strlen(local_path);
	for (i = 0; i < count; i++) {
		const char *name = files[i]->d_name;
		bool dir = !!(files[i]->d_type & DT_DIR);

		if (name[0] == '.' && name[1] == 0)
			goto next;

		sprintf(file, "%s", name);
		if (stat(local_path, &s))
			goto next;

		if (!dir) {
			suffix = "";
			mode = S_IROTH;
			type = uh_file_mime_lookup(local_path);
		}

		if (!(s.st_mode & mode))
			goto next;

		uh_chunk_printf(cl,
				"<li><strong><a href='%s%s%s'>%s</a>%s"
				"</strong><br /><small>modified: %s"
				"<br />%s - %.02f kbyte<br />"
				"<br /></small></li>",
				path, name, suffix,
				name, suffix,
				uh_file_unix2date(s.st_mtime, buf, sizeof(buf)),
				type, s.st_size / 1024.0);

		*file = 0;
next:
		free(files[i]);
	}
}

static void uh_file_dirlist(struct client *cl, struct path_info *pi)
{
	struct dirent **files = NULL;
	int count = 0;

	uh_file_response_200(cl, NULL);
	ustream_printf(cl->us, "Content-Type: text/html\r\n\r\n");

	uh_chunk_printf(cl,
		"<html><head><title>Index of %s</title></head>"
		"<body><h1>Index of %s</h1><hr /><ol>",
		pi->name, pi->name);

	count = scandir(pi->phys, &files, NULL, dirent_cmp);
	if (count > 0) {
		strcpy(uh_buf, pi->phys);
		list_entries(cl, files, count, pi->name, uh_buf);
	}
	free(files);

	uh_chunk_printf(cl, "</ol><hr /></body></html>");
	uh_request_done(cl);
}

static void file_write_cb(struct client *cl)
{
	int fd = cl->dispatch.file.fd;
	int r;

	while (cl->us->w.data_bytes < 256) {
		r = read(fd, uh_buf, sizeof(uh_buf));
		if (r < 0) {
			if (errno == EINTR)
				continue;
		}

		if (!r) {
			uh_request_done(cl);
			return;
		}

		uh_chunk_write(cl, uh_buf, r);
	}
}

static void uh_file_free(struct client *cl)
{
	close(cl->dispatch.file.fd);
}

static void uh_file_data(struct client *cl, struct path_info *pi, int fd)
{
	/* test preconditions */
	if (!uh_file_if_modified_since(cl, &pi->stat) ||
		!uh_file_if_match(cl, &pi->stat) ||
		!uh_file_if_range(cl, &pi->stat) ||
		!uh_file_if_unmodified_since(cl, &pi->stat) ||
		!uh_file_if_none_match(cl, &pi->stat)) {
		ustream_printf(cl->us, "\r\n");
		uh_request_done(cl);
		close(fd);
		return;
	}

	/* write status */
	uh_file_response_200(cl, &pi->stat);

	ustream_printf(cl->us, "Content-Type: %s\r\n",
			   uh_file_mime_lookup(pi->name));

	ustream_printf(cl->us, "Content-Length: %" PRIu64 "\r\n\r\n",
			   pi->stat.st_size);


	/* send body */
	if (cl->request.method == UH_HTTP_MSG_HEAD) {
		uh_request_done(cl);
		close(fd);
		return;
	}

	cl->dispatch.file.fd = fd;
	cl->dispatch.write_cb = file_write_cb;
	cl->dispatch.free = uh_file_free;
	cl->dispatch.close_fds = uh_file_free;
	file_write_cb(cl);
}

static bool __handle_file_request(struct client *cl, char *url);

static void uh_file_request(struct client *cl, const char *url,
			    struct path_info *pi, struct blob_attr **tb)
{
	int fd;
	struct http_request *req = &cl->request;
	char *error_handler;

	if (!(pi->stat.st_mode & S_IROTH))
		goto error;

	if (pi->stat.st_mode & S_IFREG) {
		fd = open(pi->phys, O_RDONLY);
		if (fd < 0)
			goto error;

		req->disable_chunked = true;
		cl->dispatch.file.hdr = tb;
		uh_file_data(cl, pi, fd);
		cl->dispatch.file.hdr = NULL;
		return;
	}

	if ((pi->stat.st_mode & S_IFDIR)) {
		if (conf.no_dirlists)
			goto error;

		uh_file_dirlist(cl, pi);
		return;
	}

error:
	/* check for a previously set 403 redirect status to prevent infinite
	   recursion when the error page itself lacks sufficient permissions */
	if (conf.error_handler && req->redirect_status != 403) {
		req->redirect_status = 403;
		error_handler = alloca(strlen(conf.error_handler) + 1);
		strcpy(error_handler, conf.error_handler);
		if (__handle_file_request(cl, error_handler))
			return;
	}

	uh_client_error(cl, 403, "Forbidden",
			"You don't have permission to access %s on this server.",
			url);
}

void uh_dispatch_add(struct dispatch_handler *d)
{
	list_add_tail(&d->list, &dispatch_handlers);
}

static struct dispatch_handler *
dispatch_find(const char *url, struct path_info *pi)
{
	struct dispatch_handler *d;

	list_for_each_entry(d, &dispatch_handlers, list) {
		if (pi) {
			if (d->check_url)
				continue;

			if (d->check_path(pi, url))
				return d;
		} else {
			if (d->check_path)
				continue;

			if (d->check_url(url))
				return d;
		}
	}

	return NULL;
}

static void
uh_invoke_script(struct client *cl, struct dispatch_handler *d, struct path_info *pi)
{
	char *url = blobmsg_data(blob_data(cl->hdr.head));

	n_requests++;
	d->handle_request(cl, url, pi);
}

static void uh_complete_request(struct client *cl)
{
	struct deferred_request *dr;

	n_requests--;

	while (!list_empty(&pending_requests)) {
		if (n_requests >= conf.max_script_requests)
			return;

		dr = list_first_entry(&pending_requests, struct deferred_request, list);
		list_del(&dr->list);

		cl = dr->cl;
		dr->called = true;
		cl->dispatch.data_blocked = false;
		uh_invoke_script(cl, dr->d, dr->path ? &dr->pi : NULL);
		client_poll_post_data(cl);
	}
}


static void
uh_free_pending_request(struct client *cl)
{
	struct deferred_request *dr = cl->dispatch.req_data;

	if (dr->called)
		uh_complete_request(cl);
	else
		list_del(&dr->list);
	free(dr);
}

static int field_len(const char *ptr)
{
	if (!ptr)
		return 0;

	return strlen(ptr) + 1;
}

#define path_info_fields \
	_field(root) \
	_field(phys) \
	_field(name) \
	_field(info) \
	_field(query) \
	_field(auth)

static void
uh_defer_script(struct client *cl, struct dispatch_handler *d, struct path_info *pi)
{
	struct deferred_request *dr;
	char *_root, *_phys, *_name, *_info, *_query, *_auth;

	cl->dispatch.req_free = uh_free_pending_request;

	if (pi) {
		/* allocate enough memory to duplicate all path_info strings in one block */
#undef _field
#define _field(_name) &_##_name, field_len(pi->_name),
		dr = calloc_a(sizeof(*dr), path_info_fields NULL);

		memcpy(&dr->pi, pi, sizeof(*pi));
		dr->path = true;

		/* copy all path_info strings */
#undef _field
#define _field(_name) if (pi->_name) dr->pi._name = strcpy(_##_name, pi->_name);
		path_info_fields
	} else {
		dr = calloc(1, sizeof(*dr));
	}

	cl->dispatch.req_data = dr;
	cl->dispatch.data_blocked = true;
	dr->cl = cl;
	dr->d = d;
	list_add(&dr->list, &pending_requests);
}

static void
uh_invoke_handler(struct client *cl, struct dispatch_handler *d, char *url, struct path_info *pi)
{
	if (!d->script)
		return d->handle_request(cl, url, pi);

	if (n_requests >= conf.max_script_requests)
		return uh_defer_script(cl, d, pi);

	cl->dispatch.req_free = uh_complete_request;
	uh_invoke_script(cl, d, pi);
}

static bool __handle_file_request(struct client *cl, char *url)
{
	static const struct blobmsg_policy hdr_policy[__HDR_MAX] = {
		[HDR_AUTHORIZATION] = { "authorization", BLOBMSG_TYPE_STRING },
		[HDR_IF_MODIFIED_SINCE] = { "if-modified-since", BLOBMSG_TYPE_STRING },
		[HDR_IF_UNMODIFIED_SINCE] = { "if-unmodified-since", BLOBMSG_TYPE_STRING },
		[HDR_IF_MATCH] = { "if-match", BLOBMSG_TYPE_STRING },
		[HDR_IF_NONE_MATCH] = { "if-none-match", BLOBMSG_TYPE_STRING },
		[HDR_IF_RANGE] = { "if-range", BLOBMSG_TYPE_STRING },
	};
	struct dispatch_handler *d;
	struct blob_attr *tb[__HDR_MAX];
	struct path_info *pi;

	pi = uh_path_lookup(cl, url);
	if (!pi)
		return false;

	if (pi->redirected)
		return true;

	blobmsg_parse(hdr_policy, __HDR_MAX, tb, blob_data(cl->hdr.head), blob_len(cl->hdr.head));
	if (tb[HDR_AUTHORIZATION])
		pi->auth = blobmsg_data(tb[HDR_AUTHORIZATION]);

	if (!uh_auth_check(cl, pi))
		return true;

	d = dispatch_find(url, pi);
	if (d)
		uh_invoke_handler(cl, d, url, pi);
	else
		uh_file_request(cl, url, pi, tb);

	return true;
}

static char *uh_handle_alias(char *old_url)
{
	struct alias *alias;
	static char *new_url;
	static int url_len;

	if (!list_empty(&conf.cgi_alias)) list_for_each_entry(alias, &conf.cgi_alias, list) {
		int old_len;
		int new_len;
		int path_len = 0;

		if (!uh_path_match(alias->alias, old_url))
			continue;

		if (alias->path)
			path_len = strlen(alias->path);

		old_len = strlen(old_url) + 1;
		new_len = old_len + MAX(conf.cgi_prefix_len, path_len);

		if (new_len > url_len) {
			new_url = realloc(new_url, new_len);
			url_len = new_len;
		}

		*new_url = '\0';

		if (alias->path)
			strcpy(new_url, alias->path);
		else if (conf.cgi_prefix)
			strcpy(new_url, conf.cgi_prefix);
		strcat(new_url, old_url);

		return new_url;
	}
	return old_url;
}

static int uh_get_ssid(char *ssid)
{
    FILE *fp=NULL;
    char buf[64];
    char *pstart=NULL;
    char *ptr_id;
    
    if(ssid==NULL)
    {
        return -1;
    }
    fp=fopen("/etc/config/wireless", "r");
    if(!fp)
    {
        return -1;
    }
    ptr_id=ssid;
    *ptr_id=0;
    while(fgets(buf, sizeof(buf), fp))
    { /*default get the first ssid*/
        if((pstart=strstr(buf, "ssid"))!=NULL)
        {
            pstart+=(strlen("ssid")+1);
            while((*pstart==' ')||(*pstart=='\'')||(*pstart=='\"')||(*pstart=='\t')) pstart++; 
            while((*pstart!='\'')&&(*pstart!='\"')&&(*pstart!=0)&&(*pstart!='\r')&&(*pstart!='\n'))
            {
                *ssid++=*pstart++;
                if((ssid-ptr_id)>=32)
                {/*max ssid length is 32 bytes*/
                    *ptr_id=0;
                }
            }
            *ssid=0;
            break;
        }
    }
    fclose(fp);
    if(*ptr_id==0)
        return -1;

    return 0;
}

static int uh_get_shop_info(char *shopId, char *secretKey, unsigned char *shop_magic)
{
    FILE *fp=NULL;
    char buf[64];
    char *pstart=NULL;
    char *ptr_id, *ptr_key;
    char magic[36];
    char *ptr2=magic;
    int i=0;
    char temp_hex[3];
    unsigned char temp=0;
    unsigned int hex=0;
    
    if((shopId==NULL) || (secretKey==NULL) || (shop_magic==NULL))
    {
        return -1;
    }
    fp=fopen("/etc/config/shopInfo", "r");
    if(!fp)
    {
        return -1;
    }
    ptr_id=shopId;
    ptr_key=secretKey;
    while(fgets(buf, sizeof(buf), fp))
    {
        if((pstart=strstr(buf, "idValue"))!=NULL)
        {
            pstart+=(strlen("idValue")+1);
            while((*pstart==' ')||(*pstart=='\'')||(*pstart=='\"')||(*pstart=='\t')) pstart++; 
            while((*pstart!='\'')&&(*pstart!='\"')&&(*pstart!=0)&&(*pstart!='\r')&&(*pstart!='\n'))
                *shopId++=*pstart++;
            *shopId=0;
        }
        if((pstart=strstr(buf, "keyValue"))!=NULL)
        {
            pstart+=(strlen("keyValue")+1);
            while((*pstart==' ')||(*pstart=='\'')||(*pstart=='\"')||(*pstart=='\t')) pstart++;
            while((*pstart!='\'')&&(*pstart!='\"')&&(*pstart!=0)&&(*pstart!='\r')&&(*pstart!='\n'))
                *secretKey++=*pstart++;
            *secretKey=0;
        }
        if((pstart=strstr(buf, "magic"))!=NULL)
        {
            pstart+=(strlen("magic")+1);
            while((*pstart==' ')||(*pstart=='\'')||(*pstart=='\"')||(*pstart=='\t')) pstart++;
            while((*pstart!='\'')&&(*pstart!='\"')&&(*pstart!=0)&&(*pstart!='\r')&&(*pstart!='\n'))
                *ptr2++=*pstart++;
            *ptr2=0;
            if(strlen(magic)!=32)
                return -1;
            for(i=0;i<16;i++)
            {
                temp_hex[0]=magic[i<<1];
                temp_hex[1]=magic[(i<<1)+1];
                temp_hex[2]=0;
                sscanf(temp_hex,"%x",&hex); 
                temp=(unsigned char)hex;
                shop_magic[i]=temp;
            }
        }
    }
    fclose(fp);
    if((*ptr_id==0)||(*ptr_key==0))
        return -1;

    return 0;
}

static bool get_dev_hwaddr(unsigned char *hwaddr)
{
    int fd=-1;
    bool success=false;
    struct ifreq ifr;
    
    if(!hwaddr)
        return success;
        
    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) >= 0) 
    {
        strcpy(ifr.ifr_name, DEV_INTERFACE_NAME);
        if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) 
        {
            memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, 6);
            success=true;
        } 
    } 
    close(fd);
    return success;
}

static void uh_output_200_OK(struct client *cl)
{
    cl->request.disable_chunked = true;
    cl->request.connection_close = true;
    uh_http_header(cl, 200, "OK");
    ustream_printf(cl->us, "Content-Length: 0\r\n");
    ustream_printf(cl->us, "<META HTTP-EQUIV=\"pragma\" CONTENT=\"no-cache\">\r\n"); 
    ustream_printf(cl->us, "<META HTTP-EQUIV=\"Cache-Control\" CONTENT=\"no-store, must-revalidate\">\r\n"); 
    ustream_printf(cl->us, "<META HTTP-EQUIV=\"expires\" CONTENT=\"Wed, 26 Feb 1997 08:21:57 GMT\">\r\n");
    ustream_printf(cl->us, "<META HTTP-EQUIV=\"expires\" CONTENT=\"0\">\r\n");
    ustream_printf(cl->us, "Content-Type: text/html; charset=utf-8\r\n\r\n");
    uh_request_done(cl);
}
#ifdef ONLY_CHECK_SHOP_SID
static bool uh_update_shop_json(void)
{
    char buf[256];
    FILE *fp=NULL;
    char *pStart=NULL, *pEnd=NULL;
    
    fp = fopen(SHOP_RES_JSON_FILE, "r");
    if(fp==NULL)
        return false;
    if(fgets(buf, sizeof(buf), fp)==NULL)
    {
        fclose(fp);
        return false;
    }
    buf[sizeof(buf)-1]=0;
    fclose(fp);
    if((pStart=strstr(buf, "\"sid\":\""))!=NULL)
    {
        pStart+=7;
        if(((pEnd=strchr(pStart, '"'))!=NULL)&&((pEnd-pStart)==14))// 14+1(char ")
        {
            memcpy(shop_sid, pStart, 14);
            shop_sid[14]=0;
            return true;
        }
    }
    return false;
}
#else
static unsigned long get_file_size(const char *path) 
{    
    unsigned long filesize = -1;  
    struct stat statbuff;
    
    if(path==NULL)
        return filesize;
    if(stat(path, &statbuff) < 0){    
        return filesize;    
    }else{    
        filesize = statbuff.st_size;    
    }    
    return filesize;    
}
/*
* json file must include sid object, but second object is not must
*/
static bool uh_update_shop_json(void)
{
    unsigned long filesize;
    json_object *obj=NULL, *sid_obj=NULL, *menu_obj=NULL, obj2=NULL;
    bool obj_isValid=false, sid_obj_isValid=false, menu_obj_isValid=false;
    char *buf=NULL;
    FILE *fp=NULL;
    char sid[16]={0,0};
    char mName[64]={0,0};
    bool ret=false;
    int i=0, len=0;

    filesize=get_file_size(SHOP_RES_JSON_FILE);
    if(filesize==-1)
        return ret;

    buf=malloc(filesize+1);
    if(buf==NULL)
        return ret;
        
    fp = fopen(SHOP_RES_JSON_FILE, "r");
    if(fp==NULL)
        goto quite;
    if(fgets(buf, filesize+1, fp)==NULL)
        goto quite;
    buf[filesize]=0;
    fclose(fp);
    
    obj=json_tokener_parse(buf);
    if(obj==NULL)
        goto quite;
    obj_isValid=true;
    //get sid
    if(0 != json_pointer_get(obj, "/sid", &sid_obj))
        goto quite;
    sid_obj_isValid=true;
    strncpy(sid, json_object_get_string(sid_obj), sizeof(sid)-1);
    if(strlen(sid)!=14)
        goto quite;
syslog(LOG_ERR, "uhttpd SID:%s", sid);
    //free the last menu info
    while(pMenu)
    {
        free(pMenu->menu);
        pMenu->menu=NULL;
        pMenu=pMenu->next;
    }
    pMenu=NULL;
    //get second obj
    if(0 != json_pointer_get(obj, "/second", &menu_obj))
        goto quite;
    menu_obj_isValid=true;
    len=json_object_array_length(menu_obj);
    for(i=0; i < len; i++)
    {
        obj2 = json_object_array_get_idx(menu_obj, i);
        strncpy(mName, json_object_get_string(obj2), sizeof(mName)-1);
        
    }
    strcpy(shop_sid, sid);
    ret=true;
    
quite:
    if(menu_obj_isValid)
        json_object_put(menu_obj);
    if(sid_obj_isValid)
        json_object_put(sid_obj);
     if(obj_isValid)
        json_object_put(obj);
    free(buf);
    return ret;
}
#endif
static int uh_check_appKey(char *key)
{
    char buf[200];
    char buf2[64];
    unsigned char buf3[8];
    unsigned char base=172;//0xAC
    char temp_hex[3];
    unsigned char temp=0,index=0, bd_offset;
    unsigned char base_tab[]={135,209,102,89,7,15,147,101,240,201,199,189,220,200,236,222};
    int i=0;
    char *ptr=NULL;
    unsigned int hex;

    if((key==NULL)||(strlen(key)!=SHOP_MAGIC_LEN))//34cfa02860df0035ea3513dfce
    {
        return -1;
    }
    if(shopId_key[0]==0)
    {
        if(uh_get_shop_info(buf2, buf, shop_magic)==-1)
        {
            return -1;
        }
        snprintf(shopId_key, sizeof(shopId_key), "shopId=%s&secretKey=%s", buf2, buf);
    }
    temp_hex[0]=key[0];
    temp_hex[1]=key[1];
    temp_hex[2]=0;//ȡ��һ���ֽ�
    sscanf(temp_hex,"%x",&hex); 
    temp=(unsigned char)hex;
    index=(temp^base)%14;//get offset by xor first bytes, then get index
    ptr=key+2;//����һ���ֽ�
    bd_offset=index>>1;
    for(i=0;i<6;i++)
    {
        temp_hex[0]=ptr[i<<1];
        temp_hex[1]=ptr[(i<<1)+1];
        temp_hex[2]=0;
        sscanf(temp_hex,"%x",&hex);//ԭʼ����
        temp=(unsigned char)hex;
        buf3[i]=temp^base_tab[index]^shop_magic[bd_offset+i];
    }
    snprintf(buf, sizeof(buf), "%02x%02x%02x%02x%02x%02x",buf3[0],buf3[1],buf3[2],buf3[3],buf3[4],buf3[5]);
    buf[12]=0;
    if(strncasecmp(buf,key+14,12)==0)
        return 0;
    else
        return -1;
}
/*
 * return 0, successful
 * return -1 failed
*/
static int uh_output_redirect(struct client *cl, char *url)
{
    char buf[200];
    char req_url[128];
    int i=0, len=0;
    unsigned int addr_int;
    client_info client;
    int found=0;
    unsigned char mac[6];
    unsigned char md5_buf[20];
    char client_mac[20];
    char buf2[64];
    char *page_ptr=LOCAL_CON_AUTH_PAGE;
    md5_ctx_t ctx;

    if((cl->peer_addr.family!=AF_INET)||(shm_ptr==NULL))
    {
        return -1;
    }
#if 0
    char *redirect_str="<html><head><title></title><script>(function(){window.location.href= \"http://192.168.1.1/connect/con_inet_auth.html\";})();</script></head><body></body></html>";
    cl->request.disable_chunked = true;
    cl->request.connection_close = true;
    uh_http_header(cl, 200, "OK");
    ustream_printf(cl->us, "Content-Length: %d\r\n", strlen(redirect_str));
    ustream_printf(cl->us, "<META HTTP-EQUIV=\"pragma\" CONTENT=\"no-cache\">\r\n"); 
    ustream_printf(cl->us, "<META HTTP-EQUIV=\"Cache-Control\" CONTENT=\"no-store, must-revalidate\">\r\n"); 
    ustream_printf(cl->us, "<META HTTP-EQUIV=\"expires\" CONTENT=\"Wed, 26 Feb 1997 08:21:57 GMT\">\r\n");
    ustream_printf(cl->us, "<META HTTP-EQUIV=\"expires\" CONTENT=\"0\">\r\n");
    ustream_printf(cl->us, "Content-Type: text/html; charset=utf-8\r\n\r\n");
    ustream_printf(cl->us, redirect_str);
    uh_request_done(cl);
#endif
#if 1
    if((len=uh_urlencode(req_url, sizeof(req_url), url, strlen(url)))==-1)
    {
        len=sizeof(req_url)-1;
    }
    req_url[len]=0;
    
    if(authurl_id[0]==0)
    {
        if((len=uh_urlencode(buf, sizeof(buf), WC_AUTH_URL, strlen(WC_AUTH_URL)))==-1)
        {
            return -1;
        }
        buf[len]=0;
        snprintf(authurl_id, sizeof(authurl_id), "appId=%s&authUrl=%s", WC_APPID, buf);
    }
    //if((shopId_key[0]==0)||(read_shopinfo_times>0))
    if(shopId_key[0]==0)
    {
        if(uh_get_shop_info(buf2, buf, shop_magic)==-1)
        {
            return -1;
        }
        snprintf(shopId_key, sizeof(shopId_key), "shopId=%s&secretKey=%s", buf2, buf);
        //if(read_shopinfo_times>0)
            //read_shopinfo_times--;
    }
    if(first_ssid[0]==0)
    {
        if((uh_get_ssid(buf2)==0) 
            &&((len=uh_urlencode(first_ssid, sizeof(first_ssid), buf2, strlen(buf2)))!=-1))
        {
            first_ssid[len]=0;
        }
        else
            return -1;
    }
    addr_int=ntohl(cl->peer_addr.in.s_addr);
    sem_lock();
    for(i=0; i<shm_ptr->client_num; i++)
    {
        if(shm_ptr->client[i].ip4_addr==addr_int)
        {
            memcpy(&client, &shm_ptr->client[i], sizeof(client));
            found=1;
            break;
        }
    }
    sem_unlock();
    if(found==0)
    {
        return -1;
    }
    if(hwaddr[0]==0)
    {
        if(get_dev_hwaddr(mac)==false)
        {
            return -1;
        }
        sprintf(hwaddr, "%02x%02x%02x%02x%02x%02x",
                mac[0], mac[1], mac[2],mac[3], mac[4], mac[5]);
    }
    sprintf(client_mac, "%02x:%02x:%02x:%02x:%02x:%02x", 
                            client.mac_addr[0], client.mac_addr[1], client.mac_addr[2],
                            client.mac_addr[3], client.mac_addr[4], client.mac_addr[5]);
    
    sprintf(buf2, "%s%08x%02x%02x%02x%02x%02x%02x", hwaddr, client.ip4_addr, 
            client.mac_addr[0], client.mac_addr[1], client.mac_addr[2],
            client.mac_addr[3], client.mac_addr[4], client.mac_addr[5]);
    
    md5_begin(&ctx);
    md5_hash(buf2, strlen(buf2), &ctx);
    md5_hash(CLATDM_AUTH_PASS, strlen(CLATDM_AUTH_PASS), &ctx);
    md5_end(md5_buf, &ctx);
    
    sprintf(buf, "%s%02x%02x%02x%02x%02x%02x%02x%02x", buf2,
                            md5_buf[4], md5_buf[5], md5_buf[6],md5_buf[7], 
                            md5_buf[8], md5_buf[9], md5_buf[10], md5_buf[11]);
    
    cl->request.disable_chunked = true;
    cl->request.connection_close = true;
//    uh_http_header(cl, 302, "Found");
    if(cl->request.version==UH_HTTP_VER_1_0)
        uh_http_header(cl, 302, "Moved Temporarily");
    else //UH_HTTP_VER_1_1 ignore UH_HTTP_VER_0_9
        uh_http_header(cl, 302, "Found");
    ustream_printf(cl->us, "Content-Length: 0\r\n");
    ustream_printf(cl->us, "<META HTTP-EQUIV=\"pragma\" CONTENT=\"no-cache\">\r\n"); 
    ustream_printf(cl->us, "<META HTTP-EQUIV=\"Cache-Control\" CONTENT=\"no-store, must-revalidate\">\r\n"); 
    ustream_printf(cl->us, "<META HTTP-EQUIV=\"expires\" CONTENT=\"Wed, 26 Feb 1997 08:21:57 GMT\">\r\n");
    ustream_printf(cl->us, "<META HTTP-EQUIV=\"expires\" CONTENT=\"0\">\r\n");
    
    if(access("/www/"RES_CON_AUTH_PAGE, F_OK)==0)
    {
        page_ptr=RES_CON_AUTH_PAGE;
    }
    ustream_printf(cl->us, "Location: http://%s/%s?%s&extend=%s&mac=%s&ssid=%s&%s&reqUrl=%s\r\n\r\n",
            inet_ntoa(cl->srv_addr.in), page_ptr, authurl_id, buf, client_mac, first_ssid, shopId_key, req_url);
    
    uh_request_done(cl);
    return 0;
    
#endif
#if 0
    cl->request.disable_chunked = true;
    cl->request.connection_close = true;
    uh_http_header(cl, 302, "Found");
    ustream_printf(cl->us, "Content-Length: 0\r\n");
    ustream_printf(cl->us, "Location: http://%s/connect/con_inet_auth.html\r\n\r\n",inet_ntoa(cl->srv_addr.in));
    uh_request_done(cl);
#endif    
}


static int uh_set_auth_status(struct client *cl, int *isChange, client_status cli_status)
{
    int i=0;
    struct timespec time = {0, 0};
    unsigned int addr_int;
    int found=0;

    if((cl->peer_addr.family!=AF_INET)||(shm_ptr==NULL)||(isChange==NULL))
    {
        return -1;
    }
    *isChange=0;
    addr_int=ntohl(cl->peer_addr.in.s_addr);
    clock_gettime(CLOCK_MONOTONIC, &time);
    
    sem_lock();
    for(i=0; i<shm_ptr->client_num; i++)
    {
        if(shm_ptr->client[i].ip4_addr==addr_int)
        {
            found=1;
            if((shm_ptr->client[i].status==ADD_ALLOW_RULE))
            {
                if(cli_status==AUTH_SUCCESSFUL)
                {
                    shm_ptr->client[i].status=AUTH_SUCCESSFUL;
                    shm_ptr->client[i].time_out=time.tv_sec;
                }
            }
            else if((shm_ptr->client[i].status==REDIRECT_RULE))
            {
                if(cli_status==AUTH_SUCCESSFUL)
                {
                    shm_ptr->client[i].status=AUTH_SUCCESSFUL;
                    shm_ptr->client[i].time_out=time.tv_sec;
                }
                else
                {
                    shm_ptr->client[i].status=ADD_ALLOW_RULE;
                    shm_ptr->client[i].time_out=time.tv_sec+CHECK_AUTH_TIMEOUT;
                }
                *isChange=1;
            }
            break;
        }
    }
    sem_unlock();
    return found;
}
static bool uh_check_app_url(char *url)
{
    char *ptrStart=NULL, *ptrEnd=NULL;
    char key[32];

    if(url==NULL)
        return false;
    if((ptrStart=strstr(url, "key="))==NULL)
        return false;
    ptrStart+=4;
    if((ptrEnd=strchr(ptrStart, '&'))!=NULL)
    {
        if((ptrEnd-ptrStart)==(SHOP_MAGIC_LEN+6))//check length, use 32 bytes, valid only use 26 bytes
        {
            strncpy(key, ptrStart, SHOP_MAGIC_LEN);
            key[SHOP_MAGIC_LEN]=0;
            if(uh_check_appKey(key)==0)
                return true;
        }
    }
    else
    {
        if(strlen(ptrStart)>=(SHOP_MAGIC_LEN+6))//check length, use 32 bytes, valid only use 26 bytes, may be include '\r\n' chart
        {
            strncpy(key, ptrStart, SHOP_MAGIC_LEN);
            key[SHOP_MAGIC_LEN]=0;
            if(uh_check_appKey(key)==0)
                return true;
        }
    }
    return false;
}
/*
*return 1, found, mac address is save to mac parameter
*return 0, not found,
*/
static bool uh_get_client_mac(unsigned int addr_int, unsigned char *mac)
{
    int i=0;
    bool found=false;

    if((addr_int==0)||(mac==NULL))
    {
        return found;
    }
    sem_lock();
    for(i=0; i<shm_ptr->client_num; i++)
    {
        if(shm_ptr->client[i].ip4_addr==addr_int)
        {
            found=true;
            memcpy(mac, shm_ptr->client[i].mac_addr, 6);
            break;
        }
    }
    sem_unlock();
    return found;
}

static bool is_wlanx_client(char *wlan_name, unsigned char *mac)
{
    bool found=false;
    char buf[128];
    FILE *fp=NULL;
    
    if((wlan_name==NULL)||(mac==NULL))
    {
        return false;
    }
    sprintf(buf, "iw dev %s station get %02x:%02x:%02x:%02x:%02x:%02x > "UHTTPD_WLANX_TEMP_FILE,
        wlan_name, mac[0], mac[1], mac[2],mac[3], mac[4], mac[5]);
        
    system(buf);
    fp = fopen(UHTTPD_WLANX_TEMP_FILE, "r");
    if(fp==NULL)
    {
        //my_syslog(MS_DHCP | LOG_INFO, "popen: %s failed", buf);
        unlink(UHTTPD_WLANX_TEMP_FILE);
        return false;
    }
    unlink(UHTTPD_WLANX_TEMP_FILE);
    if(fgets(buf, sizeof(buf), fp) && strstr(buf, "Station"))
    {
        found=true;
    }
    fclose(fp);
    return found;
}

static bool is_from_encrypt_ap(unsigned int addr_int)
{
    unsigned char mac[6];

    if(uh_get_client_mac(addr_int,mac)==false)
        return false;
    return is_wlanx_client(ENCRYPT_RESERVE_WLAN_INTF, mac);
}
static bool update_app_info(unsigned int addr_int)
{
    int i=0;
    struct timespec time = {0, 0};
    time_t oldest_time;
    int oldest_index;
    
    if(addr_int==0)
        return false;

    clock_gettime(CLOCK_MONOTONIC, &time);
    for(i=0; i<BS_app.num; i++)
    {
        if(BS_app.client[i].addr==addr_int){
            BS_app.client[i].time=time.tv_sec;
            return true;
        }
    }
    //not found, array is not full
    if(BS_app.num<APP_MAX_NUM){
        BS_app.client[BS_app.num].addr=addr_int;
        BS_app.client[BS_app.num].time=time.tv_sec;
        BS_app.num++;
        return true;
    }
    else
    {//array is full, override the oldest item
        oldest_time=time.tv_sec;
        oldest_index=0;
        for(i=0; i<BS_app.num; i++)
        {
            //found the oldest item
            if(BS_app.client[i].time<oldest_time)
            {
                oldest_time=BS_app.client[i].time;
                oldest_index=i;
            }
        }
        BS_app.client[oldest_index].addr=addr_int;
        BS_app.client[oldest_index].time=time.tv_sec;
        return true;
    }
}

void uh_handle_request(struct client *cl)
{
	struct http_request *req = &cl->request;
	struct dispatch_handler *d;
	char *url = blobmsg_data(blob_data(cl->hdr.head));
	char *error_handler;
	char buf[256];
	char ip_buf[32];
	char *is_success_req=NULL;
	client_status cli_status=ADD_ALLOW_RULE;
	int isChange=0, found=0;

	url = uh_handle_alias(url);

	uh_handler_run(cl, &url, false);
	if (!url)
		return;

	req->redirect_status = 200;
	
    if(strstr(url, REQUEST_CON_TOKEN) 
        || (NULL!=(is_success_req=strstr(url, REQUEST_SUCCESS_TOKEN))))
    {  
        if(NULL!=is_success_req)
            cli_status=AUTH_SUCCESSFUL;
        else
            cli_status=ADD_ALLOW_RULE;
        found=uh_set_auth_status(cl, &isChange, cli_status);
        if(found==1)
        {
            if(isChange==1)
            {
                strcpy(ip_buf, inet_ntoa(cl->peer_addr.in));
                sprintf(buf, DELETE_REDIRECT_RULE_FORMAT, ip_buf, inet_ntoa(cl->srv_addr.in));      
                system(buf);
                sprintf(buf, ADD_ALLOW_RULE_FORMAT, ip_buf);
                system(buf);
            }
            uh_output_200_OK(cl);
            return ;
        }
        else if(found==0) //not find client in share memory
        {
            uh_client_error(cl, 404, "Not Found", "The requested URL %s was not found on this server.", url);
            return ;
        }
    }
    else if(ntohl(cl->srv_addr.in.s_addr)!= req->host_ip )
    {
        if(uh_output_redirect(cl, url)!=0)
        {
            //uh_client_error(cl, 404, "Not Found", "The requested URL %s was not found on this server.", url);
            uh_client_error(cl, 502, "Bad Gateway", "The process did not produce any response");
        }
        return ;
    }
    else if(strstr(url, CLATDM_WAY)&&strstr(url, CLATDM_HTML)&&strstr(url, CLATDM_WEB_TOKEN))
    {
        char cmd_buf[128];
        if(strstr(url, "up"))
        {
            sprintf(cmd_buf,"/etc/t_gate start");
            system(cmd_buf);
            alarm(3600);
            system("/bin/close_tgate &");
            //alarm(60);
        }
        else
        {
            sprintf(cmd_buf,"/etc/t_gate stop");
            system(cmd_buf);
            system("killall close_tgate");
        }
        uh_client_error(cl, 404, "Not Found", "The requested URL %s was not found on this server.", url);
        return;
    }else if (strstr(url, APP_REG_KEYWORD))
    {
        unsigned int app_addr=ntohl(cl->peer_addr.in.s_addr);
        if(uh_check_app_url(url)&&is_from_encrypt_ap(app_addr))
        {
            update_app_info(app_addr);
            uh_output_200_OK(cl);
        }
        else
        {
            uh_client_error(cl, 404, "Not Found", "The requested URL %s was not found on this server.", url);
        }
        return;
    }
    else if (strstr(url, APP_UPLOAD_KEYWORD))
    {
        unsigned int app_addr=ntohl(cl->peer_addr.in.s_addr);
        if(uh_check_app_url(url)&&is_from_encrypt_ap(app_addr))
        {
            update_app_info(app_addr);
        }
        else
        {
            uh_client_error(cl, 404, "Not Found", "The requested URL %s was not found on this server.", url);
            return;
        }
    }
    else if (strstr(url, APP_UPLOAD_NOTE_KEYWORD))
    {
        if(uh_update_shop_json())
            uh_output_200_OK(cl);
        else
            uh_client_error(cl, 404, "Not Found", "The requested URL %s was not found on this server.", url);
        return;
    }
    if(strstr(url, IOS_JS_KEY_FILENAME) && req->isIOS)
    {
        found=uh_set_auth_status(cl, &isChange, ADD_ALLOW_RULE);
        if(found==1)
        {
            if(isChange==1)
            {
                strcpy(ip_buf, inet_ntoa(cl->peer_addr.in));
                sprintf(buf, DELETE_REDIRECT_RULE_FORMAT, ip_buf, inet_ntoa(cl->srv_addr.in));      
                system(buf);
                sprintf(buf, ADD_ALLOW_RULE_FORMAT, ip_buf);
                system(buf);
            }
        }
    }
    /*
    if((cl->request.method==UH_HTTP_MSG_POST)&&(strstr(url, "aboutshop")))
    {
        read_shopinfo_times=5;
    } */
    
	d = dispatch_find(url, NULL);
	if (d)
		return uh_invoke_handler(cl, d, url, NULL);

	if (__handle_file_request(cl, url))
		return;

	if (uh_handler_run(cl, &url, true) &&
	    (!url || __handle_file_request(cl, url)))
		return;

	req->redirect_status = 404;
	if (conf.error_handler) {
		error_handler = alloca(strlen(conf.error_handler) + 1);
		strcpy(error_handler, conf.error_handler);
		if (__handle_file_request(cl, error_handler))
			return;
	}

	uh_client_error(cl, 404, "Not Found", "The requested URL %s was not found on this server.", url);
    
}
void signal_usr1_fn(int sig)
{
    shopId_key[0]=0;
    first_ssid[0]=0;
    return;
}
