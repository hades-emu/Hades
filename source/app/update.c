/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#if defined(_WIN32)
# define WIN32_LEAN_AND_MEAN
# define NOMINMAX
# include <windows.h>
# include <winhttp.h>
#else
# include <curl/curl.h>
#endif

#include <mjson.h>
#include <string.h>
#include "hades.h"
#include "app/app.h"

#define UPDATE_HOST             "api.github.com"
#define UPDATE_PATH             "/repos/hades-emu/Hades/releases/latest"
#define UPDATE_TIMEOUT_MS       5000

static
bool
app_update_append_response(
    struct http_response *res,
    void const *data,
    size_t size
) {
    char *new_data;

    new_data = realloc(res->data, res->size + size + 1);
    if (!new_data) {
        return false;
    }

    memcpy(new_data + res->size, data, size);
    res->data = new_data;
    res->size += size;
    res->data[res->size] = '\0';
    return true;
}

#if defined(_WIN32)

static
bool
app_update_fetch_latest_release(
    struct http_response *res
) {
    HINTERNET session;
    HINTERNET connection;
    HINTERNET request;
    DWORD status;
    DWORD status_size;
    DWORD available;
    DWORD read;
    char buffer[4096];
    bool ok;

    ok = false;
    connection = NULL;
    request = NULL;

    session = WinHttpOpen(L"Hades/" HADES_VERSION, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        goto end;
    }

    WinHttpSetTimeouts(session, UPDATE_TIMEOUT_MS, UPDATE_TIMEOUT_MS, UPDATE_TIMEOUT_MS, UPDATE_TIMEOUT_MS);

    connection = WinHttpConnect(session, L"" UPDATE_HOST, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!connection) {
        goto end;
    }

    request = WinHttpOpenRequest(connection, L"GET", L"" UPDATE_PATH, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!request) {
        goto end;
    }

    if (
           !WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
        || !WinHttpReceiveResponse(request, NULL)
    ) {
        goto end;
    }

    status_size = sizeof(status);
    if (
           !WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX)
        || status != 200
    ) {
        goto end;
    }

    while (WinHttpQueryDataAvailable(request, &available) && available > 0) {
        if (
               !WinHttpReadData(request, buffer, min(available, sizeof(buffer)), &read)
            || !app_update_append_response(res, buffer, read)
        ) {
            goto end;
        }
    }

    ok = (res->data != NULL);

end:
    if (request) {
        WinHttpCloseHandle(request);
    }
    if (connection) {
        WinHttpCloseHandle(connection);
    }
    if (session) {
        WinHttpCloseHandle(session);
    }
    return ok;
}

#else

static
size_t
app_update_curl_write(
    char *data,
    size_t size,
    size_t nmemb,
    void *raw_res
) {
    return app_update_append_response(raw_res, data, size * nmemb) ? size * nmemb : 0;
}

static
bool
app_update_fetch_latest_release(
    struct http_response *res
) {
    CURL *curl;
    CURLcode code;

    curl = curl_easy_init();
    if (!curl) {
        return false;
    }

    // GitHub's API rejects requests without a User-Agent.
    curl_easy_setopt(curl, CURLOPT_URL, "https://" UPDATE_HOST UPDATE_PATH);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Hades/" HADES_VERSION);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)UPDATE_TIMEOUT_MS);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, app_update_curl_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, res);

    code = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    return code == CURLE_OK && res->data;
}

#endif

/*
** Return true if `latest` is newer than `current`, following semver's precedence (e.g. 1.2.0-dev < 1.2.0).
** Pre-release suffixes are compared as plain strings, which is enough for Hades' versions.
*/
static
bool
app_update_is_newer(
    char const *latest,
    char const *current
) {
    unsigned int l[3];
    unsigned int c[3];
    int l_len;
    int c_len;
    size_t i;

    if (*latest == 'v') {
        ++latest;
    }

    if (
           sscanf(latest, "%u.%u.%u%n", &l[0], &l[1], &l[2], &l_len) != 3
        || sscanf(current, "%u.%u.%u%n", &c[0], &c[1], &c[2], &c_len) != 3
    ) {
        return false;
    }

    for (i = 0; i < 3; ++i) {
        if (l[i] != c[i]) {
            return l[i] > c[i];
        }
    }

    latest += l_len;
    current += c_len;

    // A release is newer than any of its pre-releases.
    if (!*latest || !*current) {
        return !*latest && *current;
    }

    return strcmp(latest, current) > 0;
}

static
void
app_update_check_release(
    struct update_check *check
) {
    if (atomic_fetch_sub(&check->refcount, 1) == 1) {
        free(atomic_load(&check->new_version));
        free(check);
    }
}

static
void *
app_update_check(
    void *raw_check
) {
    struct update_check *check;
    struct http_response res;
    char tag[64];

    check = raw_check;
    res.data = NULL;
    res.size = 0;

    if (!app_update_fetch_latest_release(&res)) {
        hs_logln(HS_WARN, "Failed to check for updates.");
    } else if (mjson_get_string(res.data, (int)res.size, "$.tag_name", tag, sizeof(tag)) > 0) {
        hs_logln(HS_INFO, "Latest available version: %s.", tag);
        if (app_update_is_newer(tag, HADES_VERSION)) {
            atomic_store(&check->new_version, strdup(tag));
        } else {
            hs_logln(HS_INFO, "Hades is up to date.");
        }
    }

    free(res.data);
    app_update_check_release(check);
    return NULL;
}

/*
** Check, in the background, if a newer version of Hades is available on GitHub.
*/
void
app_update_check_start(
    struct app *app
) {
    struct update_check *check;
    pthread_t thread;

    check = calloc(1, sizeof(*check));
    hs_assert(check);

    // One reference for the main thread, one for the update thread.
    atomic_init(&check->refcount, 2);
    atomic_init(&check->new_version, NULL);

    if (pthread_create(&thread, NULL, app_update_check, check)) {
        free(check);
        return;
    }

    pthread_detach(thread);
    app->update_check = check;
}

/*
** Notify the user if the background check found a newer version.
*/
void
app_update_process_result(
    struct app *app
) {
    char *version;

    if (!app->update_check) {
        return;
    }

    version = atomic_exchange(&app->update_check->new_version, NULL);
    if (version) {
        app_new_notification(app, UI_NOTIFICATION_SUCCESS, "A new version of Hades is available: %s", version);
        free(version);
    }
}

/*
** Release the main thread's reference to the update check, without waiting for it to finish.
*/
void
app_update_check_cleanup(
    struct app *app
) {
    if (app->update_check) {
        app_update_check_release(app->update_check);
        app->update_check = NULL;
    }
}
