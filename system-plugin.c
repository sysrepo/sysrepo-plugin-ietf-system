#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <syslog.h>
#include <sysrepo.h>
#include <time.h>
#include <unistd.h>

typedef void (*sighandler_t)(int);

// Next:
// ? Timezone
// X NTP (software specific)
// X DNS (software specific)
// X RADIUS (software specific)
//   Local users
//   Set datetime RPC
//   Restart and shutdown RPCs (done)


int exec_wrapper_with_args(char * const args[])
{
    /* We have to ensure that SIGCHLD handler is not SIG_IGN; if it is a SIG_IGN, then waitpid() won't work */
    sighandler_t orig_sig_chld = signal(SIGCHLD, SIG_DFL);
    pid_t pid = fork();
    if (pid == -1) {
        syslog(LOG_ERR, "fork failed");
        signal(SIGCHLD, orig_sig_chld);
        return SR_ERR_INTERNAL;
    } else if (pid == 0) {
        execv(args[0], args);
        exit(EXIT_FAILURE);
    } else {
        int wstatus;
        while (waitpid(pid, &wstatus, 0) == -1) {
            if (errno == EINTR)
                continue;
            signal(SIGCHLD, orig_sig_chld);
            syslog(LOG_ERR, "waitpid error: %d", errno);
            return SR_ERR_INTERNAL;
        }
        signal(SIGCHLD, orig_sig_chld);
        if (WIFSIGNALED(wstatus)) {
            int res = WTERMSIG(wstatus);
            syslog(LOG_ERR, "%s killed by signal %d", args[0], res);
            return SR_ERR_INTERNAL;
        }
        int exit_status = WEXITSTATUS(wstatus);
        if (!WIFEXITED(wstatus)) {
            syslog(LOG_ERR, "%s died, exit status %d", args[0], exit_status);
            return SR_ERR_INTERNAL;
        }
        if (exit_status) {
            syslog(LOG_ERR, "%s exit status %d", args[0], exit_status);
            return SR_ERR_INTERNAL;
        }
        return SR_ERR_OK;
    }
}

static const char * sr_event_to_string(const sr_notif_event_t event)
{
    switch (event) {
    case SR_EV_ABORT:
        return "abort";
    case SR_EV_APPLY:
        return "apply";
    case SR_EV_ENABLED:
        return "enabled";
    case SR_EV_VERIFY:
        return "verify";
    }
    assert(false);
    return "unknown";
}

int hostname_cb(sr_session_ctx_t *session, const char *xpath, sr_notif_event_t event, void *private_ctx)
{
    syslog(LOG_DEBUG, "%s: event %s, xpath %s", __func__, sr_event_to_string(event), xpath);
    if (event == SR_EV_ABORT) {
        return SR_ERR_OK;
    }

    sr_val_t* value = NULL;
    int rc = SR_ERR_OK;
    const char* hostname;
    rc = sr_get_item(session, "/ietf-system:system/hostname", &value);
    if (SR_ERR_NOT_FOUND == rc) {
        hostname = "default";
    } else if (SR_ERR_OK != rc) {
        syslog(LOG_DEBUG, "error by retrieving configuration: %s", sr_strerror(rc));
        return rc;
    } else {
        assert(value->type == SR_STRING_T);
        hostname = value->data.string_val;
    }

    if (event == SR_EV_VERIFY) {
        // TODO: do we want some syntax validation?
    } else {
        syslog(LOG_DEBUG, "Setting hostname to %s\n", hostname);
        // TODO: take a systemd detour for persistency?
        sethostname(hostname, strlen(hostname));
    }

    sr_free_val(value);
    return SR_ERR_OK;
}

#define TIME_BUF_SIZE 64
static char boottime[TIME_BUF_SIZE];

static void get_time_as_string(char (*out)[TIME_BUF_SIZE])
{
    time_t curtime = time(NULL);
    strftime(*out, sizeof(*out), "%Y-%m-%dT%H:%M:%S%z", localtime(&curtime));
    // timebuf ends in +hhmm but should be +hh:mm
    memmove(*out + strlen(*out) - 1, *out + strlen(*out) - 2, 3);
    (*out)[strlen(*out) - 3] = ':';
}

static int clock_dp_cb(const char* xpath, sr_val_t** values, size_t* values_cnt, void* private_ctx)
{
    char buf[TIME_BUF_SIZE];
    if (!private_ctx) {
        get_time_as_string(&buf);
    } else {
        strcpy(buf, private_ctx);
    }

    sr_val_t* value = calloc(1, sizeof(*value));
    if (!value) {
        return SR_ERR_NOMEM;
    }

    value->xpath = strdup(xpath);
    if (!value->xpath) {
        free(value);
        return SR_ERR_NOMEM;
    }
    value->type = SR_STRING_T;
    value->data.string_val = strdup(buf);
    if (!value->data.string_val) {
        free(value->xpath);
        free(value);
        return SR_ERR_NOMEM;
    }

    *values = value;
    *values_cnt = 1;
    return SR_ERR_OK;
}

enum platform_field {
    PF_OS_NAME,
    PF_OS_RELEASE,
    PF_OS_VERSION,
    PF_MACHINE
};

static int platform_dp_cb(const char* xpath, sr_val_t** values, size_t* values_cnt, void* private_ctx)
{
    struct utsname data;
    uname(&data);
    const char* str;
    switch ((enum platform_field)private_ctx) {
    case PF_OS_NAME:
        str = data.sysname;
        break;
    case PF_OS_RELEASE:
        str = data.release;
        break;
    case PF_OS_VERSION:
        str = data.version;
        break;
    case PF_MACHINE:
        str = data.machine;
        break;
    default:
        syslog(LOG_DEBUG, "Unrecognized context value for %s", __func__);
        return SR_ERR_NOT_FOUND;
    }

    sr_val_t* value = calloc(1, sizeof(*value));
    if (!value) {
        return SR_ERR_NOMEM;
    }

    value->xpath = strdup(xpath);
    if (!value->xpath) {
        free(value);
        return SR_ERR_NOMEM;
    }
    value->type = SR_STRING_T;
    value->data.string_val = strdup(str);
    if (!value->data.string_val) {
        free(value->xpath);
        free(value);
        return SR_ERR_NOMEM;
    }

    *values = value;
    *values_cnt = 1;
    return SR_ERR_OK;
}

int exec_rpc_cb(const char* xpath, const sr_val_t* input, const size_t input_cnt, sr_val_t** output, size_t* output_cnt, void* private_ctx)
{
    system(private_ctx);
    return SR_ERR_OK;
}

#define TIMEDATECTL_BIN "/usr/bin/timedatectl"

int timezone_name_cb(sr_session_ctx_t *session, const char *xpath, sr_notif_event_t event, void *private_ctx)
{
    syslog(LOG_DEBUG, "%s: event %s, xpath %s", __func__, sr_event_to_string(event), xpath);
    if (event == SR_EV_ABORT) {
        return SR_ERR_OK;
    }

    sr_val_t* value = NULL;
    int rc = SR_ERR_OK;
    const char *timezone = NULL;
    rc = sr_get_item(session, "/ietf-system:system/clock/timezone-name", &value);
    if (SR_ERR_NOT_FOUND == rc) {
        timezone = "UTC";
    } else if (SR_ERR_OK != rc) {
        syslog(LOG_DEBUG, "Error retrieving timezone-name: %s", sr_strerror(rc));
        return rc;
    } else {
        assert(value->type == SR_STRING_T);
        timezone = value->data.string_val;
    }

    if (event == SR_EV_VERIFY) {
        char fname[PATH_MAX+1];
        snprintf(fname, sizeof(fname), "/usr/share/zoneinfo/%s", timezone);
        if (access(fname, F_OK)) {
            syslog(LOG_INFO, "Rejecting invalid timezone %s", timezone);
            rc = SR_ERR_VALIDATION_FAILED;
            sr_set_error(session, "Requested timezone not found", xpath);
            goto cleanup;
        }
        if (access(TIMEDATECTL_BIN, X_OK)) {
            syslog(LOG_ERR, TIMEDATECTL_BIN " not available");
            rc = SR_ERR_VALIDATION_FAILED;
            sr_set_error(session, TIMEDATECTL_BIN " not available", xpath);
            goto cleanup;
        }
        rc = SR_ERR_OK;
    } else {
        syslog(LOG_DEBUG, "Setting timezone to %s", timezone);
        char * args[] = {TIMEDATECTL_BIN, "set-timezone", (char *)timezone, NULL};
        rc = exec_wrapper_with_args(args);
    }
cleanup:
    sr_free_val(value);
    return rc;
}

int sr_plugin_init_cb(sr_session_ctx_t* session, void** private_ctx)
{
    sr_subscription_ctx_t* subscription = NULL;
    int rc = SR_ERR_OK;

    rc = sr_subtree_change_subscribe(session, "/ietf-system:system/hostname", hostname_cb, NULL, 0,
                                     SR_SUBSCR_CTX_REUSE | SR_SUBSCR_EV_ENABLED, &subscription);
    if (SR_ERR_OK != rc)
        goto error;

    rc = sr_subtree_change_subscribe(session, "/ietf-system:system/clock/timezone-name", timezone_name_cb, NULL, 0,
                                     SR_SUBSCR_CTX_REUSE | SR_SUBSCR_EV_ENABLED, &subscription);
    if (SR_ERR_OK != rc)
        goto error;

    get_time_as_string(&boottime);

    rc = sr_dp_get_items_subscribe(session, "/ietf-system:system-state/clock/current-datetime", clock_dp_cb, NULL, SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc)
        goto error;

    rc = sr_dp_get_items_subscribe(session, "/ietf-system:system-state/clock/boot-datetime", clock_dp_cb, boottime, SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc)
        goto error;

    rc = sr_dp_get_items_subscribe(session, "/ietf-system:system-state/platform/os-name", platform_dp_cb, (void*)PF_OS_NAME, SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc)
        goto error;

    rc = sr_dp_get_items_subscribe(session, "/ietf-system:system-state/platform/os-release", platform_dp_cb, (void*)PF_OS_RELEASE, SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc)
        goto error;

    rc = sr_dp_get_items_subscribe(session, "/ietf-system:system-state/platform/os-version", platform_dp_cb, (void*)PF_OS_VERSION, SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc)
        goto error;

    rc = sr_dp_get_items_subscribe(session, "/ietf-system:system-state/platform/machine", platform_dp_cb, (void*)PF_MACHINE, SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc)
        goto error;

    rc = sr_rpc_subscribe(session, "/ietf-system:system-restart", exec_rpc_cb, "shutdown -r now", SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc)
        goto error;
    rc = sr_rpc_subscribe(session, "/ietf-system:system-shutdown", exec_rpc_cb, "shutdown -h now", SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc)
        goto error;

    syslog(LOG_DEBUG, "plugin initialized successfully");

    /* set subscription as our private context */
    *private_ctx = subscription;

    return SR_ERR_OK;

error:
    syslog(LOG_ERR, "plugin initialization failed: %s", sr_strerror(rc));
    sr_unsubscribe(session, subscription);
    return rc;
}

void sr_plugin_cleanup_cb(sr_session_ctx_t* session, void* private_ctx)
{
    /* subscription was set as our private context */
    sr_unsubscribe(session, private_ctx);

    syslog(LOG_DEBUG, "plugin cleanup finished");
}
