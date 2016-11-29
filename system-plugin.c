#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <syslog.h>
#include <sysrepo.h>
#include <time.h>
#include <unistd.h>

// Next:
// ? Timezone
// X NTP (software specific)
// X DNS (software specific)
// X RADIUS (software specific)
//   Local users
//   Set datetime RPC
//   Restart and shutdown RPCs (done)

int hostname_cb(sr_session_ctx_t *session, const char *xpath, sr_notif_event_t event, void *private_ctx)
{
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

int sr_plugin_init_cb(sr_session_ctx_t* session, void** private_ctx)
{
    sr_subscription_ctx_t* subscription = NULL;
    int rc = SR_ERR_OK;

    rc = sr_subtree_change_subscribe(session, "/ietf-system:system/hostname", hostname_cb, NULL, 0,
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
