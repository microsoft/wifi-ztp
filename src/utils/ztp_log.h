
#ifndef __ZTP_LOG_H__
#define __ZTP_LOG_H__

#include <syslog.h>
#include <systemd/sd-journal.h>

/**
 * @brief Macros for systemd journal log prefixes. These can be used to prefix
 * printf/fprintf format strings which journald will use to catergorize the log
 * message.
 *
 *  Eg. printf(SYSTEMD_LOG_PRIORIRT_ALERT "system shutting down!");
 */
#define SYSTEMD_LOG_PRIORITY_EMERGENCY "<0>"
#define SYSTEMD_LOG_PRIORITY_ALERT "<1>"
#define SYSTEMD_LOG_PRIORITY_CRITICAL "<2>"
#define SYSTEMD_LOG_PRIORITY_ERROR "<3>"
#define SYSTEMD_LOG_PRIORITY_WARNING "<4>"
#define SYSTEMD_LOG_PRIORITY_NOTICE "<5>"
#define SYSTEMD_LOG_PRIORITY_INFORMATIONAL "<6>"
#define SYSTEMD_LOG_PRIORITY_DEBUG "<7>"

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif //__clang__

/**
 * @brief Macro to help build component log macros below.
 */
#define __ZLOG__(prio, fmt, ...) sd_journal_print(LOG_##prio, (fmt), ##__VA_ARGS__)

/**
 * @brief Wrappers for systemd journal logging. Must be macros to retain source
 * line logging.
 */
#define zlog_panic(fmt, ...) __ZLOG__(EMERG, (fmt), ##__VA_ARGS__)
#define zlog_alert(fmt, ...) __ZLOG__(ALERT, (fmt), ##__VA_ARGS__)
#define zlog_critical(fmt, ...) __ZLOG__(CRIT, (fmt), ##__VA_ARGS__)
#define zlog_error(fmt, ...) __ZLOG__(ERR, (fmt), ##__VA_ARGS__)
#define zlog_warning(fmt, ...) __ZLOG__(WARNING, (fmt), ##__VA_ARGS__)
#define zlog_notice(fmt, ...) __ZLOG__(NOTICE, (fmt), ##__VA_ARGS__)
#define zlog_info(fmt, ...) __ZLOG__(INFO, (fmt), ##__VA_ARGS__)
#define zlog_debug(fmt, ...) __ZLOG__(DEBUG, (fmt), ##__VA_ARGS__)

/**
 * @brief Short-form aliases for above macros.
 */
#define zpanic zlog_panic
#define zalert zlog_alert
#define zcrit zlog_critical
#define zerr zlog_error
#define zwarn zlog_warning
#define znotify zlog_notify
#define zinfo zlog_info
#define zdbg zlog_debug

/**
 * @brief Helper macros for logging interface-specific messages. Will prefix
 * each message with '[<ifname>]'.
 */
#define zlog_if(_prio, _if, _fmt, ...) zlog_##_prio("[%s] " _fmt, _if, ##__VA_ARGS__)
#define zlog_panic_if(_if, _fmt, ...) zlog_if(panic, _if, _fmt, ##__VA_ARGS__)
#define zlog_alert_if(_if, _fmt, ...) zlog_if(alert, _if, _fmt, ##__VA_ARGS__)
#define zlog_critical_if(_if, _fmt, ...) zlog_if(critical, _if, _fmt, ##__VA_ARGS__)
#define zlog_error_if(_if, _fmt, ...) zlog_if(error, _if, _fmt, ##__VA_ARGS__)
#define zlog_warning_if(_if, _fmt, ...) zlog_if(warning, _if, _fmt, ##__VA_ARGS__)
#define zlog_notice_if(_if, _fmt, ...) zlog_if(notice, _if, _fmt, ##__VA_ARGS__)
#define zlog_info_if(_if, _fmt, ...) zlog_if(info, _if, _fmt, ##__VA_ARGS__)
#define zlog_debug_if(_if, _fmt, ...) zlog_if(debug, _if, _fmt, ##__VA_ARGS__)

#ifdef __clang__
#pragma clang diagnostic pop
#endif //__clang__

#endif //__ZTP_LOG_H__
