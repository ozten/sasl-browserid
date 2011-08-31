#include <config.h>

#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include <mysql.h>
#include <mysql/errmsg.h>

#include <session.h>

/**
 * Checks for an active session based on the given assertion.
 * If a session is active, email will be populated.
 * returns bool YES/NO
 */
int check_session(const char *assertion, char *email)
{
	syslog(LOG_DEBUG, "MySQL client version: %s\n", mysql_get_client_info());
        MYSQL *conn;
        int query_rs;
        int num_rs;
        MYSQL_RES *rs;
        MYSQL_ROW row;

        char assertion_esc[300];
        char *select_email =
            "SELECT email FROM browserid_session WHERE digest = MD5('%s')";
        char select_email_esc[1024];

        char *update_session = "UPDATE browserid_session SET created = NOW() WHERE digest = MD5('%s')";
        char update_session_esc[1024];

        int rv = 0; /* TODO use TRUE/FALSE bool */

        conn = mysql_init(NULL);
        if (conn == NULL) {
            syslog(LOG_EMERG, "Unable to mysql_init, this can't end well.");
        }
        conn = mysql_real_connect(conn, "localhost", "root", "", "mozillians", (int)NULL, NULL, 0);
        if (conn == NULL) {
                syslog(LOG_EMERG, "Unable to connect to mysql server");
                syslog(LOG_EMERG, "Error %u: %s", mysql_errno(conn), mysql_error(conn));
        }
        mysql_real_escape_string(conn, assertion_esc, assertion, strlen(assertion));
        sprintf(select_email_esc, select_email, assertion_esc);
        syslog(LOG_DEBUG, "Sending %s", select_email_esc);
        if (mysql_query(conn, select_email_esc) == 0) {
                rs = mysql_store_result(conn);
                while((row = mysql_fetch_row(rs))) {
                        syslog(LOG_DEBUG, "msyql email: %s", row[0]);
                        strcpy(email, row[0]);
                        rv = 1;

                        /* Touch session */
                        sprintf(update_session_esc, update_session, assertion_esc);
                        syslog(LOG_DEBUG, "Sending %s", update_session_esc);
                        mysql_query(conn, update_session_esc);
                        break;
                }
                if (rs != 0) {
                        mysql_free_result(rs);
                }
        } else if (query_rs == CR_UNKNOWN_ERROR) {
                syslog(LOG_ERR, "Unkown Error");
        } else if (query_rs == CR_SERVER_GONE_ERROR ||  \
                   query_rs == CR_SERVER_LOST) {
                syslog(LOG_ERR, "Lost connection to MySQL");
        } else {
                syslog(LOG_ERR, "Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
        }
        mysql_close(conn);
        return rv;
}

int create_session(const char *assertion, const char *email)
{
        MYSQL *conn;
        int query_rs;
        int num_rs;
        MYSQL_RES *rs;
        MYSQL_ROW row;

        char assertion_esc[300];
        char email_esc[300];
        char *insert_email =
            "INSERT INTO browserid_session (digest, assertion, email) VALUES (MD5('%s'), '%s', '%s')";
        char insert_email_esc[1024];
        int rv = 0;

        conn = mysql_init(NULL);
        if (conn == NULL) {
                syslog(LOG_EMERG, "Unable to mysql_init");
                return 0;
        }
        conn = mysql_real_connect(conn, "localhost", "root", "", "mozillians", (int)NULL, NULL, 0);
        if (conn == NULL) {
                syslog(LOG_EMERG, "Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
                syslog(LOG_EMERG, "Unable to connect to mysql server");
                return 0;
        }
        mysql_real_escape_string(conn, assertion_esc, assertion, strlen(assertion));
        mysql_real_escape_string(conn, email_esc, email, strlen(email));

        sprintf(insert_email_esc, insert_email, assertion_esc, assertion_esc, email_esc);
        syslog(LOG_DEBUG, "Sending %s", insert_email_esc);
        if (mysql_query(conn, insert_email_esc) == 0) {
                if (mysql_affected_rows(conn) == 1) {
                        syslog(LOG_DEBUG, "Successfully created a session\n");
                        rv = 1;
                } else {
                        syslog(LOG_WARNING, "WARN: %llu rows affected, expected 1", mysql_affected_rows(conn));
                }
        } else if (query_rs == CR_UNKNOWN_ERROR) {
		syslog(LOG_ERR, "Unkown Error");
	} else if (query_rs == CR_SERVER_GONE_ERROR ||	\
		   query_rs == CR_SERVER_LOST) {
		syslog(LOG_ERR, "Lost Mysql Connection");
	} else {
		syslog(LOG_ERR, "Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
	}
	mysql_close(conn);
	return rv;
}
