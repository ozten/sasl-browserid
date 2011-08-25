/* gcc -g `mysql_config --include --libs` mysql_main.c -o test_mysql &&  valgrind --leak-check=full ./test_mysql 23lk4j23lk4j23l4j23lj42l3kj4l23kj4 */
#include <error.h>

#include <stdio.h>
#include <mysql.h>
#include <mysql/errmsg.h>

static int check_session(const char *assertion, char *email)
{
    printf("MySQL client version: %s\n", mysql_get_client_info());
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

    int rv = 0;

    conn = mysql_init(NULL);
    if (conn == NULL) {
        error(1, 1, "Unable to mysql_init");
    }
    conn = mysql_real_connect(conn, "localhost", "root", "", "mozillians", NULL, NULL, (void *) 0);
    if (conn == NULL) {
        printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
        error(1, 1, "Unable to connect to mysql server");
    }
    mysql_real_escape_string(conn, assertion_esc, assertion, strlen(assertion));
    sprintf(select_email_esc, select_email, assertion_esc);
    printf(select_email_esc);
    printf("\n");
    if (mysql_query(conn, select_email_esc) == 0) {
        rs = mysql_store_result(conn);
        while((row = mysql_fetch_row(rs))) {
            printf("Email: %s\n", row[0]);
	    printf("\n");
            strcpy(email, row[0]);
            rv = 1;
	    
	    /* Touch session */
	    sprintf(update_session_esc, update_session, assertion_esc);
	    printf(update_session_esc);
	    printf("\n");
	    mysql_query(conn, update_session_esc);
            break;
        }
        if (rs != 0) {
            mysql_free_result(rs);
        }
    } else if (query_rs == CR_UNKNOWN_ERROR) {
        error(1, 1, "Unkown Error");
    } else if (query_rs == CR_SERVER_GONE_ERROR ||\
               query_rs == CR_SERVER_LOST) {
        error(1, 1, "Executed query, SOL");
    } else {
        printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
        error(1, 1, mysql_error(conn));
    }
    mysql_close(conn);
    return rv;
}

static int create_session(const char *assertion, const char *email)
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
        error(1, 1, "Unable to mysql_init");
    }
    conn = mysql_real_connect(conn, "localhost", "root", "", "mozillians", NULL, NULL, (void *) 0);
    if (conn == NULL) {
        printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
        error(1, 1, "Unable to connect to mysql server");
    }
    mysql_real_escape_string(conn, assertion_esc, assertion, strlen(assertion));
    mysql_real_escape_string(conn, email_esc, email, strlen(email));

    sprintf(insert_email_esc, insert_email, assertion_esc, assertion_esc, email_esc);
    printf(insert_email_esc);
    printf("\n");
    if (mysql_query(conn, insert_email_esc) == 0) {
        if (mysql_affected_rows(conn) == 1) {
            printf("Successfully created a session\n");
            rv = 1;
        } else {
            printf("WARN: %u rows affected, expected 1", mysql_affected_rows(conn));
        }
    } else if (query_rs == CR_UNKNOWN_ERROR) {
        error(1, 1, "Unkown Error");
    } else if (query_rs == CR_SERVER_GONE_ERROR ||\
               query_rs == CR_SERVER_LOST) {
        error(1, 1, "Executed query, SOL");
    } else {
        printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
        error(1, 1, mysql_error(conn));
    }
    mysql_close(conn);
    return rv;
}

int
main (int argc, char **argv) {
    char assertion[4080]; /* = "lskdajfljk23l4j23lkj423lkj423klj4l23kj423klj4jkl423lj";*/
    char email[1024];
    strcpy(assertion, argv[1]);
    /* given an assertion, do we know the email address? */
    /* yes - return email 
       no - no session yet
       error - something went horribly wrong ;) - Handle errors directly, quit plugin
    */
    if (check_session(assertion, &email) == 1) {
        printf("Got email=%s\n", email);
        /* set user into the session or whatever... */
    } else {
        /* New Session! */
        /* do auth or whatever */
        create_session(assertion, "baz@boz.com");
    }
    
}
