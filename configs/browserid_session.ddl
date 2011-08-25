DROP TABLE IF EXISTS browserid_session;
CREATE TABLE browserid_session (
    digest    CHAR(32),
    assertion VARCHAR(4080),
    email     VARCHAR(1024),
    created   TIMESTAMP,
    INDEX lookup (digest),
    INDEX cleanup (created)
);