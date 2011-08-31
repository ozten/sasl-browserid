<?php
/* Run this via the commandline (apt-get install php5-cli) */

if ($argc != 2) {
    echo "Usage: " . $argv[0] . " some-long-assertion-string from http://localhost:8001/browserid_debug.html\n";
} else {
    $conn = ldap_connect("ldap://:1389/")
          or die("Failed to connect to LDAP server.");

    echo "Connected to LDAP server.<br>\n";

    ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3);   
    ldap_set_option($conn, LDAP_OPT_REFERRALS, 0);
  


    $result = ldap_sasl_bind($conn, NULL, '', 'BROWSER-ID', NULL, 'localhost:8001', $argv[1])
        or die("Failed to BROWSER-ID bind.<br />");

    $rs = ldap_search($conn, 'ou=people,dc=mozillians,dc=org',
                   '(uid=*1@*)', array('displayName', 'mail'));
    $data = ldap_get_entries($conn, $rs);
    $vouched = FALSE;
    for ($i=0; $i < $data["count"]; $i++) {
        echo $data[$i]['dn']. ' ';
        if (array_key_exists('displayName', $data[$i])) echo $data[$i]['displayName'] . ' ';
        if (array_key_exists('mail', $data[$i])) {
            $vouched = TRUE;
            echo $data[$i]['mail'];
        }
        echo "\n";
    }

    if (!$vouched) {
        echo "User isn't vouched\n";
    }
}
?>