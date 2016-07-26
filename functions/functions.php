<?php /**
 * @author Bill Minozzi
 * @copyright 2016
 */

function reportattacks_do_report()
{
    
    global $wpdb, $reportattacks_server, $reportattacks_whitelist;
    
   
    $table_name = $wpdb->prefix . "reportattacks_loginlog";
    $charset_collate = $wpdb->get_charset_collate();
    $service = 'wp-bruteforce';

    $minimo = 6;

    $reportattacks_my_blocklist_server = trim(get_site_option('reportattacks_my_blocklist_server', ''));
    $reportattacks_my_blocklist_api = trim(get_site_option('reportattacks_my_blocklist_api', ''));
    $reportattacks_radio_report_attacks = trim(get_site_option('reportattacks_radio_report_attacks', ''));


    if ($reportattacks_radio_report_attacks <> 'yes')
        return;


    $query = "select * from " . $table_name . " WHERE reported <>  'yes' 
             GROUP BY IP
             HAVING COUNT( * ) > 5 ";

    $result = $wpdb->get_results($query);

    $count = $wpdb->num_rows;
  //  $count = count($result);


    if ($count < 1)
        return;

    foreach ($result as $row) {
        $reportattacks_ip = $row->ip;
        break;
    }
    
    // Double check if is whitelisted...
    if (reportattacks_whitelisted($reportattacks_ip, $reportattacks_whitelist)) {
        return;
    }   
    

    $query = "select * from " . $table_name . " WHERE reported <>  'yes' 
             and ip = '".$reportattacks_ip."'";


    $result = $wpdb->get_results($query);

    $count = count($result);

    if ($count < 6)
        return;

  

    $logs = 'Here more information about ' . $reportattacks_ip;
    $logs .= chr(13) . chr(10);
    $logs .= 'Our Server: ' . $reportattacks_server;
    $logs .= chr(13) . chr(10);

    $logs .= 'Service: ' . $service;
    $logs .= chr(13) . chr(10);

    foreach ($result as $row) {
        $logs .= "----------------------------------";
        $logs .= chr(13) . chr(10);
        $logs .= "Time: " . $row->time . "  ";
        $logs .= chr(13) . chr(10);
        $logs .= "User: " . $row->user . "  ";
        $logs .= chr(13) . chr(10);
        $logs .= "User Agent: " . $row->ua . "  ";
        $logs .= chr(13) . chr(10);
        $logs .= "URL: " . $row->url . "  ";
        $logs .= chr(13) . chr(10);
        $logs .= "----------------------------------";
    }


    $logs = urlencode($logs);


    $url = "https://www.blocklist.de/de/httpreports.html";
    $domain_name = get_site_url();
    $urlParts = parse_url($domain_name);
    $domain_name = preg_replace('/^www\./', '', $urlParts['host']);


    $response = wp_remote_post($url, array(
        'method' => 'POST',
        'timeout' => 15,
        'redirection' => 5,
        'httpversion' => '1.0',
        'blocking' => true,
        'headers' => array(),
        'body' => array(
            'a' => 'b',
            'server' => $reportattacks_my_blocklist_server,
            'apikey' => $reportattacks_my_blocklist_api,
            'ip' => $reportattacks_ip,
            'service' => 'wp-bruteforce',
            'format' => 'php',
            'logs' => $logs),
        'cookies' => array()));


    if (is_wp_error($response)) {
        // $error_message = $response->get_error_message();
        // echo "Something went wrong: $error_message";
    } else {
        $query = "UPDATE " . $table_name . " set reported = 'yes' where ip = '" . $reportattacks_ip . "'";
        $r = $wpdb->get_results($query);
    }


/*
  //Debug
    $email_from = 'wordpress@' . $reportattacks_server;

    $headers = 'MIME-Version: 1.0' . "\r\n";
    $headers .= 'Content-type: text/html; charset=iso-8859-1' . "\r\n";

    $headers .= "From: " . $email_from . "\r\n 'Reply-To: xxxxxxxxxx@gmail.com' \r\n" .
        'X-Mailer: PHP/' . phpversion();

    $to = 'xxxxxxxxx@gmail.com';
    $subject = 'Cron at: ' . $reportattacks_server;

    wp_mail($to, $subject, $logs, $headers, '');

*/

}

function reportattacks_my_deactivation()
{
    wp_clear_scheduled_hook('reportattacks_my_hourly_event');
}


if (is_admin()) {
    if (isset($_GET['page'])) {
        $page = $_GET['page'];
        if ($page == 'report-attacks' or $page == 'reportattacks_getapi' or $page == 'my-custom-submenu-page') 
        {
            add_filter('contextual_help', 'reportattacks_contextual_help', 10, 3);

            function reportattacks_contextual_help($contextual_help, $screen_id, $screen)
            {

                $myhelp = '<br> Improve system security and report login brute force attack.';
                $myhelp .= '<br />Read the StartUp guide at Report Attacks Settings page.';
                $myhelp .= '<br />Visit the <a href="http://reportattacks.com" target="_blank">plugin site</a> for more details.';

                $screen->add_help_tab(array(
                    'id' => 'ra-overview-tab',
                    'title' => __('Overview', 'reportattacks'),
                    'content' => '<p>' . $myhelp . '</p>',
                    ));
                return $contextual_help;
            }

        }
    }

}
function reportattacks_whitelisted($reportattacks_ip, $areportattacks_whitelist)
{

    for ($i = 0; $i < count($areportattacks_whitelist); $i++) {


        if (trim($areportattacks_whitelist[$i]) == trim($reportattacks_ip))
            return 1;

    }
    return 0;

}

function reportattacks_failed_login($user_login)
{

    global $reportattacks_whitelist;
    global $reportattacks_radio_report_all_logins;
    global $reportattacks_ip;
    global $reportattacks_admin_email;


    if (reportattacks_whitelisted($reportattacks_ip, $reportattacks_whitelist)) {
        return;
    }


    if ($reportattacks_radio_report_all_logins == '1') {


        $dt = date("Y-m-d H:i:s");
        $dom = $_SERVER['SERVER_NAME'];

        $msg = 'This email was sent from your website ' . $dom .
            ' by the ReportAttacks plugin. <br> ';

        $msg .= 'Date : ' . $dt . '<br>';
        $msg .= 'Ip: ' . $reportattacks_ip . '<br>';
        $msg .= 'Domain: ' . $dom . '<br>';
        $msg .= 'Role: ' . $user_login;
        $msg .= '<br>';
        $msg .= 'Failed login';


        $email_from = 'wordpress@' . $dom;

        $headers = 'MIME-Version: 1.0' . "\r\n";
        $headers .= 'Content-type: text/html; charset=iso-8859-1' . "\r\n";

        $headers .= "From: " . $email_from . "\r\n" . 'Reply-To: ' . $user_login . "\r\n" .
            'X-Mailer: PHP/' . phpversion();

        $to = $reportattacks_admin_email;
        $subject = 'Failed Login at: ' . $dom;

        wp_mail($to, $subject, $msg, $headers, '');
    }


    

    reportattacks_add_try($reportattacks_ip, $user_login);
    return;

}


function reportattacks_add_try($reportattacks_ip, $user)
{

    global $wpdb;
    $table_name = $wpdb->prefix . "reportattacks_loginlog";
    $charset_collate = $wpdb->get_charset_collate();


    $reportattacks_record_active = get_site_option('reportattacks_record_active', '0');

    if ($reportattacks_record_active <> '1')
        return;

    $time = time();
    $time = date("Y-m-d H:m:s", $time);


    $ua = sanitize_text_field(trim($_SERVER['HTTP_USER_AGENT']));

    if (substr($ua, 0, 6) == 'Parser')
        $ua = "Unknow User Agent";

    $url = esc_url($_SERVER['REQUEST_URI']);


    if (isset($_SERVER['HTTP_REFERER'])) {
        $referrer = esc_url($_SERVER['HTTP_REFERER']);
    } else
        $referrer = '';
   
   
    // %d (integer), %f (float), and %s (string).
    $r = $wpdb->query($wpdb->prepare("INSERT INTO " . $table_name .
        " (time, ip, user, ua, url, referrer) 
        VALUES ( %s, %s, %s, %s, %s, %s)", array(
        $time,
        $reportattacks_ip,
        $user,
        $ua,
        $url,
        $referrer)));

    return $r;
}


function reportattacks_findip()
{

    $reportattacks_ip = '';

    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $reportattacks_ip = $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $reportattacks_ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    } else {
        $reportattacks_ip = $_SERVER['REMOTE_ADDR'];
    }

    $reportattacks_ip = trim($reportattacks_ip);


    if (!empty($reportattacks_ip) and reportattacks_validate_ip($reportattacks_ip))
        return $reportattacks_ip;
    else
        return 'unknow';
}


function reportattacks_create_db()
{
    global $wpdb;
    require_once (ABSPATH . 'wp-admin/includes/upgrade.php');
    // creates my_table in database if not exists
    $table = $wpdb->prefix . "reportattacks_loginlog";
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE IF NOT EXISTS $table (
          `id` int(11) NOT NULL AUTO_INCREMENT,
          `time` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00' ON UPDATE CURRENT_TIMESTAMP,
          `ip` varchar(30) NOT NULL,
          `user` varchar(100) NOT NULL,
          `ua` text NOT NULL,
          `url` text NOT NULL,
          `referrer` text NOT NULL,
          `reported` varchar(3) NOT NULL,
          `flag` char(1) NOT NULL,
    UNIQUE (`id`)
    ) $charset_collate;";


    dbDelta($sql);

}

function reportattacks_plugin_was_activated()
{
    global $wp_sbb_blacklist;

    reportattacks_create_db();
    reportattacks_addmyip();
    wp_schedule_event(current_time('timestamp'), 'hourly', 'reportattacks_my_hourly_event');
}

function reportattacks_addmyip()
{

    $reportattacks_whitelist = trim(get_site_option('reportattacks_whitelist', ''));
    if (empty($reportattacks_whitelist))
        add_site_option('reportattacks_whitelist', reportattacks_findip());

} 


function reportattacks_validate_ip($reportattacks_ip)
{
    if (filter_var($reportattacks_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return false;
    }
    return true;
}

function reportattacks_email_display()
    { ?>
        My WordPress user email:
        <br />
        <input type="text" id="reportattacks_myemail" name="reportattacks_myemail" value="" placeholder="" size="100" />
        <br />
        <?     
    }
    
function reportattacks_validate_email_field($user, $password)
    {
        global $reportattacks_myemail;
        

        if (!is_email($reportattacks_myemail))
            return new WP_Error('wrong_email', 'Please, fill out the email field!');
        else
           {
                
                // The Query
                $user_query = new WP_User_Query( array ( 'orderby' => 'registered', 'order' => 'ASC' ) );
                // User Loop
                if ( ! empty( $user_query->results ) ) {
                	foreach ( $user_query->results as $user ) {
                        
                        if(strtolower(trim($user->user_email)) == $reportattacks_myemail )
                                 return $user;
    
                	}
                } else {
                	// echo 'No users found.';
                }
                   
                    return new WP_Error( 'wrong_email', 'email not found!');
     
            
           } 
            
            
            return $user;

}

?>