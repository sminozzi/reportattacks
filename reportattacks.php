<?php /*
Plugin Name: ReportAttacks 
Plugin URI: http://ReportAttacks.com
Description: Report login brute force attacks and improve login security.
Version: 1.4
Text Domain: reportattacks
Domain Path: /language
Author: Bill Minozzi
Author URI: http://ReportAttacks.com
License:     GPL2
Copyright (c) 2016 Bill Minozzi

 
ReportAttacks is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
any later version.
 
BoatDealer is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
 
You should have received a copy of the GNU General Public License
along with BoatDealer. If not, see {License URI}.


Permission is hereby granted, free of charge subject to the following conditions:

The above copyright notice and this FULL permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/



if (!defined('ABSPATH'))
    exit; // Exit if accessed directly

define('ReportAttacks', '1.4' );
define('REPORTATTACKSPATH', plugin_dir_path(__file__) );
define('REPORTATTACKSURL', plugin_dir_url(__file__));
define('REPORTATTACKSDOMAIN', get_site_url() );
$reportattacks_server = $_SERVER['SERVER_NAME'];


// Add settings link on plugin page
function ReportAttacks_plugin_settings_link($links) { 
  $settings_link = '<a href="options-general.php?page=report-attacks">Settings</a>'; 
  array_unshift($links, $settings_link); 
  return $links; 
}

$reportattacks_plugin = plugin_basename(__FILE__); 
add_filter("plugin_action_links_$reportattacks_plugin", 'ReportAttacks_plugin_settings_link' );


require_once(REPORTATTACKSPATH . "settings/load-plugin.php");
require_once(REPORTATTACKSPATH . "settings/options/plugin_options_tabbed.php");
require_once(REPORTATTACKSPATH . "functions/functions.php");
require_once(ABSPATH . 'wp-includes/pluggable.php');
require_once(REPORTATTACKSPATH . 'includes/get-api-key/getapikey.php');


$reportattacks_ip = trim(reportattacks_findip());

if(!empty($_POST["reportattacks_myemail"]))
  {$reportattacks_myemail = $_POST["reportattacks_myemail"];}
else
  {$reportattacks_myemail = '';}


$reportattacks_admin_email = trim(get_option( 'reportattacks_my_email' ));
if( ! empty($reportattacks_admin_email)) {
    if ( ! is_email($reportattacks_admin_email)) {

        $reportattacks_admin_email = '';
        update_option('reportattacks_my_email', '');

    }
}

if(empty($reportattacks_admin_email))
     $reportattacks_admin_email = get_option( 'admin_email' ); 
     

if ( ! class_exists( 'WP_List_Table' ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

require dirname( __FILE__ ) . '/includes/list-tables/class-reportattacks-list-table.php';


    
    
add_action( 'admin_menu', 'reportattacks_add_menu_items' );

function reportattacks_add_menu_items() {
    add_submenu_page(
        'report-attacks', // $parent_slug
        'Failed Logins Table', // string $page_title
        'Failed Logins Table', // string $menu_title
        'manage_options', // string $capability
        'my-custom-submenu-page',
        'reportattacks_render_list_page' );
}


function reportattacks_render_list_page() {
	$reportattacks_list_table = new reportattacks_List_Table();
	$reportattacks_list_table->reportattacks_prepare_items();
    require dirname( __FILE__ ) . '/includes/list-tables/page.php';
}



$reportattacks_radio_report_all_logins =  get_site_option('reportattacks_radio_report_all_logins', '0'); // Alert me all Failed Login Attempts

$reportattacks_whitelist = trim(get_site_option('reportattacks_whitelist',''));
$reportattacks_whitelist = explode(PHP_EOL, $reportattacks_whitelist);
$reportattacks_email_display = trim(get_site_option('reportattacks_email_display',''));

register_activation_hook( __FILE__, 'reportattacks_plugin_was_activated');
register_deactivation_hook(__FILE__, 'reportattacks_my_deactivation');

add_action('wp_login_failed', 'reportattacks_failed_login');
add_action('reportattacks_my_hourly_event', 'reportattacks_do_report');



if (! reportattacks_whitelisted($reportattacks_ip, $reportattacks_whitelist)) {
 
 
     if ($reportattacks_email_display <> '1') {
        return;
     }
    
     add_action('login_form', 'reportattacks_email_display');
     add_action('wp_authenticate_user', 'reportattacks_validate_email_field', 10, 2);
} /* endif if (! ah_whitelisted($ip, $my_whitelist)) */



$schedule = wp_get_schedule( 'reportattacks_my_hourly_event' );

if($schedule <> 'hourly')
   wp_schedule_event(current_time('timestamp'), 'hourly', 'reportattacks_my_hourly_event');


/*
// Debug...
function reportattacks_my_plugin_override() {
    reportattacks_failed_login('bill');
}

add_action( 'plugins_loaded', 'reportattacks_my_plugin_override' );

reportattacks_add_try($reportattacks_ip,'bill');
reportattacks_do_report();



*/


?>