<?php namespace reportattacksWPSettings;

$mypage = new Page('Report Attacks', array('type' => 'menu'));
     
$settings = array();

require_once (REPORTATTACKSPATH. "guide/guide.php");


$settings['Startup Guide']['Startup Guide'] = array('info' => $reportattacks_help );
$fields = array();   

        
$settings['Startup Guide']['Startup Guide']['fields'] = $fields;


$msg2 = 'You need only check yes or no below. 
<br />Then click SAVE CHANGES. ';
 


$settings['General Settings']['Instructions'] = array('info' => $msg2);
$fields = array();
   

$fields[] = array(
	'type' 	=> 'radio',
	'name' 	=> 'reportattacks_record_active',
	'label' => 'Record all failed login not included at IP White List?',
	'radio_options' => array(
		array('value'=>'1', 'label' => 'yes'),
		array('value'=>'0', 'label' => 'no')
		)			
	);
    
 $fields[] = array(
	'type' 	=> 'radio',
	'name' 	=> 'reportattacks_email_display',
	'label' => 'Add extra login protection when ip is not withelisted?<br />(Will request your WordPress email at login)',
	'radio_options' => array(
		array('value'=>'1', 'label' => 'yes'),
		array('value'=>'0', 'label' => 'no')
		)			
	);
                
$settings['General Settings']['']['fields'] = $fields;


$myip = reportattacks_findip2(); 
$msg2 = 'Add your current ip to your whitelist, (one IP each line) then click SAVE CHANGES. <b> Your current ip is: '.$myip .'</b>';
$msg2 .= '<br />When your IP is not whitelisted, the WordPress login page will require your WordPress email address.';

$settings['My IP White List']['Customized whitelist'] = array('info' => $msg2);
$fields = array();   
$fields[] = array(
	'type' 	=> 'textarea',
	'name' 	=> 'reportattacks_whitelist',
	'label' => 'My IP White List'
	);
        
$settings['My IP White List']['']['fields'] = $fields;

$reportattacks_admin_email = get_option( 'admin_email' ); 
$msg_email = 'Fill out the email address to send messages.<br />Left Blank to use your default Wordpress email.<br />('.$reportattacks_admin_email.')<br />Then, click save changes.';

 
$settings['Email Settings']['email'] = array('info' => $msg_email );
$fields = array();
$fields[] = array(
	'type' 	=> 'text',
	'name' 	=> 'reportattacks_my_email',
	'label' => 'email'
	);
$settings['Email Settings']['email']['fields'] = $fields;




$notificatin_msg = 'Do you want receive email alerts for each failed login attempt?
<br /><strong>If you under bruteforce attack, you will receive a lot of emails.</strong>
';
 
$settings['Notifications Settings']['Notifications'] = array('info' => $notificatin_msg );
$fields = array();

    
$fields[] = array(
	'type' 	=> 'radio',
	'name' 	=> 'reportattacks_radio_report_all_logins',
	'label' => 'Alert me by email each Failed Login',
	'radio_options' => array(
		array('value'=>'1', 'label' => 'Yes.'),
		array('value'=>'0', 'label' => 'No.'),
		)			
	);    
    
    
$settings['Notifications Settings']['email']['fields'] = $fields;
   
    
$settings['Blocklist Settings']['Blocklist Instructions']['fields'] = $fields;


/*
$blocklist_msg = 'You need go to <strong>www.blocklist.de</strong> and create a free account';
$blocklist_msg .= '<br>';
$blocklist_msg .= 'At their site, you can get:';
$blocklist_msg .= '<br>';
$blocklist_msg .= '* <strong>API KEY</strong>';
$blocklist_msg .= '<br>';
$blocklist_msg .= '* <strong>Sender Address</strong> (Usually your email address left at blocklist.de)';
$blocklist_msg .= '<br>';
$blocklist_msg .= 'At BlockList.de site, you can choose the language: English, French or Deutch (look for the flags)';
*/
$blocklist_msg = 'To get your free Blocklist API Key, go to <strong>Request API Key</strong> page under the Repport Attacks menu and follow the instructions there.';

$settings['Blocklist Settings']['Blocklist Instructions'] = array('info' => $blocklist_msg );
$fields = array();


       
    
    
    

//server=abuse@siterightaway.com
//apikey=f18d03f528
            
$fields[] = array(
	'type' 	=> 'text',
	'name' 	=> 'reportattacks_my_blocklist_api',
	'label' => 'Blocklist API KEY'
	);
    
$fields[] = array(
	'type' 	=> 'text',
	'name' 	=> 'reportattacks_my_blocklist_server',
	'label' => 'Blocklist Sender-Address'
	);     
    
$fields[] = array(
	'type' 	=> 'radio',
	'name' 	=> 'reportattacks_radio_report_attacks',
	'label' => 'Report Attacks (failed logins) to Blocklist.de ?',
	'radio_options' => array(
		array('value'=>'yes', 'label' => 'Yes.'),
		array('value'=>'no', 'label' => 'No.'),
		)			
	);
        
$settings['Blocklist Settings']['Blocklist Settings and Notifications']['fields'] = $fields;



new OptionPageBuilderTabbed($mypage, $settings);


function reportattacks_findip2()
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

    if (!empty($reportattacks_ip) and reportattacks_validate_ip2($reportattacks_ip))
        return $reportattacks_ip;
    else
        return 'unknow';


}

function reportattacks_validate_ip2($reportattacks_ip)
{
    if (filter_var($reportattacks_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return false;
    }
    return true;
}

