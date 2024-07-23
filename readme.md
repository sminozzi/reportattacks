# WordPress Report Brute Force Attacks and Login Protection ReportAttacks Plugins #
Contributors: sminozzi
Donate link: http://billminozzi.com/donate/
Tags: login protection, abuse, fail2ban, brute force, report attacks
Requires at least: 4.0
Tested up to: 6.6
Stable tag: 2.32
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

## Report login brute force attacks and improve login protection and security. Firewall Included. ##

== Description ==
Report login brute force attacks, protect and block against brute force login attempts and create a blacklist of IP addresses. Firewall included.
<ul>
<li>Not whitelisted IPs need fill out one aditional email field in login form.</li>
<li>Firewall to Block Malicious Requests, Queries, User Agents and URLS. 100% Plug-n-play, no configuration required.</li>
<li>Option to disable xml-rpc API. </li>
<li>Option to disable Json WordPress Rest API (also new WordPress 4.7 Rest API).</li> 
<li>Option to login notification by email.</li>
<li>Alert when this plugin is deactivated.</li>
<li>Alert when a new plugin is installed at your site.(usually first thing hacker do after attack you)</li>
<li>Optionally, let you hide your site (and login page) from attackers.</li>
<li>Stay Up-to-Date: Option to set WordPress to automatically download and install themes and plugin updates.</li>
<li>WordPress Debug enabled warning.</li>
<li>Disable file editing within the WordPress dashboard.</li>
<li>Replace insecure login error message.</li>
<li>Multilingual ready.</li>
</ul> 
Report not whitelisted IP address attacks to the respective abuse departments of the infected PCs/servers, through free services of blocklist, to ensure that the responsible provider can inform their customer about the infection and disable the attacker. 

No fail2ban or another software required.

We hope our plugin makes the Internet better, safer and helps to clean infected PCs.



== Startup Guide ==
1)  Open the Request API Key page (under Report Attacks Menu) and follow the instructions to get your free API KEY.

2) After receive the Blocklist email with your API KEY, go to Blocklist Settings Tab and fill out your free API info. Check Yes to begin to report attacks. We can report attacks when the same IP attempt attacks you more than 5 time

3) Important: Add your’s  IP address to MY IP White List.

4) At eMail Settings tab, you can customize your contact email or left blank to use your wordpress eMail.

5) At Notification Settings Tab, you can record your option by receive or not email alerts about failed logins.

6)  Open the Plugin General Settings Tab and click over Yes  (to begin to record failed login attempts).

Remember to click Save Changes before to left each tab.

To manage the failed login’s table, go to Failed Logins Table

That is all. Enjoy it.


== Installation ==


1) Install via wordpress.org

2) Activate the plugin through the 'Plugins' menu in WordPress

or

Extract the zip file and just drop the contents in the wp-content/plugins/ directory of your WordPress installation and then activate the Plugin from Plugins page.


== Frequently Asked Questions ==

How to Install?

1) Install via wordpress.org

2) Activate the plugin through the 'Plugins' menu in WordPress

or

Extract the zip file and just drop the contents in the wp-content/plugins/ directory of your WordPress installation and then activate the Plugin from Plugins page.



== Screenshots ==
1. Control Panel
2. Default IP Black List

== Credits (Thanks) ==
Translation to Germany by emha.koeln (@emhakoeln)

== Changelog ==
2.32 2024-03-27 - Small Improvements.

2.31 2024-01-14 - Small Improvements.

2.30 2023-10-17 - Improved Error Handling.

2.28/29 2023-08-30 - Improved Error Handling.

2.27 2021-06-19 - Minor Improvements

2.26 2021-05-04 - Improved Germany Translation File.

2.25 2021-04-29 - Added Germany Translation File.

2.24 2021-04-27 - Improved Translation.

2.23 2020-11-11 - Minor improvements.

2.22 2020-11-11 - Minor improvements.

2.21 2019-07-24 - Improved Translation.

2.20 2019-05-20 -  Included Firewall.

2.19 2018-12-27 -  Included Firewall.

2.18 2018-01-05 -  Security Improved.

2.17 2018-01-05 -  Security Improved.

2.16 2017-12-23 -  Security Improved.

2.15 2017-12-10 -  Security Improved.

2.14 2017-12-09 -  Security Improved.

2.13 2017-12-08 -  Security Improved.

2.12 2017-08-15 -  Help and Feedback improved.

2.11 2017-06-09 -  Tested with WordPress 4.8

2.10 2017-05-25 -  eMail Notification improvement.

2.09 2017-04-12 -  Feedback System Improvements.

2.08 2017-03-10 -  Add warning if debug is true, options to disable editing, replace error login message and automatic plugins and themes updtate.

2.07 2017-01-25 -  Add language file.

2.06 2017-01-06 -  Improved Help System

2.05 2016-12-16 -  Improved Ip recover

2.04 2016-12-13 -  Disable Json WordPress Rest API (also new WordPress 4.7 Rest API). 

2.03 2016-12-12 -  Fixed bug at get api key page.

2.02 2016-12-05 -  Tested with WordPress 4.7.

2.01 2016-09-30 -  Minor improvments.

2.0 2016-09-28 -  Minor improvments.

1.9 2016-09-02 -  Minor bug fixes.

1.8 2016-09-01 -  Add email alert when this plugin is deactivated, new plugin is installed and 
let you hide the whole site (and login page) from attackers.

1.7 2016-08-18 -  Improved Notifications settings.

1.6 2016-08-10 -  Included Options to Disable xml-rpc API and also notification for successfull login.

1.5 2016-08-05 -  Included button Screen Options at Failed login table and add message compatibility with WordPress 4.6

1.4 2016-07-22 -  Included screen to get free API KEY from Blocklist.de

1.3 2016-07-19 -  Improvements at Start Up Guide. 

1.2 2016-07-12 -  Improvements at Cron Job. 

1.1 2016-07-11 -  Add extra login protection when ip it is not whitelisted and improved failed login table management. 

1.0 2016-07-08 -  Initial Release
