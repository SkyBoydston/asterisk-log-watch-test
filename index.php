<?php

/* This is a program that identifies attempts
 * to access a server without permission and 
 * notifies the server owner with the offenders'
 * IP addresses. It's designed to be run as a 
 * Cron job.
*/ 


// Open the log and pare it down to only relevant entries.

if (file_exists('log.txt')) {
	$log = file_get_contents('log.txt');
} elseif (file_exists('full.1')) {
	$log = file_get_contents('full.1');
} else {
	mail('kevin@networxonline.com', 
		'Log file absence warning', 
		'Please make sure that a log file that tracks unpermitted attempts to log into host PBX-2 is being generated.', 
		$from);
}

if (strlen($log) >= 100000000) {  // This is here so that pcre.backtrack_limit doesn't need to be set by variable, which could result in a very large backtrack limit.
	mail('kevin@networxonline.com', 
		'Log file size warning', 
		'Please make sure that log files to track unpermitted attempts to log into host PBX-2 do not exceed 100 million characters in length for optimal performance.', 
		$from);
}

if (file_exists('log_placeholder.txt') && strlen($log) <= 100000000) {
	$placeholder = file_get_contents('log_placeholder.txt', false, null, 0, 19); // Making sure it doesn't pick up an extra newline or anything else.
	$pattern = "/.*" . str_replace(' ', '\s', $placeholder) . "/s";
	ini_set('pcre.backtrack_limit', '100000000');
	$log = preg_replace($pattern, '', $log);
} else {
	$placeholder = 0;
}









// Get together a list of notices.

$notices = array();
preg_match_all('/\n.*NOTICE\[23697\].*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*\n/', $log, $notices); // This needs to be changed for the final version

if (!empty($notices)) {
	$notices = $notices[0];  // Not necessary but convenient because of the way preg_match_all() outputs its results.
	$notices = array_unique($notices);  // Cutting down the amount of data to process.

	foreach ($notices as $key => $value) {
		$value = htmlentities($value);  //Takes care of encoding so that we can see what's going on under the hood.
	}




	// Pull out the suspected offenders' IP addresses.

	$suspect_ips = array();
	foreach ($notices as $key => $value) {
		$ip = array();
		preg_match_all('/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/', $value, $ip);
		
		$ip = $ip[0][1];  // Grabbing the second match since the first match is always friendly. 
		
		array_push($suspect_ips, $ip);
	}

	function array_unique_right($array)
	{
	  return array_reverse(array_unique(array_reverse($array, true)), true);
	}

	$suspect_ips = array_unique_right($suspect_ips);







	// Get the latest time at which there was a suspect IP. This is possible because array_unique() above keeps the original keys in the array
	// that we can then use to trace back and see what time the notice was logged. That could be one of the earlier log entries for that IP
	// or a later one; it's not known which but it's also not necessary to know. Whether it's an earlier entry or later one, the second to last
	// in the list can give us a starting point for our search on the next run. Knowing its exact time stamp is helpful in finding the exact
	// place in the log file to start removing log entries. That way they don't have to be checked for suspect IP's and that offers a little 
	// performance boost.

	$times = array();
	foreach ($notices as $key => $value) {
		$time = array();

		preg_match_all('/\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}/', $value, $time);

		$time = $time[0][0];  
		
		array_push($times, $time);
	}

	$times_of_suspect_ips = array();
	foreach ($suspect_ips as $key => $value) {
		$times_of_suspect_ips[] = $times[$key];
	}

	$time_of_latest_suspect = end($times_of_suspect_ips);
	while (($time_of_latest_suspect == end($times_of_suspect_ips)) && (count($times_of_suspect_ips) > 1)) {
		array_pop($times_of_suspect_ips);
	}


	if (($time_of_latest_suspect != end($times_of_suspect_ips)) && (count($times_of_suspect_ips) > 1)){
		$time_of_second_latest_suspect = end($times_of_suspect_ips);  
	} elseif (($time_of_latest_suspect != end($times_of_suspect_ips)) && (count($times_of_suspect_ips) == 1)){
		$time_of_second_latest_suspect = end($times_of_suspect_ips);  
	} elseif (($time_of_latest_suspect == end($times_of_suspect_ips)) && (count($times_of_suspect_ips) == 1)) {
		$time_of_second_latest_suspect = null;
	}






	// Store the latest suspect's time so for use on the next run of this script.

	if ($time_of_second_latest_suspect != null ) {
		if ($time_of_second_latest_suspect >= $placeholder) {
	$log_placeholder = fopen('log_placeholder.txt', 'w');
			echo 'placeholder before write is <br>';
			echo $placeholder;
			fwrite($log_placeholder, $time_of_second_latest_suspect);
	fclose($log_placeholder);
		}
	}








	// Gather up a list of IP addresses that have already been notified on and compare them to the current suspect list.

	$previously_alerted = fopen('previously_alerted.txt', 'a+');  // But what if this file gets huge?
	$previously_alerted = file('previously_alerted.txt', FILE_IGNORE_NEW_LINES); // Flag is necessary for accurate matches in following 'in_array()'

	$ips_to_alert = array();
	foreach ($suspect_ips as $key => $value) {
		if (!in_array($value, $previously_alerted)) {
			array_push($ips_to_alert, $value);
		}
	}







	// // Mail out for each ip to alert on. This would ideally be set up into a queue.

	// $to = 'kevin@networxonline.com';
	// $subject = 'A suspect IP is trying to access your server';

	// foreach ($ips_to_alert as $key => $value) {
	// 	$message = 'IP address ' . $value . ' is trying to register on host PBX-2.';
	// 	mail($to, $subject, $message, $from);
	// }







	// Record the IP's that were just alerted on so that they don't get alerted on again.

	$file_location = fopen('previously_alerted.txt', 'a');

	foreach ($ips_to_alert as $key => $value) {
		fwrite($file_location, $value . "\r\n");
	}
	fclose($file_location);
}
?>