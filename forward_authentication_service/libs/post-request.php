<?php
//Copyright (C) BlueWave Projects and Services 2016-2020

if (isset($argv[1])) {$remote_url=$argv[1];} else {echo "missing argument\n"; exit(1);}
if (isset($argv[2])) {$action=$argv[2];} else {echo "missing argument\n"; exit(1);}
if (isset($argv[3])) {$gatewayhash=$argv[3];} else {echo "missing argument\n"; exit(1);}
if (isset($argv[4])) {$user_agent=$argv[4];} else {echo "missing argument\n"; exit(1);}

$_p = array("auth_get"=>$action,"gatewayhash"=>$gatewayhash);
$response=SendPostData($_p, $remote_url, $user_agent);
echo "$response";

function SendPostData($_p, $remote_url, $user_agent) {
	$fields_string = http_build_query($_p);
	$headers="Content-type: application/x-www-form-urlencoded\r\n"."Content-Length: ".strlen($fields_string)."\r\n";

	$context_options = array (
		'http' => array (
			'method' => 'POST',
			'header' => $headers,
			'user_agent' => $user_agent,
			'content'=> $fields_string
		)
	);

	$context = stream_context_create($context_options);

	//open the stream and get the response
	$fp = @fopen($remote_url, 'r', false, $context);

	if ($fp == TRUE) {
		$response = stream_get_contents($fp);
	}

	return $response;
}

?>
