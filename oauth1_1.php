<?php

$request_url;
$auth_url;
$consumer_key;
$consumer_secret;
$callback;

$nonce = sha1(rand());
$timestamp = time();
$parameter = 'oauth_callback=' . rawurlencode($callback) .
	'&oauth_consumer_key=' . rawurlencode($consumer_key) .
	'&oauth_nonce=' . rawurlencode($nonce) .
	'&oauth_signature_method=' . 'HMAC-SHA1' .
	'&oauth_timestamp=' . $timestamp .
	'&oauth_version=' . '1.0';
$base = 'GET&' . rawurlencode($request_url) . '&' . rawurlencode($parameter);
$key = rawurlencode($consumer_secret) . '&';
$signature = base64_encode(hash_hmac('sha1', $base, $key, TRUE));
$url = $request_url .
	'?oauth_callback=' . urlencode($callback) .
	'&oauth_consumer_key=' . urlencode($consumer_key) .
	'&oauth_nonce=' . urlencode($nonce) .
	'&oauth_signature=' . urlencode($signature) .
	'&oauth_signature_method=' . 'HMAC-SHA1' .
	'&oauth_timestamp=' . $timestamp .
	'&oauth_version=' . '1.0';

$ch = curl_init($url);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
$result = curl_exec($ch);
curl_close($ch);

$pairs = explode('&', $result);
$values = explode('=', $pairs[0]);
$token = $values[1];
$values = explode('=', $pairs[1]);
$token_secret = $values[1];

session_start();
$_SESSION['token_secret'] = $token_secret;
$url = $auth_url . '?oauth_token=' . urlencode($token);
header('Location: ' . $url);

?>