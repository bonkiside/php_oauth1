<?php

session_start();
$token_secret = $_SESSION['token_secret'];
unset($_SESSION['token_secret']);
$token = urldecode($_GET['oauth_token']);
$verifier = urldecode($_GET['oauth_verifier']);

$access_url;
$consumer_key;
$consumer_secret;
$callback;

$nonce = sha1(rand());
$timestamp = time();
$parameter = 'oauth_consumer_key=' . rawurlencode($consumer_key) .
    '&oauth_nonce=' . rawurlencode($nonce) .
    '&oauth_signature_method=' . 'HMAC-SHA1' .
    '&oauth_timestamp=' . $timestamp .
    '&oauth_token=' . rawurlencode($token) .
    '&oauth_verifier=' . rawurlencode($verifier) .
    '&oauth_version=' . '1.0';
$base = 'GET&' . rawurlencode($access_url) . '&' . rawurlencode($parameter);
$key = rawurlencode($consumer_secret) . '&' . rawurlencode($token_secret);
$signature = base64_encode(hash_hmac('sha1', $base, $key, TRUE));
$url = $access_url .
    '?oauth_consumer_key=' . urlencode($consumer_key) .
    '&oauth_nonce=' . urlencode($nonce) .
    '&oauth_signature=' . urlencode($signature) .
    '&oauth_signature_method=' . 'HMAC-SHA1' .
    '&oauth_timestamp=' . $timestamp .
    '&oauth_token=' . urlencode($token) .
    '&oauth_verifier=' . urlencode($verifier) .
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

$_SESSION['token'] = $token_secret;
$_SESSION['token_secret'] = $token_secret;

?>