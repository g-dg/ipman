<?php

$ip_file = './ip.txt';
$key_file = './ip_key.txt';

$ip = $_SERVER['REMOTE_ADDR'];

if (isset($_POST['key']) && is_readable($key_file) && trim($_POST['key']) === trim(file_get_contents($key_file))) {
		if (is_readable($ip_file) && is_writable($ip_file)) {
				if (trim(file_get_contents($ip_file)) !== trim($ip)) {
						file_put_contents($ip_file, trim($ip));
				}
		}
}
