<?php

require_once('ipman_api.php');

if (isset($_POST['key'])) {
	IPManagerAPI::ping($_POST['key'], $_SERVER['REMOTE_ADDR']);
}
