<?php

error_reporting(E_ALL);
ini_set('display_errors', 'On');

class IPManagerAPI
{
	private const ADDRESS_MAX_AGE = 86400;
	private const ADDRESS_MIN_AGE = 60;

	private static $dbconn;

	public static function db_connect()
	{
		// return if already connected
		if (isset($GLOBALS['_ipman_dbconn'])) {
			return;
		}

		// load config
		require('config.php');

		if (!isset($config['database_file'])) {
			http_response_code(500);
			exit('Config file incorrect!');
		}

		// check whether the database file exists
		if (
			!is_readable($config['database_file']) ||
			!is_writable($config['database_file']) ||
			!is_readable(dirname($config['database_file'])) ||
			!is_writable(dirname($config['database_file']))
		) {
			http_response_code(500);
			exit('Database doesn\'t exist!');
		}
		if (!is_readable('./database.sql')) {
			http_response_code(500);
			exit('Could not get database definition.');
		}

		// connect to database
		self::$dbconn = new PDO('sqlite:' . $config['database_file']);

		// set connection properties
		self::$dbconn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		self::$dbconn->setAttribute(PDO::ATTR_TIMEOUT, 60);
		self::$dbconn->exec('PRAGMA journal_mode=WAL;');
		self::$dbconn->exec('PRAGMA synchronous=NORMAL;');
		self::$dbconn->exec('PRAGMA foreign_keys=on;');

		// create tables
		self::$dbconn->exec(file_get_contents('database.sql'));

		// create user if none exists
		self::$dbconn->beginTransaction();
		$user_exists = self::$dbconn->query('SELECT COUNT() AS "count" FROM "users";')->fetch();
		if (isset($user_exists[0]['count']) && (int)$user_exists[0]['count'] === 0) {
			self::$dbconn->prepare('INSERT INTO "users"("username", "password") VALUES (?, ?);')->execute([$config['default_username'], password_hash($config['default_password'], PASSWORD_DEFAULT)]);
		}
		self::$dbconn->commit();
	}

	private static function db_query($sql, $params = [])
	{
		self::db_connect();
		$stmt = self::$dbconn->prepare($sql);
		$stmt->execute($params);
		return $stmt->fetchAll();
	}

	private static function db_trans()
	{
		self::$dbconn->beginTransaction();
	}

	private static function db_commit()
	{
		self::$dbconn->commit();
	}

	// returns whether authentication succeeded
	public static function authenticate($username, $password)
	{
		$results = self::db_query('SELECT "id", "username", "password" FROM "users" WHERE "username" = ?;', [$username]);
		foreach ($results as $user) {
			if ($user['username'] === $username) {
				if (password_verify($password, $user['password'])) {
					if (password_needs_rehash($user['password'], PASSWORD_DEFAULT)) {
						self::db_query('UPDATE "users" SET "password" = ? WHERE "id" = ?;', [password_hash($password, PASSWORD_DEFAULT), (int)$user['id']]);
					}
					return true;
				}
			}
		}
		return false;
	}

	// returns whether the passed-in IP address is trusted
	public static function address_is_trusted($ip_address = null)
	{
		if (is_null($ip_address))
			$ip_address = $_SERVER['REMOTE_ADDR'];

		$results = self::db_query('SELECT a."ip_address", a."timestamp" FROM "address_history" AS a INNER JOIN "tracked_locations" AS l ON l."id" = a."location_id" WHERE a."ip_address" = ? AND l."trusted" != 0 AND a."timestamp" >= ? ORDER BY a."timestamp" DESC;', [$ip_address, time() - self::ADDRESS_MAX_AGE]);
		return (count($results) > 0);
	}

	// processes a ping
	public static function ping($ping_key, $ip_address = null) {
		if (is_null($ip_address))
			$ip_address = $_SERVER['REMOTE_ADDR'];

		self::db_trans();
		// check if ping key is valid
		$location_results = self::db_query('SELECT "id" FROM "tracked_locations" WHERE "ping_key" = ?;', [$ping_key]);
		if (count($location_results) > 0) {
			$location_id = $location_results[0]['id'];
			// check if the address already exists for the specified key
			$address_results = self::db_query('SELECT "entry_id", "timestamp" FROM "address_history" WHERE "location_id" = ? AND "ip_address" = ? ORDER BY "timestamp" DESC;', [$location_id, $ip_address]);
			if (count($address_results) > 0) {
				// update timestamp if it's old enough to prevent unnecessary database writes
				if ((int)$address_results[0]['timestamp'] > self::ADDRESS_MIN_AGE) {
					self::db_query('UPDATE "address_history" SET "timestamp" = ? WHERE "entry_id" = ?;', [time(), $address_results[0]['entry_id']]);
				}
			} else {
				// insert new entry
				self::db_query('INSERT INTO "address_history" ("location_id", "ip_address", "timestamp") VALUES (?, ?, ?);', [$location_id, $ip_address, time()]);
			}
			return true;
		} else {
			return false;
		}
		self::db_commit();
	}

}
