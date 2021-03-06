PRAGMA foreign_keys=on;

BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS "users" (
	"id" INTEGER PRIMARY KEY NOT NULL,
	"username" TEXT NOT NULL UNIQUE,
	"password" TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS "tracked_locations" (
	"id" INTEGER PRIMARY KEY NOT NULL,
	"name" TEXT NOT NULL,
	"ping_key" TEXT NOT NULL UNIQUE,
	"trusted" INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS "address_history" (
	"entry_id" INTEGER PRIMARY KEY NOT NULL,
	"location_id" INTEGER NOT NULL REFERENCES "tracked_locations"("id") ON UPDATE CASCADE ON DELETE CASCADE,
	"ip_address" TEXT,
	"timestamp" INTEGER NOT NULL,
	UNIQUE("location_id", "ip_address") ON CONFLICT REPLACE
);

CREATE INDEX IF NOT EXISTS "idx_addresshistory_ipaddress" ON "address_history"("ip_address");

COMMIT TRANSACTION;
