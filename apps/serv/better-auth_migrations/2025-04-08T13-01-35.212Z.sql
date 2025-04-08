alter table "user" add column "role" text;

alter table "user" add column "banned" boolean;

alter table "user" add column "banReason" text;

alter table "user" add column "banExpires" timestamp;

alter table "session" add column "impersonatedBy" text;