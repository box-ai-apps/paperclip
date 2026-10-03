CREATE TABLE "relay_instance_credentials" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"issued_by_user_id" text NOT NULL,
	"label" text NOT NULL,
	"token_hash" text NOT NULL,
	"last_used_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"expires_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "relay_instance_settings" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"singleton_key" text DEFAULT 'default' NOT NULL,
	"paused_at" timestamp with time zone,
	"connection_state" text DEFAULT 'disconnected' NOT NULL,
	"last_session_id" text,
	"last_connected_at" timestamp with time zone,
	"last_disconnected_at" timestamp with time zone,
	"last_error_code" text,
	"last_error_message" text,
	"status" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "relay_instance_credentials" ADD CONSTRAINT "relay_instance_credentials_issued_by_user_id_user_id_fk" FOREIGN KEY ("issued_by_user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "relay_instance_credentials_token_hash_idx" ON "relay_instance_credentials" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "relay_instance_credentials_issuer_idx" ON "relay_instance_credentials" USING btree ("issued_by_user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "relay_instance_settings_singleton_key_idx" ON "relay_instance_settings" USING btree ("singleton_key");