CREATE TABLE `agent_runs` (
	`agent_run_id` text PRIMARY KEY NOT NULL,
	`role` text NOT NULL,
	`scan_id` text,
	`finding_id` text,
	`status` text NOT NULL,
	`started_at` text NOT NULL,
	`data` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_agent_runs_scan` ON `agent_runs` (`scan_id`);--> statement-breakpoint
CREATE INDEX `idx_agent_runs_finding` ON `agent_runs` (`finding_id`,`started_at`);