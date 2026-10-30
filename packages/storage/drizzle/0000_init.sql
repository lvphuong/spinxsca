CREATE TABLE `baselines` (
	`baseline_id` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`scope_type` text NOT NULL,
	`scope_ref` text NOT NULL,
	`scan_id` text NOT NULL,
	`reason` text NOT NULL,
	`activated_at` text NOT NULL,
	`deactivated_at` text,
	FOREIGN KEY (`project_id`) REFERENCES `projects`(`project_id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`scan_id`) REFERENCES `scan_runs`(`scan_id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_baselines_scope` ON `baselines` (`project_id`,`scope_type`,`scope_ref`);--> statement-breakpoint
CREATE TABLE `evidences` (
	`evidence_id` text PRIMARY KEY NOT NULL,
	`kind` text NOT NULL,
	`snapshot_id` text NOT NULL,
	`data` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `finding_assessments` (
	`assessment_id` text PRIMARY KEY NOT NULL,
	`finding_id` text NOT NULL,
	`scan_id` text NOT NULL,
	`occurrence_id` text,
	`reconciliation_state` text NOT NULL,
	`severity` text NOT NULL,
	`assessed_at` text NOT NULL,
	`data` text NOT NULL,
	FOREIGN KEY (`finding_id`) REFERENCES `findings`(`finding_id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`scan_id`) REFERENCES `scan_runs`(`scan_id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `uq_assessment_scan_finding` ON `finding_assessments` (`scan_id`,`finding_id`);--> statement-breakpoint
CREATE INDEX `idx_assessments_finding` ON `finding_assessments` (`finding_id`,`assessed_at`);--> statement-breakpoint
CREATE TABLE `finding_candidates` (
	`candidate_id` text PRIMARY KEY NOT NULL,
	`scan_id` text NOT NULL,
	`scan_task_id` text NOT NULL,
	`scanner` text NOT NULL,
	`rule_id` text NOT NULL,
	`category` text NOT NULL,
	`semantic_fingerprint` text NOT NULL,
	`data` text NOT NULL,
	FOREIGN KEY (`scan_id`) REFERENCES `scan_runs`(`scan_id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_candidates_scan` ON `finding_candidates` (`scan_id`);--> statement-breakpoint
CREATE TABLE `finding_dispositions` (
	`disposition_id` text PRIMARY KEY NOT NULL,
	`finding_id` text NOT NULL,
	`kind` text NOT NULL,
	`decided_at` text NOT NULL,
	`data` text NOT NULL,
	FOREIGN KEY (`finding_id`) REFERENCES `findings`(`finding_id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_dispositions_finding` ON `finding_dispositions` (`finding_id`);--> statement-breakpoint
CREATE TABLE `finding_fingerprints` (
	`project_id` text NOT NULL,
	`fingerprint` text NOT NULL,
	`finding_id` text NOT NULL,
	`algorithm` text NOT NULL,
	`created_at` text NOT NULL,
	PRIMARY KEY(`project_id`, `fingerprint`),
	FOREIGN KEY (`finding_id`) REFERENCES `findings`(`finding_id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE TABLE `finding_match_events` (
	`event_id` text PRIMARY KEY NOT NULL,
	`scan_id` text NOT NULL,
	`finding_id` text NOT NULL,
	`candidate_id` text,
	`method` text NOT NULL,
	`decision` text NOT NULL,
	`data` text NOT NULL,
	FOREIGN KEY (`scan_id`) REFERENCES `scan_runs`(`scan_id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_match_events_scan` ON `finding_match_events` (`scan_id`);--> statement-breakpoint
CREATE TABLE `finding_occurrences` (
	`occurrence_id` text PRIMARY KEY NOT NULL,
	`finding_id` text NOT NULL,
	`scan_id` text NOT NULL,
	`snapshot_id` text NOT NULL,
	`fingerprint` text NOT NULL,
	`data` text NOT NULL,
	FOREIGN KEY (`finding_id`) REFERENCES `findings`(`finding_id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`scan_id`) REFERENCES `scan_runs`(`scan_id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_occurrences_scan` ON `finding_occurrences` (`scan_id`);--> statement-breakpoint
CREATE INDEX `idx_occurrences_finding` ON `finding_occurrences` (`finding_id`);--> statement-breakpoint
CREATE TABLE `findings` (
	`finding_id` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`seq` integer NOT NULL,
	`category` text NOT NULL,
	`rule_family` text NOT NULL,
	`title` text NOT NULL,
	`cwe` text NOT NULL,
	`canonical_fingerprint` text NOT NULL,
	`fingerprint_algorithm` text NOT NULL,
	`first_seen_scan_id` text NOT NULL,
	`created_at` text NOT NULL,
	FOREIGN KEY (`project_id`) REFERENCES `projects`(`project_id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `uq_findings_seq` ON `findings` (`project_id`,`seq`);--> statement-breakpoint
CREATE INDEX `idx_findings_fp` ON `findings` (`project_id`,`canonical_fingerprint`);--> statement-breakpoint
CREATE TABLE `projects` (
	`project_id` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `repositories` (
	`repository_id` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`root_path` text NOT NULL,
	`created_at` text NOT NULL,
	FOREIGN KEY (`project_id`) REFERENCES `projects`(`project_id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE TABLE `scan_runs` (
	`scan_id` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`repository_id` text NOT NULL,
	`snapshot_id` text NOT NULL,
	`mode` text NOT NULL,
	`status` text NOT NULL,
	`manifest` text NOT NULL,
	`manifest_digest` text NOT NULL,
	`baseline_scan_id` text,
	`requested_at` text NOT NULL,
	`started_at` text,
	`completed_at` text,
	`summary` text,
	`error` text,
	FOREIGN KEY (`project_id`) REFERENCES `projects`(`project_id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`snapshot_id`) REFERENCES `source_snapshots`(`snapshot_id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_scan_runs_project` ON `scan_runs` (`project_id`,`requested_at`);--> statement-breakpoint
CREATE TABLE `scan_tasks` (
	`task_id` text PRIMARY KEY NOT NULL,
	`scan_id` text NOT NULL,
	`kind` text NOT NULL,
	`name` text NOT NULL,
	`scanner_id` text,
	`idempotency_key` text NOT NULL,
	`status` text NOT NULL,
	`attempt` integer NOT NULL,
	`output_digest` text,
	`coverage` text,
	`error` text,
	`started_at` text,
	`completed_at` text,
	FOREIGN KEY (`scan_id`) REFERENCES `scan_runs`(`scan_id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `uq_scan_tasks_key` ON `scan_tasks` (`scan_id`,`idempotency_key`);--> statement-breakpoint
CREATE INDEX `idx_scan_tasks_key` ON `scan_tasks` (`idempotency_key`,`status`);--> statement-breakpoint
CREATE TABLE `source_snapshots` (
	`snapshot_id` text PRIMARY KEY NOT NULL,
	`repository_id` text NOT NULL,
	`kind` text NOT NULL,
	`commit_sha` text,
	`tree_sha` text,
	`branch_at_capture` text,
	`content_manifest_digest` text NOT NULL,
	`file_count` integer NOT NULL,
	`file_list_digest` text NOT NULL,
	`captured_at` text NOT NULL,
	FOREIGN KEY (`repository_id`) REFERENCES `repositories`(`repository_id`) ON UPDATE no action ON DELETE no action
);
