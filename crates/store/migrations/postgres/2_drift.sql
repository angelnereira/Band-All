-- Learned clock drift per factor (H3). Existing rows default to zero.
ALTER TABLE factors ADD COLUMN drift_steps BIGINT NOT NULL DEFAULT 0;
