CREATE TABLE IF NOT EXISTS winafl_jobs (
	name TEXT NOT NULL, 
	command TEXT NOT NULL, 
	file TEXT NOT NULL,
	module TEXT, 
	offset INT, 
	nargs INT DEFAULT 8,
	timeout TEXT DEFAULT "10000+"
);

-- job_types:
-- 0 = winafl
CREATE TABLE IF NOT EXISTS runs (
	job_id INT NOT NULL,
	job_type INT NOT NULL,
	start_time INT,
	end_time INT,
	time_limit INT DEFAULT 60 NOT NULL, -- minutes
	crashes INT DEFAULT 0 NOT NULL,
	hangs INT DEFAULT 0 NOT NULL,
	in_dir TEXT NOT NULL,
	out_dir TEXT NOT NULL
	-- Max run
	-- Crashes
	-- Hangs
);

CREATE TABLE IF NOT EXISTS run_crash_link_table (
	run_id INT NOT NULL,
	crash_id INT NOT NULL
);

CREATE TABLE IF NOT EXISTS crashes (
	sha256 TEXT NOT NULL,
	location TEXT NOT NULL
);