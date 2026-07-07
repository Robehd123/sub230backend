-- Strava OAuth tokens (single row, your account only)
CREATE TABLE IF NOT EXISTS tokens (
  id INTEGER PRIMARY KEY DEFAULT 1,
  access_token TEXT NOT NULL,
  refresh_token TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  athlete_id INTEGER NOT NULL
);

-- Every activity synced from Strava (all types)
CREATE TABLE IF NOT EXISTS activities (
  id INTEGER PRIMARY KEY,
  strava_id INTEGER UNIQUE NOT NULL,
  name TEXT,
  type TEXT,
  sport_type TEXT,
  start_date TEXT,
  distance_m REAL,
  moving_time_s INTEGER,
  elapsed_time_s INTEGER,
  elevation_gain_m REAL,
  average_hr REAL,
  max_hr REAL,
  average_cadence REAL,
  average_watts REAL,
  suffer_score INTEGER,
  perceived_exertion REAL,
  map_polyline TEXT,
  raw_json TEXT,
  synced_at TEXT DEFAULT (datetime('now'))
);

-- Daily health metrics from Apple Health via Health Auto Export
CREATE TABLE IF NOT EXISTS daily_metrics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  date TEXT UNIQUE NOT NULL,
  resting_hr REAL,
  sleep_duration_min REAL,
  sleep_score REAL,
  respiratory_rate REAL,
  vo2max REAL,
  steps INTEGER,
  raw_json TEXT,
  recorded_at TEXT DEFAULT (datetime('now'))
);

-- Weekly AI-generated training plans
CREATE TABLE IF NOT EXISTS weekly_plans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  week_start TEXT UNIQUE NOT NULL,
  plan_json TEXT NOT NULL,
  generated_at TEXT DEFAULT (datetime('now'))
);

-- Weekly summaries (computed from activities)
CREATE TABLE IF NOT EXISTS weekly_summaries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  week_start TEXT UNIQUE NOT NULL,
  total_distance_km REAL,
  total_time_min REAL,
  run_count INTEGER,
  long_run_km REAL,
  easy_km REAL,
  interval_km REAL,
  threshold_km REAL,
  avg_resting_hr REAL,
  is_down_week INTEGER DEFAULT 0,
  computed_at TEXT DEFAULT (datetime('now'))
);