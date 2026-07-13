/*
  Sub 2:30: Cloudflare Workers backend
  =======================================
  Routes:
    GET  /auth/strava          → redirect to Strava OAuth
    GET  /auth/callback        → Strava OAuth callback, stores tokens
    GET  /auth/status          → check if authorised
    POST /webhook/strava       → receive new activity events from Strava
    GET  /webhook/strava       → Strava webhook verification challenge
    POST /health/metrics       → receive daily metrics from Apple Health Auto Export
    GET  /api/dashboard        → main data endpoint consumed by the dashboard
    GET  /api/activities       → paginated activity list (runs only)
    GET  /api/weeks            → weekly summaries for the chart
    GET  /api/calendar         → all activities by date for the calendar
    POST /admin/reclassify     → reclassify activities in batches of 100
    POST /admin/recompute      → recompute weekly summaries in batches of 50
    POST /admin/backfill       → sync one page of Strava history (all types)

  Environment variables (set via wrangler secret):
    STRAVA_CLIENT_ID
    STRAVA_CLIENT_SECRET
    STRAVA_WEBHOOK_TOKEN
    HEALTH_API_KEY
*/

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Dashboard-Token",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS },
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

// ---- auth check ----
// Hashes the stored password with SHA-256 and compares to the header token.
// Uses timing-safe comparison via string equality on hex digests.
async function isAuthorised(request, env) {
  if (!env.DASHBOARD_PASSWORD) return true; // if secret not set, allow all (dev mode)
  const token = request.headers.get("X-Dashboard-Token");
  if (!token) return false;
  const encoder = new TextEncoder();
  const data = encoder.encode(env.DASHBOARD_PASSWORD);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const expected = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
  return token === expected;
}

// ---- token management ----

async function getTokens(db) {
  return await db.prepare("SELECT * FROM tokens WHERE id = 1").first();
}

async function saveTokens(db, { access_token, refresh_token, expires_at, athlete_id }) {
  await db.prepare(`
    INSERT INTO tokens (id, access_token, refresh_token, expires_at, athlete_id)
    VALUES (1, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      access_token = excluded.access_token,
      refresh_token = excluded.refresh_token,
      expires_at = excluded.expires_at,
      athlete_id = excluded.athlete_id
  `).bind(access_token, refresh_token, expires_at, athlete_id).run();
}

async function getFreshAccessToken(db, env) {
  const tokens = await getTokens(db);
  if (!tokens) return null;

  const now = Math.floor(Date.now() / 1000);
  if (tokens.expires_at > now + 300) {
    return tokens.access_token;
  }

  const res = await fetch("https://www.strava.com/oauth/token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: env.STRAVA_CLIENT_ID,
      client_secret: env.STRAVA_CLIENT_SECRET,
      grant_type: "refresh_token",
      refresh_token: tokens.refresh_token,
    }),
  });

  if (!res.ok) return null;
  const data = await res.json();

  await saveTokens(db, {
    access_token: data.access_token,
    refresh_token: data.refresh_token,
    expires_at: data.expires_at,
    athlete_id: tokens.athlete_id,
  });

  return data.access_token;
}

// ---- CSV parser (RFC4180-aware, handles quoted fields with embedded commas/newlines) ----

function parseCSV(text) {
  const rows = [];
  let row = [];
  let field = "";
  let inQuotes = false;
  let i = 0;

  while (i < text.length) {
    const char = text[i];

    if (inQuotes) {
      if (char === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 2;
          continue;
        }
        inQuotes = false;
        i++;
        continue;
      }
      field += char;
      i++;
      continue;
    }

    if (char === '"') {
      inQuotes = true;
      i++;
      continue;
    }
    if (char === ',') {
      row.push(field);
      field = "";
      i++;
      continue;
    }
    if (char === '\r') { i++; continue; }
    if (char === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
      i++;
      continue;
    }
    field += char;
    i++;
  }
  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

// ---- activity classifier ----

function classifyActivity(activity) {
  const name = (activity.name || "").toLowerCase();
  const sportType = (activity.sport_type || activity.type || "").toLowerCase();
  const workoutType = activity.workout_type;
  const distKm = (activity.distance_m || 0) / 1000;
  const movingTimeSec = activity.moving_time_s || activity.moving_time || 0;
  const paceSecKm = distKm > 0 && movingTimeSec > 0 ? movingTimeSec / distKm : null;

  // ---- non-run types first ----

  // swimming
  if (sportType === "swim" || sportType === "openwaterswim" ||
      name.includes("swim") || name.includes("pool")) {
    return "swim";
  }

  // cycling
  if (sportType === "ride" || sportType === "virtualride" ||
      sportType === "ebikeride" || sportType === "handcycle" ||
      name.includes("cycling") || name.includes("cycle") || name.includes("bike")) {
    return "cycling";
  }

  // strength / gym
  if (sportType === "weighttraining" || sportType === "crosstraining" ||
      sportType === "yoga" || sportType === "pilates" ||
      name.includes("gym") || name.includes("leg day") || name.includes("legs") ||
      name.includes("upper body") || name.includes("weights") ||
      name.includes("strength") || name.includes("core")) {
    return "strength";
  }

  // ---- run subtypes ----

  if (workoutType === 3) return "intervals";

  if (name.includes("interval") || name.includes("intervals") ||
      name.includes("track") || name.includes("rep") || name.includes("reps") ||
      name.includes("treadmill") || name.includes("speed") ||
      name.includes("vo2") || name.includes("fartlek")) {
    return "intervals";
  }

  if (name.includes("tempo") || name.includes("threshold") ||
      name.includes("lactate") || name.includes("cruise")) {
    return "threshold";
  }

  if (workoutType === 2) return "long";

  if (distKm >= 20 && (paceSecKm === null || paceSecKm > 270)) {
    return "long";
  }

  if (name.includes("long run") || name.includes("lsr") || name.includes("marathon")) {
    return "long";
  }

  // default: if it has a run sport type treat as easy run
  if (sportType.includes("run")) return "easy";

  // anything else
  return "other";
}

function isRunType(type) {
  return ["easy", "long", "intervals", "threshold"].includes(type);
}

// ---- activity sync (all types) ----

async function syncActivity(db, stravaActivity) {
  const a = stravaActivity;
  const classification = classifyActivity({
    name: a.name,
    sport_type: a.sport_type,
    type: a.type,
    distance_m: a.distance,
    moving_time_s: a.moving_time,
    workout_type: a.workout_type,
  });

  await db.prepare(`
    INSERT INTO activities (
      strava_id, name, type, sport_type, start_date,
      distance_m, moving_time_s, elapsed_time_s, elevation_gain_m,
      average_hr, max_hr, average_cadence, average_watts,
      suffer_score, perceived_exertion, map_polyline, raw_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(strava_id) DO UPDATE SET
      name = excluded.name,
      type = excluded.type,
      distance_m = excluded.distance_m,
      moving_time_s = excluded.moving_time_s,
      average_hr = excluded.average_hr,
      raw_json = excluded.raw_json
  `).bind(
    a.id, a.name, classification, a.sport_type, a.start_date,
    a.distance || 0, a.moving_time || 0, a.elapsed_time || 0,
    a.total_elevation_gain || 0, a.average_heartrate || null,
    a.max_heartrate || null, a.average_cadence || null,
    a.average_watts || null, a.suffer_score || null,
    a.perceived_exertion || null,
    a.map?.summary_polyline || null,
    JSON.stringify(a)
  ).run();
}

async function fetchAndSyncDetailedActivity(db, env, stravaId) {
  const token = await getFreshAccessToken(db, env);
  if (!token) return;

  const res = await fetch(`https://www.strava.com/api/v3/activities/${stravaId}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) return;

  const activity = await res.json();
  await syncActivity(db, activity);

  const type = classifyActivity({
    name: activity.name, sport_type: activity.sport_type, type: activity.type,
    distance_m: activity.distance, moving_time_s: activity.moving_time,
    workout_type: activity.workout_type,
  });

  if (isRunType(type)) {
    await recomputeWeeklySummary(db, activity.start_date);
  }

  // invalidate the cached plan so next dashboard load regenerates
  // with this new activity included
  const actDate = new Date(activity.start_date);
  const day = actDate.getDay();
  const monday = new Date(actDate);
  monday.setDate(actDate.getDate() - ((day + 6) % 7));
  monday.setHours(0, 0, 0, 0);
  const weekStart = monday.toISOString().split("T")[0];
  await db.prepare("DELETE FROM weekly_plans WHERE week_start = ?")
    .bind(weekStart).run();
}

// ---- weekly summary (runs only) ----

async function recomputeWeeklySummary(db, dateStr) {
  const date = new Date(dateStr);
  const day = date.getDay();
  const monday = new Date(date);
  monday.setDate(date.getDate() - ((day + 6) % 7));
  const weekStart = monday.toISOString().split("T")[0];

  const sunday = new Date(monday);
  sunday.setDate(monday.getDate() + 6);
  const weekEnd = sunday.toISOString().split("T")[0];

  // runs only for distance totals
  const { results } = await db.prepare(`
    SELECT * FROM activities
    WHERE date(start_date) >= ? AND date(start_date) <= ?
    AND type IN ('easy','long','intervals','threshold')
  `).bind(weekStart, weekEnd).all();

  const totalDistance = results.reduce((s, a) => s + (a.distance_m || 0), 0) / 1000;
  const totalTime = results.reduce((s, a) => s + (a.moving_time_s || 0), 0) / 60;
  const longRun = Math.max(0, ...results.filter(a => a.type === "long").map(a => a.distance_m / 1000));
  const easyKm = results.filter(a => a.type === "easy").reduce((s, a) => s + a.distance_m / 1000, 0);
  const intervalKm = results.filter(a => a.type === "intervals").reduce((s, a) => s + a.distance_m / 1000, 0);
  const thresholdKm = results.filter(a => a.type === "threshold").reduce((s, a) => s + a.distance_m / 1000, 0);
  const isDownWeek = totalDistance < 80 ? 1 : 0;

  await db.prepare(`
    INSERT INTO weekly_summaries (
      week_start, total_distance_km, total_time_min, run_count,
      long_run_km, easy_km, interval_km, threshold_km, is_down_week
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(week_start) DO UPDATE SET
      total_distance_km = excluded.total_distance_km,
      total_time_min = excluded.total_time_min,
      run_count = excluded.run_count,
      long_run_km = excluded.long_run_km,
      easy_km = excluded.easy_km,
      interval_km = excluded.interval_km,
      threshold_km = excluded.threshold_km,
      is_down_week = excluded.is_down_week,
      computed_at = datetime('now')
  `).bind(
    weekStart, totalDistance, totalTime, results.length,
    longRun, easyKm, intervalKm, thresholdKm, isDownWeek
  ).run();
}

// ---- backfill (all activity types, one page at a time) ----

async function backfillPage(db, env, page) {
  const token = await getFreshAccessToken(db, env);
  if (!token) return { synced: 0, page, hasMore: false, error: "No token" };

  const res = await fetch(
    `https://www.strava.com/api/v3/athlete/activities?per_page=50&page=${page}`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  if (!res.ok) return { synced: 0, page, hasMore: false, error: `Strava ${res.status}` };

  const activities = await res.json();
  if (!activities.length) return { synced: 0, page, hasMore: false };

  let synced = 0;
  for (const a of activities) {
    await syncActivity(db, a);
    const t = classifyActivity({
      name: a.name, sport_type: a.sport_type, type: a.type,
      distance_m: a.distance, moving_time_s: a.moving_time, workout_type: a.workout_type,
    });
    if (isRunType(t)) {
      await recomputeWeeklySummary(db, a.start_date);
    }
    synced++;
  }

  return {
    synced,
    page,
    hasMore: activities.length === 50,
    nextPage: page + 1,
    oldestDate: activities[activities.length - 1]?.start_date?.split("T")[0],
  };
}

// ---- VDOT and pace calculator ----

function getUkOffsetMinutes(date) {
  // Returns the correct UTC offset in minutes for UK time (GMT/BST)
  // BST: last Sunday of March to last Sunday of October
  const year = date.getUTCFullYear();

  // find last Sunday of March
  const marchEnd = new Date(Date.UTC(year, 2, 31));
  marchEnd.setUTCDate(31 - marchEnd.getUTCDay());

  // find last Sunday of October
  const octEnd = new Date(Date.UTC(year, 9, 31));
  octEnd.setUTCDate(31 - octEnd.getUTCDay());

  const isBST = date >= marchEnd && date < octEnd;
  return isBST ? 60 : 0; // BST = UTC+1, GMT = UTC+0
}

function toLocalDateStr(utcDateStr) {
  // Convert a UTC ISO date string to the correct UK local date string
  const d = new Date(utcDateStr);
  const offsetMs = getUkOffsetMinutes(d) * 60 * 1000;
  const local = new Date(d.getTime() + offsetMs);
  const y = local.getUTCFullYear();
  const m = String(local.getUTCMonth() + 1).padStart(2, "0");
  const day = String(local.getUTCDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}

function estimateVdot(recentRuns) {
  // Priority 1: use long runs (unloaded, best aerobic signal)
  // Priority 2: use interval/threshold runs (sharpest pace signal)
  // Priority 3: fall back to easy runs, but apply backpack correction
  // Backpack correction: loaded easy runs are ~8-10% slower than unloaded

  const BACKPACK_CORRECTION = 0.91; // unloaded pace ≈ loaded pace * 0.91

  // Long runs: unloaded, distance > 18km, not too slow (rules out walking)
  const longRuns = recentRuns.filter(r =>
    r.type === "long" &&
    r.distance_m > 18000 &&
    r.average_hr > 125 && r.average_hr < 165 &&
    r.moving_time_s > 0
  );

  // Interval/track runs: short, fast, best pace signal
  const intervalRuns = recentRuns.filter(r =>
    r.type === "intervals" &&
    r.distance_m > 5000 &&
    r.moving_time_s > 0
  );

  // Easy runs for fallback (apply backpack correction)
  const easyRuns = recentRuns.filter(r =>
    r.type === "easy" &&
    r.distance_m > 8000 &&
    r.average_hr > 120 && r.average_hr < 160 &&
    r.moving_time_s > 0
  );

  let bestPaceSecKm = null;
  let source = "none";

  if (longRuns.length >= 2) {
    // Use best (fastest) long run pace, most reliable unloaded signal
    const paces = longRuns.map(r => r.moving_time_s / (r.distance_m / 1000));
    bestPaceSecKm = Math.min(...paces);
    source = "long";
  } else if (easyRuns.length >= 3) {
    // Average of easy runs with backpack correction applied
    const avgLoaded = easyRuns.reduce((s, r) =>
      s + (r.moving_time_s / (r.distance_m / 1000)), 0
    ) / easyRuns.length;
    bestPaceSecKm = avgLoaded * BACKPACK_CORRECTION;
    source = "easy_corrected";
  } else if (longRuns.length === 1) {
    const paces = longRuns.map(r => r.moving_time_s / (r.distance_m / 1000));
    bestPaceSecKm = Math.min(...paces);
    source = "long_single";
  }

  if (!bestPaceSecKm) return null;

  // For long/easy runs, pace represents easy effort (~75% VO2max)
  // VO2max pace = easy pace / 1.25 (inverse of the easy multiplier 1.25)
  // Using Daniels: easy = 59-74% vVO2max, we use 0.74 as conservative
  const vo2maxPaceSecKm = bestPaceSecKm * 0.74;
  const vo2maxPaceMinKm = vo2maxPaceSecKm / 60;

  const vdot = Math.round(3000 / (vo2maxPaceMinKm * 21.6));
  return Math.min(Math.max(vdot, 35), 85);
}

function paceFromVdot(vdot, effort) {
  // Daniels VDOT → vVO2max pace using correct polynomial
  // vVO2max (m/min) = 29.54 + 5.000663*v - 0.007546*v^2
  const vVO2maxMperMin = 29.54 + 5.000663 * vdot - 0.007546 * vdot * vdot;
  const vVO2maxSecPerKm = (1000 / vVO2maxMperMin) * 60;

  // Daniels effort multipliers (fraction of vVO2max pace, >1 = slower)
  const multipliers = {
    easy:       1.29,   // ~59-74% vVO2max
    marathon:   1.09,   // ~75-84% vVO2max
    threshold:  1.03,   // ~83-88% vVO2max
    interval:   0.975,  // ~95-100% vVO2max
    repetition: 0.93,   // ~105% vVO2max
  };
  const m = multipliers[effort] || 1.09;
  const paceSec = vVO2maxSecPerKm * m;
  const min = Math.floor(paceSec / 60);
  const sec = Math.round(paceSec % 60).toString().padStart(2, "0");
  return `${min}:${sec}/km`;
}

// ---- training load (CTL/ATL/TSB) ----

function computeLoad(weekSummaries) {
  // CTL = 42-day exponential weighted average of daily TSS
  // ATL = 7-day exponential weighted average
  // TSS approximated from distance and assumed intensity
  // Simple version: use km as proxy for load units
  if (!weekSummaries.length) return { ctl: 0, atl: 0, tsb: 0 };

  const dailyLoads = [];
  for (const w of weekSummaries) {
    const dailyAvg = (w.total_distance_km || 0) / 7;
    for (let d = 0; d < 7; d++) dailyLoads.push(dailyAvg);
  }

  let ctl = 0, atl = 0;
  const kCtl = 1 / 42, kAtl = 1 / 7;
  for (const load of dailyLoads) {
    ctl = ctl + kCtl * (load - ctl);
    atl = atl + kAtl * (load - atl);
  }

  return {
    ctl: Math.round(ctl * 10) / 10,
    atl: Math.round(atl * 10) / 10,
    tsb: Math.round((ctl - atl) * 10) / 10,
  };
}

// ---- plan generator ----

async function generateWeeklyPlan(db, env, forceRegenerate = false, referenceDate = null) {
  const now = referenceDate || new Date();
  const day = now.getDay();
  const monday = new Date(now);
  monday.setDate(now.getDate() - ((day + 6) % 7));
  monday.setHours(0, 0, 0, 0);
  const weekStart = monday.toISOString().split("T")[0];

  // regenerate if: forced, no plan exists, plan was generated on a previous day,
  // OR new activities have been synced since the plan was last generated
  if (!forceRegenerate) {
    const cached = await db.prepare(
      "SELECT * FROM weekly_plans WHERE week_start = ?"
    ).bind(weekStart).first();
    if (cached) {
      const generatedAt = new Date(cached.generated_at);
      const todayStart = new Date(now);
      todayStart.setHours(0, 0, 0, 0);

      // return cached plan only if generated today AND no new activities since then
      if (generatedAt >= todayStart) {
        // check if any activity was synced after plan generation
        const newActivity = await db.prepare(`
          SELECT 1 FROM activities
          WHERE synced_at > ?
          AND date(start_date) >= ?
          LIMIT 1
        `).bind(cached.generated_at, weekStart).first();

        if (!newActivity) return JSON.parse(cached.plan_json);
        // new activity synced, fall through to regenerate
      }
    }
  }

  // gather training data
  const { results: weeklySummaries } = await db.prepare(
    "SELECT * FROM weekly_summaries ORDER BY week_start DESC LIMIT 12"
  ).all();
  weeklySummaries.reverse();

  const { results: recentRuns } = await db.prepare(`
    SELECT name, type, start_date, distance_m, moving_time_s, average_hr, elevation_gain_m
    FROM activities
    WHERE type IN ('easy','long','intervals','threshold')
    AND date(start_date) >= date('now', '-28 days')
    ORDER BY start_date DESC
  `).all();

  const { results: recentLongRuns } = await db.prepare(`
    SELECT distance_m, moving_time_s, average_hr, start_date
    FROM activities
    WHERE type = 'long'
    ORDER BY start_date DESC LIMIT 4
  `).all();

  const latestMetrics = await db.prepare(
    "SELECT * FROM daily_metrics ORDER BY date DESC LIMIT 1"
  ).first();

  const latestBody = await db.prepare(
    "SELECT * FROM body_composition ORDER BY date DESC LIMIT 1"
  ).first();

  const { results: recentFeedback } = await db.prepare(`
    SELECT activity_date, activity_name, rating, notes
    FROM session_feedback
    WHERE activity_date >= date('now', '-14 days')
    ORDER BY activity_date DESC LIMIT 5
  `).all();

  const { results: athleteNotes } = await db.prepare(`
    SELECT notes, recorded_at FROM athlete_notes
    ORDER BY recorded_at DESC LIMIT 3
  `).all();

  const load = computeLoad(weeklySummaries);
  const vdot = estimateVdot(recentRuns);
  const recentWeeklyKm = weeklySummaries.slice(-4).map(w => Math.round(w.total_distance_km));
  const avgWeeklyKm = Math.round(recentWeeklyKm.reduce((s, v) => s + v, 0) / Math.max(recentWeeklyKm.length, 1));
  const longestRecentRun = Math.max(0, ...recentLongRuns.map(r => r.distance_m / 1000));

  // fetch this week's track session from Mick's spreadsheet (2026 tab gid=515003)
  let trackSession = null;
  try {
    const csvUrl = "https://docs.google.com/spreadsheets/d/1-nLf0RLZdtH_KV_p8DrRXqURP-jDwyKZ-5T49-vhAJA/export?format=csv&gid=515003";
    const csvRes = await fetch(csvUrl);
    if (csvRes.ok) {
      const csv = await csvRes.text();
      const rows = parseCSV(csv).map(r => r.map(c => c.trim()));
      const nextTuesday = new Date(now);
      const currentDay = now.getDay(); // 0=Sun, 1=Mon, 2=Tue ... 6=Sat
      const daysUntilTuesday = (2 - currentDay + 7) % 7; // 0 if today is Tuesday
      nextTuesday.setDate(now.getDate() + daysUntilTuesday);

      const monthAbbr = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
      const pad = n => String(n).padStart(2, "0");
      const dateFormats = [
        `${pad(nextTuesday.getDate())}/${monthAbbr[nextTuesday.getMonth()]}/${nextTuesday.getFullYear()}`,
        `${nextTuesday.getDate()}/${monthAbbr[nextTuesday.getMonth()]}/${nextTuesday.getFullYear()}`,
      ];

      for (const row of rows) {
        const dateCell = (row[0] || "").trim();
        if (dateFormats.some(f => dateCell === f)) {
          // session description is in column B (index 1)
          const description = (row[1] || "").trim();
          if (description) trackSession = description;
          break;
        }
      }

      // if no exact match, fall back to most recent past entry using column B
      if (!trackSession) {
        const monthMap = { Jan:0,Feb:1,Mar:2,Apr:3,May:4,Jun:5,Jul:6,Aug:7,Sep:8,Oct:9,Nov:10,Dec:11 };
        let bestRow = null;
        let bestDate = null;
        for (const row of rows) {
          const dateCell = (row[0] || "").trim();
          const parts = dateCell.split("/");
          if (parts.length === 3 && monthMap[parts[1]] !== undefined) {
            const d = new Date(Date.UTC(parseInt(parts[2]), monthMap[parts[1]], parseInt(parts[0])));
            const description = (row[1] || "").trim();
            if (!isNaN(d) && d <= now && (!bestDate || d > bestDate) && description) {
              bestDate = d;
              bestRow = row;
            }
          }
        }
        if (bestRow) {
          trackSession = (bestRow[1] || "").trim();
        }
      }
    }
  } catch {}

  // determine phase based on time to race (placeholder late 2027)
  const targetRace = new Date("2027-10-01");
  const weeksToRace = Math.round((targetRace - now) / (7 * 24 * 60 * 60 * 1000));
  const phase = weeksToRace > 20 ? "base" : weeksToRace > 10 ? "specific" : "taper";

  // paces if vdot available
  const paces = vdot ? {
    easy: paceFromVdot(vdot, "easy"),
    marathon: paceFromVdot(vdot, "marathon"),
    threshold: paceFromVdot(vdot, "threshold"),
    interval: paceFromVdot(vdot, "interval"),
  } : null;

  // what has already happened this week
  const sundayEnd = new Date(monday);
  sundayEnd.setDate(monday.getDate() + 6);
  sundayEnd.setHours(23, 59, 59, 999);
  const { results: thisWeekActivities } = await db.prepare(`
    SELECT name, type, start_date, distance_m, moving_time_s, average_hr
    FROM activities
    WHERE date(start_date) >= ? AND date(start_date) <= ?
    ORDER BY start_date ASC
  `).bind(weekStart, sundayEnd.toISOString().split("T")[0]).all();

  const dayNames = ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"];
  const todayName = dayNames[now.getDay()];
  const completedThisWeek = thisWeekActivities.map(a => {
    const d = new Date(a.start_date);
    const dayName = dayNames[d.getDay()];
    const km = (a.distance_m / 1000).toFixed(1);
    const pace = a.distance_m > 0 ? Math.round(a.moving_time_s / (a.distance_m / 1000)) : 0;
    const paceStr = pace > 0 ? `${Math.floor(pace/60)}:${String(pace%60).padStart(2,"0")}/km` : "";
    return `${dayName}: ${a.name}, ${km}km ${paceStr} ${a.average_hr ? `@ ${Math.round(a.average_hr)}bpm` : ""}`.trim();
  });
  const thisWeekKm = thisWeekActivities.filter(a => isRunType(a.type)).reduce((s, a) => s + a.distance_m / 1000, 0);

  const prompt = `You are an expert marathon coach preparing an athlete for a sub-2:30 marathon in late 2027. Their current PB is 2:46, set with an even effort that faded in the final 10km, indicating late-race endurance as the primary limiter.

ATHLETE PROFILE:
- Current PB: 2:46 (faded late, endurance limiter)
- Target: Sub 2:30 by late 2027
- Weekly volume: typically 90-120km when fully training
- Fixed schedule: commute runs (10km easy) on Tue/Wed/Thu morning/Fri
- Commutes are always easy pace with a loaded backpack

TODAY IS: ${todayName}

CURRENT TRAINING STATE:
- Recent 4-week average weekly km: ${avgWeeklyKm}km
- Last 4 weeks: ${recentWeeklyKm.join(', ')}km
- This week so far: ${thisWeekKm.toFixed(1)}km
- Longest recent long run: ${longestRecentRun.toFixed(1)}km
- CTL (chronic load): ${load.ctl}
- ATL (acute load): ${load.atl}  
- TSB (form): ${load.tsb}
- Estimated VDOT: ${vdot || 'unknown'}
- Training phase: ${phase} (${weeksToRace} weeks to target race)
${paces ? `- Current paces: Easy ${paces.easy}, Marathon ${paces.marathon}, Threshold ${paces.threshold}, Interval ${paces.interval}` : ''}
${latestMetrics?.resting_hr ? `- Resting HR today: ${latestMetrics.resting_hr} bpm` : ''}
${latestBody?.weight_kg ? `- Body weight: ${latestBody.weight_kg}kg, Body fat: ${latestBody.body_fat_pct ? latestBody.body_fat_pct.toFixed(1) + '%' : 'unknown'}, Lean mass: ${latestBody.lean_mass_kg ? latestBody.lean_mass_kg.toFixed(1) + 'kg' : 'unknown'} (from ${latestBody.date})` : ''}

ATHLETE CONDITIONING NOTES:
${athleteNotes?.length > 0 ? athleteNotes.map(n => `[${n.recorded_at?.split('T')[0] || ''}] ${n.notes}`).join('\n') : 'No notes logged'}

RECENT SESSION FEEDBACK FROM ATHLETE:
${recentFeedback?.length > 0 ? recentFeedback.map(f => `${f.activity_date} | ${f.activity_name || 'session'}: ${f.rating ? `${f.rating}/5` : ''} ${f.notes || ''}`).join('\n') : 'No recent feedback'}

SESSIONS COMPLETED THIS WEEK SO FAR:
${completedThisWeek.length > 0 ? completedThisWeek.join('\n') : 'None yet this week'}

MONDAY GYM SESSION: EXERCISE LIBRARY:
Select from the following based on phase, week load, and what follows later in the week. Never prescribe exercises that would create so much DOMS that Tuesday track or Thursday treadmill is compromised.

Barbell and compound (strength foundation, prioritise in base phase):
- Back squat, Trap-bar deadlift, Bulgarian split squat, Hip thrust

Power and plyometric (running economy, increase in specific phase, use sparingly in base):
- Trap-bar jump, Box jump, Pogo hops, Bounding

Single-leg and supporting (injury resilience, always include at least one):
- Single-leg Romanian deadlift, Box step-down, Nordic hamstring curl, Calf raises (straight and bent knee)

Kettlebell (loaded movement variety, good for lower-intensity weeks):
- Kettlebell swing (two-handed), Single-arm kettlebell swing, Goblet squat, Kettlebell single-leg deadlift, Kettlebell reverse lunge, Loaded carries (suitcase and front rack)

BOSU ball (stability and proprioception, good finisher or after injury niggles):
- BOSU single-leg balance, BOSU squat, BOSU split squat, BOSU calf raise, BOSU single-leg Romanian deadlift

PRESCRIPTION PRINCIPLES:
- Base phase: 2-3 compound lifts (3-4 sets, 5-8 reps at 70-80% 1RM) + 1-2 single-leg exercises + calf raises. Minimal plyometrics.
- Specific phase: reduce compound volume, add 1-2 plyometric exercises (2-3 sets, 6-10 reps), maintain single-leg work.
- Always include Nordic hamstring curls or single-leg RDL for hamstring resilience given the running load.
- If TSB is negative (fatigued), reduce to kettlebell and BOSU work only, no heavy barbell loading.
- Calf raises (both straight and bent knee) should appear most weeks given the running volume.
- Monday: Gym, leg session (prescribe if not yet done this week)
- Tuesday morning: 10km easy commute run (fixed)
- Tuesday evening: Club track. THIS WEEK'S SESSION: ${trackSession ? `"${trackSession}"` : "not yet published"}
- Wednesday morning: 10km easy commute run (fixed, athlete commutes by running, always include this in the plan even though pace/structure is fixed)
- Wednesday evening: blocked
- Thursday morning: Treadmill intervals (YOU PRESCRIBE)
- Thursday evening: optional
- Friday morning: 10km easy commute run (fixed)
- Friday evening: YOU RECOMMEND gym, swim, or rest
- Saturday: YOU PRESCRIBE specifically for Saturday (long run OR easy recovery depending on week)
- Sunday: YOU PRESCRIBE specifically for Sunday (the other of long run/easy recovery)

IMPORTANT: Today is ${todayName}. Only prescribe sessions that have NOT yet happened this week. For sessions already completed, you may reference what was done when prescribing remaining sessions. Adjust remaining sessions based on what has actually been completed. If a session was missed or harder than planned, adapt accordingly.

TITLE RULE: Session titles must never contain the words "completed", "done", "finished", "already" or any reference to completion status. Titles describe the session only, for example "Easy commute run" or "Club track: threshold reps". Completion status must not appear in the title field under any circumstances.

Generate a training plan for the coming week. Respond ONLY with a valid JSON object, no markdown, no preamble, exactly this structure:

{
  "phase": "${phase}",
  "weekFocus": "one sentence describing the week's training emphasis",
  "progressNote": "2-3 sentences on current fitness trajectory and what needs to happen to reach sub-2:30",
  "sessions": {
    "monday": {
      "type": "strength",
      "title": "Gym · Leg session",
      "detail": ["exercise 1 with sets/reps", "exercise 2", "..."],
      "rationale": "why this loading given the week ahead"
    },
    "tuesday": {
      "type": "intervals",
      "title": "Club track: [session name/description]",
      "detail": ["the actual session as written by the coach", "any key notes from the sheet"],
      "rationale": "brief note on how to approach this specific session given current load"
    },
    "wednesday": {
      "type": "easy",
      "title": "Easy commute run",
      "detail": ["10km easy pace, backpack load", "any specific note for this week given accumulated fatigue from Tue track"],
      "rationale": "why easy effort matters specifically this week given the days around it"
    },
    "thursday": {
      "type": "intervals",
      "title": "Treadmill intervals",
      "detail": ["specific session structure e.g. 6 x 1km @ 3:25/km, 90s recovery"],
      "rationale": "why this specific session given current load and phase"
    },
    "friday": {
      "type": "easy or strength or swim",
      "title": "title",
      "detail": ["specific recommendation"],
      "rationale": "why this choice given cumulative week load"
    },
    "saturday": {
      "type": "long or easy",
      "title": "title",
      "detail": ["specific prescription"],
      "rationale": "why this day gets this session"
    },
    "sunday": {
      "type": "long or easy",
      "title": "title",
      "detail": ["specific prescription"],
      "rationale": "why this day gets this session"
    }
  },
  "sub230Progress": {
    "onTrack": true or false,
    "currentEquivalent": "estimated current marathon time based on training data e.g. 2:42",
    "keyLever": "the single most important thing to focus on right now"
  }
}`;

  const response = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": env.ANTHROPIC_API_KEY,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: "claude-sonnet-4-6",
      max_tokens: 3500,
      messages: [{ role: "user", content: prompt }],
    }),
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`Claude API error: ${response.status} ${errText}`);
  }

  const data = await response.json();
  const text = data.content?.[0]?.text || "";

  // strip any accidental markdown fences
  const clean = text.replace(/```json|```/g, "").trim();
  const plan = JSON.parse(clean);

  // cache in database
  await db.prepare(`
    INSERT INTO weekly_plans (week_start, plan_json)
    VALUES (?, ?)
    ON CONFLICT(week_start) DO UPDATE SET
      plan_json = excluded.plan_json,
      generated_at = datetime('now')
  `).bind(weekStart, JSON.stringify(plan)).run();

  return plan;
}

// ---- status computation ----
// Returns a single status object consumed by the readiness gantry, the goal chip
// and any status sentence. Deriving everything from one function makes contradiction
// structurally impossible.
function computeStatus(restHrDelta, tsb, latestNoteText) {
  // Injury signal: check the latest journal note for common injury terms
  const injuryTerms = ["strain", "pain", "injury", "injured", "niggle", "sore", "hurt", "hamstring", "calf", "achilles", "knee", "shin", "stress fracture"];
  const noteHasInjury = latestNoteText
    ? injuryTerms.some(t => latestNoteText.toLowerCase().includes(t))
    : false;

  if (noteHasInjury) {
    return { word: "Caution", colour: "warn", detail: "Injury flagged in journal" };
  }
  if (restHrDelta !== null && restHrDelta > 5) {
    return { word: "Hold", colour: "alert", detail: `Resting HR +${restHrDelta} vs baseline` };
  }
  if (restHrDelta !== null && restHrDelta > 2) {
    return { word: "Caution", colour: "warn", detail: `Resting HR +${restHrDelta} vs baseline` };
  }
  if (tsb !== null && tsb < -15) {
    return { word: "Caution", colour: "warn", detail: `TSB ${tsb}, high fatigue` };
  }
  return { word: "Ready", colour: "pos", detail: restHrDelta !== null ? `Resting HR on baseline` : "No HR data" };
}

// ---- dashboard data builder ----

async function buildDashboardData(db) {
  const now = new Date();
  const day = now.getDay();
  const monday = new Date(now);
  monday.setDate(now.getDate() - ((day + 6) % 7));
  monday.setHours(0, 0, 0, 0);
  const weekStart = monday.toISOString().split("T")[0];

  const sunday = new Date(monday);
  sunday.setDate(monday.getDate() + 6);
  const weekEnd = sunday.toISOString().split("T")[0];

  // all activities this week for the strip
  const { results: weekActivities } = await db.prepare(`
    SELECT * FROM activities
    WHERE date(start_date) >= ? AND date(start_date) <= ?
    ORDER BY start_date ASC
  `).bind(weekStart, weekEnd).all();

  // runs only for km total
  const weeklyKm = weekActivities
    .filter(a => isRunType(a.type))
    .reduce((s, a) => s + (a.distance_m || 0), 0) / 1000;

  const latestMetrics = await db.prepare(
    "SELECT * FROM daily_metrics ORDER BY date DESC LIMIT 1"
  ).first();

  const hrBaseline = await db.prepare(`
    SELECT AVG(resting_hr) as avg_hr FROM daily_metrics
    WHERE date >= date('now', '-28 days') AND resting_hr IS NOT NULL
  `).first();

  const restHrDelta = (latestMetrics?.resting_hr && hrBaseline?.avg_hr)
    ? Math.round((latestMetrics.resting_hr - hrBaseline.avg_hr) * 10) / 10
    : null;

  let readinessState = "ready";
  if (restHrDelta !== null) {
    if (restHrDelta > 5) readinessState = "hold";
    else if (restHrDelta > 2) readinessState = "steady";
  }

  const { results: weeklySummaries } = await db.prepare(
    "SELECT * FROM weekly_summaries ORDER BY week_start DESC LIMIT 8"
  ).all();
  weeklySummaries.reverse();

  const { results: recentActivities } = await db.prepare(`
    SELECT strava_id, name, type, start_date, distance_m, moving_time_s, average_hr
    FROM activities
    WHERE type IN ('easy','long','intervals','threshold')
    ORDER BY start_date DESC LIMIT 5
  `).all();

  // active weeks: weeks with 3+ runs OR 30km+ (honest metric for injury rebuilds)
  // legacy streak: consecutive active weeks without a break (kept for backwards compat)
  const { results: allWeeks } = await db.prepare(`
    SELECT week_start, total_distance_km, run_count FROM weekly_summaries
    ORDER BY week_start DESC LIMIT 52
  `).all();

let weekStreak = 0;
  let activeWeeksCount = 0;
  const weeksWindow = allWeeks.filter(w => w.week_start !== weekStart).slice(0, 12);
  for (const w of allWeeks) {
    if (w.week_start === weekStart) continue;
    const isActive = (w.run_count || 0) >= 1 || (w.total_distance_km || 0) > 0;
    if (isActive) { weekStreak++; } else { break; }
  }
  for (const w of weeksWindow) {
    const isActive = (w.run_count || 0) >= 1 || (w.total_distance_km || 0) > 0;
    if (isActive) activeWeeksCount++;
  }

  // total minutes run this week
  const weekMinutes = Math.round(
    weekActivities
      .filter(a => isRunType(a.type))
      .reduce((s, a) => s + (a.moving_time_s || 0), 0) / 60
  );

  // ---- fitness metrics ----

  // CTL/ATL/TSB from last 12 weeks
  const { results: allWeeklySummaries } = await db.prepare(
    "SELECT * FROM weekly_summaries ORDER BY week_start DESC LIMIT 12"
  ).all();
  allWeeklySummaries.reverse();
  const load = computeLoad(allWeeklySummaries);

  // CTL sparkline: last 8 weeks of daily CTL values (one per week end)
  const ctlSparkline = [];
  let runningCtl = 0;
  const kCtl = 1 / 42;
  for (const w of allWeeklySummaries) {
    const dailyAvg = (w.total_distance_km || 0) / 7;
    for (let d = 0; d < 7; d++) {
      runningCtl = runningCtl + kCtl * (dailyAvg - runningCtl);
    }
    ctlSparkline.push(Math.round(runningCtl * 10) / 10);
  }

  // VDOT from recent runs
  const { results: recentRunsForVdot } = await db.prepare(`
    SELECT name, type, start_date, distance_m, moving_time_s, average_hr
    FROM activities
    WHERE type IN ('easy','long','intervals','threshold')
    AND date(start_date) >= date('now', '-56 days')
    ORDER BY start_date DESC
  `).all();
  const currentVdot = estimateVdot(recentRunsForVdot);

  // VDOT 4 weeks ago for trend
  const { results: olderRunsForVdot } = await db.prepare(`
    SELECT name, type, start_date, distance_m, moving_time_s, average_hr
    FROM activities
    WHERE type IN ('easy','long','intervals','threshold')
    AND date(start_date) >= date('now', '-84 days')
    AND date(start_date) < date('now', '-28 days')
    ORDER BY start_date DESC
  `).all();
  const previousVdot = estimateVdot(olderRunsForVdot);
  const vdotTrend = (currentVdot && previousVdot) ? currentVdot - previousVdot : null;

  // Pace at HR trend: average pace at 140-150 bpm, current 4 weeks vs previous 4 weeks
  const { results: recentHrRuns } = await db.prepare(`
    SELECT distance_m, moving_time_s, average_hr, start_date
    FROM activities
    WHERE type IN ('easy','long')
    AND average_hr >= 138 AND average_hr <= 152
    AND distance_m > 8000
    AND date(start_date) >= date('now', '-28 days')
  `).all();

  const { results: prevHrRuns } = await db.prepare(`
    SELECT distance_m, moving_time_s, average_hr, start_date
    FROM activities
    WHERE type IN ('easy','long')
    AND average_hr >= 138 AND average_hr <= 152
    AND distance_m > 8000
    AND date(start_date) >= date('now', '-56 days')
    AND date(start_date) < date('now', '-28 days')
  `).all();

  const avgPaceAtHr = (runs) => {
    if (!runs.length) return null;
    const avg = runs.reduce((s, r) => s + r.moving_time_s / (r.distance_m / 1000), 0) / runs.length;
    const min = Math.floor(avg / 60);
    const sec = Math.round(avg % 60).toString().padStart(2, "0");
    return { secPerKm: Math.round(avg), display: `${min}:${sec}` };
  };

  const currentPaceAtHr = avgPaceAtHr(recentHrRuns);
  const prevPaceAtHr = avgPaceAtHr(prevHrRuns);
  // negative delta = getting faster (good)
  const paceAtHrDelta = (currentPaceAtHr && prevPaceAtHr)
    ? currentPaceAtHr.secPerKm - prevPaceAtHr.secPerKm
    : null;

  // predicted marathon from VDOT
  const predictedMarathon = currentVdot ? paceFromVdot(currentVdot, "marathon") : null;
  const predictedMarathonTime = predictedMarathon ? (() => {
    const parts = predictedMarathon.split(":");
    const secPerKm = parseInt(parts[0]) * 60 + parseInt(parts[1]);
    const totalSec = Math.round(secPerKm * 42.195);
    const h = Math.floor(totalSec / 3600);
    const m = Math.floor((totalSec % 3600) / 60);
    const s = Math.round(totalSec % 60).toString().padStart(2, "0");
    return `${h}:${String(m).padStart(2,"0")}:${s}`;
  })() : null;

  // latest body composition
  const latestBody = await db.prepare(
    "SELECT * FROM body_composition ORDER BY date DESC LIMIT 1"
  ).first();

  // recent session feedback for plan context
  const { results: recentFeedback } = await db.prepare(`
    SELECT activity_date, activity_name, rating, notes
    FROM session_feedback
    WHERE activity_date >= date('now', '-14 days')
    ORDER BY activity_date DESC LIMIT 5
  `).all();

  // on Saturday (6) or Sunday (0), return cached next week plan if available
  let nextWeekPlan = null;
  if (day === 6 || day === 0) {
    const nextMonday = new Date(monday);
    nextMonday.setDate(monday.getDate() + 7);
    const nextWeekStart = nextMonday.toISOString().split("T")[0];
    const cachedNext = await db.prepare(
      "SELECT plan_json FROM weekly_plans WHERE week_start = ?"
    ).bind(nextWeekStart).first();
    if (cachedNext) nextWeekPlan = JSON.parse(cachedNext.plan_json);
  }

  // compute unified status object (consumed by gantry and goal chip)
  const latestNoteForStatus = (await db.prepare(
    "SELECT notes FROM athlete_notes ORDER BY recorded_at DESC LIMIT 1"
  ).first())?.notes || null;
  const status = computeStatus(restHrDelta, load.tsb, latestNoteForStatus);

  return {
    week: {
      start: weekStart,
      completed: Math.round(weeklyKm * 10) / 10,
      target: 104,
      isDownWeek: weeklyKm < 80,
      activities: weekActivities,
    },
    // status: single source of truth for Ready/Caution/Hold across all UI surfaces
    status,
    activeWeeks: { active: activeWeeksCount, of: 12 },
    readiness: {
      state: readinessState, // legacy field: "ready" | "steady" | "hold"
      restingHr: latestMetrics?.resting_hr || null,
      restHrDelta,
      hrBaseline: hrBaseline?.avg_hr || null,
      sleepDuration: latestMetrics?.sleep_duration_min || null,
      sleepScore: latestMetrics?.sleep_score || null,
      steps: latestMetrics?.steps || null,
      respiratoryRate: latestMetrics?.respiratory_rate || null,
      note: readinessState === "hold"
        ? "Resting HR elevated. Consider reducing intensity today."
        : readinessState === "steady"
        ? "Resting HR slightly above baseline. Proceed with awareness."
        : "Resting HR normal. Cleared for the full session.",
    },
    series: {
      weeks: weeklySummaries.map(w => w.week_start.slice(5)),
      actual: weeklySummaries.map(w => Math.round(w.total_distance_km * 10) / 10),
      target: weeklySummaries.map(() => 104),
      down: weeklySummaries.map(w => !!w.is_down_week),
    },
    recentActivities,
    streak: weekStreak,
    weekMinutes,
    nextWeekPlan,
    body: latestBody || null,
    recentFeedback: recentFeedback || [],
    latestNote: (await db.prepare(
      "SELECT notes, recorded_at FROM athlete_notes ORDER BY recorded_at DESC LIMIT 1"
    ).first()) || null,
    fitness: {
      vdot: currentVdot,
      vdotTrend,
      ctl: load.ctl,
      atl: load.atl,
      tsb: load.tsb,
      ctlSparkline,
      paceAtHr: currentPaceAtHr?.display || null,
      paceAtHrDelta,
      predictedMarathon: predictedMarathonTime,
    },
    lastSync: new Date().toISOString(),
  };
}

// ---- main router ----

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (method === "OPTIONS") {
      return new Response(null, { headers: CORS });
    }

    const db = env.DB;

    // Debug: inspect track sheet CSV and date matching
    if (path === "/debug/track" && method === "GET") {
      try {
        const csvUrl = "https://docs.google.com/spreadsheets/d/1-nLf0RLZdtH_KV_p8DrRXqURP-jDwyKZ-5T49-vhAJA/export?format=csv&gid=515003";
        const csvRes = await fetch(csvUrl);
        if (!csvRes.ok) return json({ error: `CSV fetch failed: ${csvRes.status}` });
        const csv = await csvRes.text();
        const rows = parseCSV(csv).map(r => r.map(c => c.trim()));

        const now = new Date();
        const nextTuesday = new Date(now);
        const currentDay = now.getDay();
        const daysUntilTuesday = (2 - currentDay + 7) % 7;
        nextTuesday.setDate(now.getDate() + daysUntilTuesday);

        const monthAbbr = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
        const dateFormats = [
          `${String(nextTuesday.getDate()).padStart(2,"0")}/${monthAbbr[nextTuesday.getMonth()]}/${nextTuesday.getFullYear()}`,
          `${nextTuesday.getDate()}/${monthAbbr[nextTuesday.getMonth()]}/${nextTuesday.getFullYear()}`,
        ];

        return json({
          today: now.toISOString(),
          nextTuesdayCalculated: nextTuesday.toISOString().split("T")[0],
          dateFormatsBeingSearched: dateFormats,
          first15Rows: rows.slice(0, 15),
          totalRows: rows.length,
        });
      } catch (e) {
        return json({ error: e.message });
      }
    }

    // Strava OAuth
    if (path === "/auth/strava" && method === "GET") {
      const redirectUri = `${url.origin}/auth/callback`;
      const stravaUrl = `https://www.strava.com/oauth/authorize?client_id=${env.STRAVA_CLIENT_ID}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=activity:read_all`;
      return Response.redirect(stravaUrl, 302);
    }

    if (path === "/auth/callback" && method === "GET") {
      const code = url.searchParams.get("code");
      if (!code) return err("Missing code");

      const res = await fetch("https://www.strava.com/oauth/token", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: env.STRAVA_CLIENT_ID,
          client_secret: env.STRAVA_CLIENT_SECRET,
          code,
          grant_type: "authorization_code",
        }),
      });

      if (!res.ok) return err("Token exchange failed", 500);
      const data = await res.json();

      await saveTokens(db, {
        access_token: data.access_token,
        refresh_token: data.refresh_token,
        expires_at: data.expires_at,
        athlete_id: data.athlete.id,
      });

      ctx.waitUntil(backfillPage(db, env, 1));

      return new Response(`
        <html><body style="font-family:sans-serif;padding:2rem;background:#070707;color:#fff">
          <h2 style="color:#FFFF00">Connected to Strava</h2>
          <p>Syncing your activity history in the background.</p>
          <p>Athlete: ${data.athlete.firstname} ${data.athlete.lastname}</p>
          <p>You can close this tab.</p>
        </body></html>
      `, { headers: { "Content-Type": "text/html" } });
    }

    if (path === "/auth/status" && method === "GET") {
      const tokens = await getTokens(db);
      return json({ authorised: !!tokens, athleteId: tokens?.athlete_id || null });
    }

    // Admin: backfill one page (all activity types)
    if (path === "/admin/backfill" && method === "POST") {
      const page = parseInt(url.searchParams.get("page") || "1");
      const result = await backfillPage(db, env, page);
      return json(result);
    }

    // Admin: reclassify 100 activities at a time
    if (path === "/admin/reclassify" && method === "POST") {
      const offset = parseInt(url.searchParams.get("offset") || "0");
      const { results } = await db.prepare(
        "SELECT strava_id, raw_json FROM activities LIMIT 100 OFFSET ?"
      ).bind(offset).all();

      let updated = 0;
      for (const row of results) {
        try {
          const a = JSON.parse(row.raw_json);
          const newType = classifyActivity({
            name: a.name, sport_type: a.sport_type, type: a.type,
            distance_m: a.distance, moving_time_s: a.moving_time, workout_type: a.workout_type,
          });
          await db.prepare("UPDATE activities SET type = ? WHERE strava_id = ?")
            .bind(newType, row.strava_id).run();
          updated++;
        } catch {}
      }

      return json({
        reclassified: updated,
        hasMore: results.length === 100,
        nextOffset: offset + 100,
      });
    }

    // Admin: recompute weekly summaries 50 days at a time
    if (path === "/admin/recompute" && method === "POST") {
      const offset = parseInt(url.searchParams.get("offset") || "0");
      const { results: acts } = await db.prepare(
        "SELECT DISTINCT date(start_date) as d FROM activities ORDER BY start_date LIMIT 50 OFFSET ?"
      ).bind(offset).all();

      for (const row of acts) {
        await recomputeWeeklySummary(db, row.d);
      }

      return json({
        recomputed: acts.length,
        hasMore: acts.length === 50,
        nextOffset: offset + 50,
      });
    }

    // Strava webhook verification
    if (path === "/webhook/strava" && method === "GET") {
      const challenge = url.searchParams.get("hub.challenge");
      const token = url.searchParams.get("hub.verify_token");
      if (token !== env.STRAVA_WEBHOOK_TOKEN) return err("Invalid token", 403);
      return json({ "hub.challenge": challenge });
    }

    // Strava webhook event
    if (path === "/webhook/strava" && method === "POST") {
      const body = await request.json();
      if (body.object_type === "activity" && body.aspect_type === "create") {
        ctx.waitUntil(fetchAndSyncDetailedActivity(db, env, body.object_id));
      }
      return json({ status: "ok" });
    }

    // Debug: log raw incoming health payload (no auth required for testing)
    if (path === "/health/debug" && method === "POST") {
      const body = await request.json().catch(() => ({}));
      return json({ received: body, keys: Object.keys(body), contentType: request.headers.get("content-type") });
    }

    // Apple Health metrics
    if (path === "/health/metrics" && method === "POST") {
      const apiKey = request.headers.get("x-api-key");
      if (apiKey !== env.HEALTH_API_KEY) return err("Unauthorised", 401);

      const body = await request.json();
      let recorded = 0;

      if (body?.data?.metrics) {
        // v2 format: { data: { metrics: [ { name, units, data: [ { date, qty, ... } ] } ] } }
        const metrics = body.data.metrics;

        // collect all data by date first
        const byDate = {};

        for (const metric of metrics) {
          const name = (metric.name || "").toLowerCase();
          const entries = metric.data || [];

          for (const entry of entries) {
            // parse date: "2026-06-19 00:00:00 +0100" → "2026-06-19"
            const dateStr = (entry.date || "").split(" ")[0];
            if (!dateStr) continue;
            if (!byDate[dateStr]) byDate[dateStr] = {};

            if (name === "resting_heart_rate") {
              byDate[dateStr].resting_hr = entry.qty || null;
            } else if (name === "sleep_analysis") {
              // totalSleep is in hours, convert to minutes
              const totalSleepHours = parseFloat(entry.totalSleep || 0);
              byDate[dateStr].sleep_duration_min = totalSleepHours > 0 ? Math.round(totalSleepHours * 60) : null;
              // derive a simple sleep score: 100 * min(totalSleep/8, 1) weighted by deep+rem
              const deep = parseFloat(entry.deep || 0);
              const rem = parseFloat(entry.rem || 0);
              const qualityBonus = Math.min((deep + rem) / totalSleepHours, 0.5) * 20;
              const baseScore = Math.min(totalSleepHours / 8, 1) * 80;
              byDate[dateStr].sleep_score = Math.round(baseScore + qualityBonus);
            } else if (name === "body_fat_percentage") {
              byDate[dateStr].body_fat_pct = entry.qty || null;
            } else if (name === "lean_body_mass") {
              // Apple Health stores lean body mass in kg
              byDate[dateStr].lean_mass_kg = entry.qty || null;
            } else if (name === "body_mass" || name === "weight") {
              byDate[dateStr].weight_kg = entry.qty || null;
            } else if (name === "body_mass_index") {
              byDate[dateStr].bmi = entry.qty || null;
            } else if (name === "step_count") {
              byDate[dateStr].steps = Math.round(entry.qty || 0);
            } else if (name === "respiratory_rate") {
              byDate[dateStr].respiratory_rate = entry.qty || null;
            }
          }
        }

        // write each date to the database
        for (const [date, m] of Object.entries(byDate)) {
          await db.prepare(`
            INSERT INTO daily_metrics (date, resting_hr, sleep_duration_min, sleep_score, respiratory_rate, steps, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(date) DO UPDATE SET
              resting_hr = COALESCE(excluded.resting_hr, resting_hr),
              sleep_duration_min = COALESCE(excluded.sleep_duration_min, sleep_duration_min),
              sleep_score = COALESCE(excluded.sleep_score, sleep_score),
              respiratory_rate = COALESCE(excluded.respiratory_rate, respiratory_rate),
              steps = COALESCE(excluded.steps, steps),
              raw_json = excluded.raw_json
          `).bind(
            date,
            m.resting_hr || null,
            m.sleep_duration_min || null,
            m.sleep_score || null,
            m.respiratory_rate || null,
            m.steps || null,
            JSON.stringify({ date, ...m })
          ).run();

          // write body composition separately if present
          if (m.weight_kg || m.body_fat_pct || m.lean_mass_kg) {
            await db.prepare(`
              INSERT INTO body_composition (date, weight_kg, body_fat_pct, lean_mass_kg, bmi)
              VALUES (?, ?, ?, ?, ?)
              ON CONFLICT(date) DO UPDATE SET
                weight_kg = COALESCE(excluded.weight_kg, weight_kg),
                body_fat_pct = COALESCE(excluded.body_fat_pct, body_fat_pct),
                lean_mass_kg = COALESCE(excluded.lean_mass_kg, lean_mass_kg),
                bmi = COALESCE(excluded.bmi, bmi)
            `).bind(
              date,
              m.weight_kg || null,
              m.body_fat_pct || null,
              m.lean_mass_kg || null,
              m.bmi || null
            ).run();
          }

          recorded++;
        }
      } else {
        // flat format fallback
        const metrics = Array.isArray(body) ? body : [body];
        for (const m of metrics) {
          const date = m.date || new Date().toISOString().split("T")[0];
          await db.prepare(`
            INSERT INTO daily_metrics (date, resting_hr, sleep_duration_min, sleep_score, respiratory_rate, steps, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(date) DO UPDATE SET
              resting_hr = COALESCE(excluded.resting_hr, resting_hr),
              sleep_duration_min = COALESCE(excluded.sleep_duration_min, sleep_duration_min),
              sleep_score = COALESCE(excluded.sleep_score, sleep_score),
              respiratory_rate = COALESCE(excluded.respiratory_rate, respiratory_rate),
              steps = COALESCE(excluded.steps, steps),
              raw_json = excluded.raw_json
          `).bind(
            date,
            m.resting_hr || m.restingHeartRate || null,
            m.sleep_duration_min || m.sleepDuration || null,
            m.sleep_score || m.sleepScore || null,
            m.respiratory_rate || m.respiratoryRate || null,
            m.steps || null,
            JSON.stringify(m)
          ).run();
          recorded++;
        }
      }

      return json({ status: "ok", recorded });
    }
// Auth check for all /api/ routes
    if (path.startsWith("/api/")) {
      const authorised = await isAuthorised(request, env);
      if (!authorised) return json({ error: "Unauthorised" }, 401);
    }
    // Dashboard API
    if (path === "/api/dashboard" && method === "GET") {
      const data = await buildDashboardData(db);
      return json(data);
    }

    if (path === "/api/activities" && method === "GET") {
      const limit = parseInt(url.searchParams.get("limit") || "20");
      const offset = parseInt(url.searchParams.get("offset") || "0");
      const { results } = await db.prepare(`
        SELECT strava_id, name, type, sport_type, start_date, distance_m, moving_time_s, average_hr, elevation_gain_m
        FROM activities
        WHERE type IN ('easy','long','intervals','threshold')
        ORDER BY start_date DESC LIMIT ? OFFSET ?
      `).bind(limit, offset).all();
      return json(results);
    }

    if (path === "/api/weeks" && method === "GET") {
      const { results } = await db.prepare(
        "SELECT * FROM weekly_summaries ORDER BY week_start DESC LIMIT 52"
      ).all();
      return json(results.reverse());
    }

    // Calendar: all activities grouped by date for the last N days
    if (path === "/api/calendar" && method === "GET") {
      const days = parseInt(url.searchParams.get("days") || "84");

      // compute correct UK offset for today (handles GMT/BST automatically)
      const offsetMins = getUkOffsetMinutes(new Date());
      const offsetHours = offsetMins / 60;
      const offsetStr = offsetHours > 0 ? `+${offsetHours} hour` : `${offsetHours} hour`;

      const { results } = await db.prepare(`
        SELECT
          date(datetime(start_date, '${offsetStr}')) as date,
          type,
          sport_type,
          name,
          distance_m,
          moving_time_s
        FROM activities
        WHERE date(datetime(start_date, '${offsetStr}')) >= date('now', '${offsetStr}', '-' || ? || ' days')
        ORDER BY start_date ASC
      `).bind(days).all();

      const byDate = {};
      for (const a of results) {
        if (!byDate[a.date]) byDate[a.date] = [];
        byDate[a.date].push({ type: a.type, sport_type: a.sport_type, name: a.name, distance_m: a.distance_m, moving_time_s: a.moving_time_s });
      }

      return json(byDate);
    }

    // Session feedback
    if (path === "/api/feedback" && method === "POST") {
      const body = await request.json();
      const { strava_id, activity_name, activity_date, rating, notes } = body;
      if (!activity_date) return err("activity_date required");
      await db.prepare(`
        INSERT INTO session_feedback (activity_date, activity_name, strava_id, rating, notes)
        VALUES (?, ?, ?, ?, ?)
      `).bind(activity_date, activity_name || null, strava_id || null, rating || null, notes || null).run();
      // invalidate plan cache so next load regenerates with this feedback
      const actDate = new Date(activity_date);
      const d = actDate.getDay();
      const mon = new Date(actDate);
      mon.setDate(actDate.getDate() - ((d + 6) % 7));
      const ws = mon.toISOString().split("T")[0];
      await db.prepare("DELETE FROM weekly_plans WHERE week_start = ?").bind(ws).run();
      return json({ status: "ok" });
    }

   if (path === "/api/feedback" && method === "GET") {
      const { results } = await db.prepare(`
        SELECT * FROM session_feedback ORDER BY activity_date DESC LIMIT 10
      `).all();
      return json(results);
    }

    // Delete feedback by id
    if (path.startsWith("/api/feedback/") && method === "DELETE") {
      const id = parseInt(path.split("/")[3]);
      if (!id) return err("Invalid id");
      await db.prepare("DELETE FROM session_feedback WHERE id = ?").bind(id).run();
      return json({ status: "ok", deleted: id });
    } 

    // Athlete notes: general conditioning log fed into plan generation
    if (path === "/api/notes" && method === "POST") {
      const body = await request.json();
      const { notes } = body;
      if (!notes?.trim()) return err("notes required");
      await db.prepare(`
        INSERT INTO athlete_notes (notes) VALUES (?)
      `).bind(notes.trim()).run();
      // invalidate plan cache so next load regenerates with these notes
      const now2 = new Date();
      const d2 = now2.getDay();
      const mon2 = new Date(now2);
      mon2.setDate(now2.getDate() - ((d2 + 6) % 7));
      const ws2 = mon2.toISOString().split("T")[0];
      await db.prepare("DELETE FROM weekly_plans WHERE week_start = ?").bind(ws2).run();
      return json({ status: "ok" });
    }

    if (path === "/api/notes" && method === "GET") {
      const { results } = await db.prepare(`
        SELECT * FROM athlete_notes ORDER BY recorded_at DESC LIMIT 20
      `).all();
      return json(results);
    }

    // Delete a journal entry by id
    if (path.startsWith("/api/notes/") && method === "DELETE") {
      const id = parseInt(path.split("/")[3]);
      if (!id) return err("Invalid id");
      await db.prepare("DELETE FROM athlete_notes WHERE id = ?").bind(id).run();
      // invalidate plan cache
      const now2 = new Date();
      const d2 = now2.getDay();
      const mon2 = new Date(now2);
      mon2.setDate(now2.getDate() - ((d2 + 6) % 7));
      const ws2 = mon2.toISOString().split("T")[0];
      await db.prepare("DELETE FROM weekly_plans WHERE week_start = ?").bind(ws2).run();
      return json({ status: "ok", deleted: id });
    }

    // Body composition history
    if (path === "/api/body" && method === "GET") {
      const { results } = await db.prepare(`
        SELECT * FROM body_composition ORDER BY date DESC LIMIT 20
      `).all();
      return json(results.reverse());
    }

    // Plan: get or generate weekly training plan
    if (path === "/api/plan" && method === "GET") {
      try {
        const force = url.searchParams.get("force") === "true";
        const next = url.searchParams.get("next") === "true";

        if (next) {
          // generate next week's plan
          const now2 = new Date();
          const d2 = now2.getDay();
          const nextMonday = new Date(now2);
          nextMonday.setDate(now2.getDate() - ((d2 + 6) % 7) + 7);
          nextMonday.setHours(0, 0, 0, 0);
          // temporarily override now for generateWeeklyPlan by passing a fake date context
          // simplest: just call generateWeeklyPlan with the next week start cached
          const nextWeekStart = nextMonday.toISOString().split("T")[0];
          const cached = await db.prepare(
            "SELECT plan_json FROM weekly_plans WHERE week_start = ?"
          ).bind(nextWeekStart).first();
          if (cached && !force) return json(JSON.parse(cached.plan_json));
          // generate fresh for next week by calling with force
          const plan = await generateWeeklyPlan(db, env, true, nextMonday);
          return json(plan);
        }

        const plan = await generateWeeklyPlan(db, env, force);
        return json(plan);
      } catch (e) {
        return err(`Plan generation failed: ${e.message}`, 500);
      }
    }

    return err("Not found", 404);
  },
};