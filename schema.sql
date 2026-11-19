CREATE TABLE IF NOT EXISTS app_state (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS visitor_passes (
    id TEXT PRIMARY KEY,
    visitor_name TEXT NOT NULL,
    company TEXT NOT NULL DEFAULT '',
    phone TEXT NOT NULL DEFAULT '',
    address TEXT NOT NULL DEFAULT '',
    purpose TEXT NOT NULL DEFAULT '',
    vehicle_no TEXT NOT NULL DEFAULT '',
    factory TEXT NOT NULL DEFAULT '',
    department TEXT NOT NULL DEFAULT '',
    host_username TEXT NOT NULL DEFAULT '',
    host_name TEXT NOT NULL DEFAULT '',
    id_card_photo TEXT NOT NULL DEFAULT '',
    id_card_photos JSONB NOT NULL DEFAULT '[]'::jsonb,
    selfie_photo TEXT NOT NULL DEFAULT '',
    selfie_photos JSONB NOT NULL DEFAULT '[]'::jsonb,
    status TEXT NOT NULL DEFAULT 'Pending',
    entry_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    approved_by TEXT NOT NULL DEFAULT '',
    approved_at TIMESTAMPTZ,
    checked_in_by TEXT NOT NULL DEFAULT '',
    checked_in_at TIMESTAMPTZ,
    checked_out_by TEXT NOT NULL DEFAULT '',
    checked_out_at TIMESTAMPTZ,
    rejected_reason TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT 'Gate Kiosk',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_gp_visitors_status_time ON visitor_passes (status, entry_time DESC);
CREATE INDEX IF NOT EXISTS idx_gp_visitors_dept ON visitor_passes (department, host_username);

CREATE TABLE IF NOT EXISTS material_gate_passes (
    id TEXT PRIMARY KEY,
    direction TEXT NOT NULL DEFAULT 'IN',
    material_type TEXT NOT NULL DEFAULT '',
    material_name TEXT NOT NULL DEFAULT '',
    quantity TEXT NOT NULL DEFAULT '1',
    unit TEXT NOT NULL DEFAULT 'Nos',
    vehicle_no TEXT NOT NULL DEFAULT '',
    driver_name TEXT NOT NULL DEFAULT '',
    driver_phone TEXT NOT NULL DEFAULT '',
    party_name TEXT NOT NULL DEFAULT '',
    challan_no TEXT NOT NULL DEFAULT '',
    factory TEXT NOT NULL DEFAULT '',
    department TEXT NOT NULL DEFAULT '',
    for_username TEXT NOT NULL DEFAULT '',
    for_name TEXT NOT NULL DEFAULT '',
    is_returnable BOOLEAN NOT NULL DEFAULT FALSE,
    expected_days INTEGER NOT NULL DEFAULT 0,
    expected_return_at TIMESTAMPTZ,
    returned_at TIMESTAMPTZ,
    return_note TEXT NOT NULL DEFAULT '',
    last_reminder_at TIMESTAMPTZ,
    material_photo TEXT NOT NULL DEFAULT '',
    material_photos JSONB NOT NULL DEFAULT '[]'::jsonb,
    bill_photo TEXT NOT NULL DEFAULT '',
    bill_photos JSONB NOT NULL DEFAULT '[]'::jsonb,
    status TEXT NOT NULL DEFAULT 'Recorded',
    entry_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verified_by TEXT NOT NULL DEFAULT '',
    verified_at TIMESTAMPTZ,
    notes TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT 'Security Gate',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_gp_material_dir_time ON material_gate_passes (direction, entry_time DESC);
CREATE INDEX IF NOT EXISTS idx_gp_material_returnable ON material_gate_passes (is_returnable, returned_at, expected_return_at);

CREATE TABLE IF NOT EXISTS notification_events (
    id TEXT PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    kind TEXT NOT NULL DEFAULT 'info',
    level TEXT NOT NULL DEFAULT 'info',
    title TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL DEFAULT '',
    factory TEXT NOT NULL DEFAULT '',
    target_department TEXT NOT NULL DEFAULT '',
    target_usernames JSONB NOT NULL DEFAULT '[]'::jsonb,
    target_view TEXT NOT NULL DEFAULT 'visitors',
    target_id TEXT NOT NULL DEFAULT '',
    meta JSONB NOT NULL DEFAULT '{}'::jsonb,
    read_by JSONB NOT NULL DEFAULT '[]'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_gp_notif_ts ON notification_events (ts DESC);

CREATE TABLE IF NOT EXISTS user_notification_prefs (
    username TEXT PRIMARY KEY,
    prefs JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    meta JSONB NOT NULL DEFAULT '{}'::jsonb
);
