CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    logo_url TEXT NOT NULL DEFAULT '',
    portal_title TEXT NOT NULL DEFAULT 'Security Gate · Visitor & Material Entry',
    status TEXT NOT NULL DEFAULT 'active',
    max_users INTEGER NOT NULL DEFAULT 100,
    plan_name TEXT NOT NULL DEFAULT 'Standard',
    expires_at TIMESTAMPTZ,
    contact_name TEXT NOT NULL DEFAULT '',
    contact_phone TEXT NOT NULL DEFAULT '',
    contact_email TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS app_state (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS org_state (
    org_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, key)
);

CREATE TABLE IF NOT EXISTS visitor_passes (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL DEFAULT 'org-default',
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
    expected_duration_minutes INTEGER NOT NULL DEFAULT 0,
    expected_duration_label TEXT NOT NULL DEFAULT '',
    expected_checkout_at TIMESTAMPTZ,
    next_followup_at TIMESTAMPTZ,
    reminder_count INTEGER NOT NULL DEFAULT 0,
    last_reminder_at TIMESTAMPTZ,
    overstay_reason TEXT NOT NULL DEFAULT '',
    stay_updates JSONB NOT NULL DEFAULT '[]'::jsonb,
    checkout_type TEXT NOT NULL DEFAULT '',
    checkout_note TEXT NOT NULL DEFAULT '',
    gate_checkins JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_by TEXT NOT NULL DEFAULT 'Gate Kiosk',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS material_gate_passes (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL DEFAULT 'org-default',
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

CREATE TABLE IF NOT EXISTS notification_events (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL DEFAULT 'org-default',
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

CREATE TABLE IF NOT EXISTS user_notification_prefs (
    org_id TEXT NOT NULL DEFAULT 'org-default',
    username TEXT NOT NULL,
    prefs JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, username)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    org_id TEXT NOT NULL DEFAULT 'org-default',
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor TEXT NOT NULL DEFAULT 'system',
    action TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    meta JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- Safe schema upgrades when updating from single-tenant or earlier Shree GatePass
ALTER TABLE visitor_passes ADD COLUMN IF NOT EXISTS org_id TEXT NOT NULL DEFAULT 'org-default';
ALTER TABLE visitor_passes ADD COLUMN IF NOT EXISTS expected_duration_minutes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE visitor_passes ADD COLUMN IF NOT EXISTS expected_duration_label TEXT NOT NULL DEFAULT '';
ALTER TABLE visitor_passes ADD COLUMN IF NOT EXISTS expected_checkout_at TIMESTAMPTZ;
ALTER TABLE visitor_passes ADD COLUMN IF NOT EXISTS next_followup_at TIMESTAMPTZ;
ALTER TABLE visitor_passes ADD COLUMN IF NOT EXISTS reminder_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE visitor_passes ADD COLUMN IF NOT EXISTS last_reminder_at TIMESTAMPTZ;
ALTER TABLE visitor_passes ADD COLUMN IF NOT EXISTS overstay_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE visitor_passes ADD COLUMN IF NOT EXISTS stay_updates JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE visitor_passes ADD COLUMN IF NOT EXISTS checkout_type TEXT NOT NULL DEFAULT '';
ALTER TABLE visitor_passes ADD COLUMN IF NOT EXISTS checkout_note TEXT NOT NULL DEFAULT '';
ALTER TABLE visitor_passes ADD COLUMN IF NOT EXISTS gate_checkins JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE material_gate_passes ADD COLUMN IF NOT EXISTS org_id TEXT NOT NULL DEFAULT 'org-default';
ALTER TABLE notification_events ADD COLUMN IF NOT EXISTS org_id TEXT NOT NULL DEFAULT 'org-default';
ALTER TABLE user_notification_prefs ADD COLUMN IF NOT EXISTS org_id TEXT NOT NULL DEFAULT 'org-default';
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS org_id TEXT NOT NULL DEFAULT 'org-default';

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'user_notification_prefs'::regclass
          AND contype = 'p'
          AND pg_get_constraintdef(oid) = 'PRIMARY KEY (username)'
    ) THEN
        ALTER TABLE user_notification_prefs DROP CONSTRAINT user_notification_prefs_pkey;
        ALTER TABLE user_notification_prefs ADD PRIMARY KEY (org_id, username);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_gp_orgs_slug ON organizations (slug);
CREATE INDEX IF NOT EXISTS idx_gp_visitors_org_status_time ON visitor_passes (org_id, status, entry_time DESC);
CREATE INDEX IF NOT EXISTS idx_gp_visitors_dept ON visitor_passes (org_id, department, host_username);
CREATE INDEX IF NOT EXISTS idx_gp_visitors_followup ON visitor_passes (org_id, status, expected_duration_minutes, next_followup_at);
CREATE INDEX IF NOT EXISTS idx_gp_material_org_dir_time ON material_gate_passes (org_id, direction, entry_time DESC);
CREATE INDEX IF NOT EXISTS idx_gp_material_returnable ON material_gate_passes (org_id, is_returnable, returned_at, expected_return_at);
CREATE INDEX IF NOT EXISTS idx_gp_notif_org_ts ON notification_events (org_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_gp_audit_org_ts ON audit_logs (org_id, ts DESC);
