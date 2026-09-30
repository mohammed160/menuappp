/*
# Create database schema for pizza restaurant app

## Overview
This migration creates the full database schema for a pizza restaurant ordering app.
It replaces the JSON file-based storage (data/menu.json, data/orders.json) with persistent Supabase tables.

## New Tables

1. `app_settings` — single-row table holding the restaurant's configuration:
   - currency, restaurant name, whatsapp number, logo JSON, theme
   - branches (JSON array), delivery settings (JSON), takeaway settings (JSON), payment methods (JSON)
   - version timestamp for cache-busting

2. `menu_items` — all menu items (pizzas, pasta, sides, extras, drinks) in one table:
   - id (text, primary key) — e.g. "z-burger", "extra-cheese"
   - category — 'pizza', 'pasta', 'side', 'extra', 'drink'
   - en_name, ar_name — display names
   - group_name — sub-group like 'signature', 'premium', 'classic', 'regular', or null
   - price_json — JSONB column holding the price structure (varies by category)
   - stuffed_json — JSONB for stuffed-crust pricing (pizzas only, nullable)
   - image_json — JSONB for image paths and metadata (nullable)
   - sauce_color — hex color string for pasta items (nullable)
   - pasta_images — JSONB for pasta noodle-type images (nullable)
   - extra_category — 'toppings', 'cheese', 'sauces' for extras (nullable)
   - side_column — 'L' or 'R' for sides layout (nullable)
   - side_highlight — boolean for sides (nullable)
   - sort_order — integer for ordering within each category
   - hidden — boolean, default false
   - sold_out — boolean, default false
   - created_at, updated_at — timestamps

3. `orders` — customer orders:
   - id (text, primary key) — short hash ID
   - number (integer) — human-readable order number
   - status — 'new', 'confirmed', 'preparing', 'delivering', 'done', 'cancelled'
   - type — 'delivery' or 'takeaway'
   - customer (JSONB) — name, phone, address, zone, branch info
   - lines (JSONB) — array of order line items with extras
   - subtotal, delivery_fee, total — numeric
   - currency — text
   - payment — payment method key
   - payment_label — human-readable payment label
   - note — customer note
   - history (JSONB) — array of status change events
   - cancel_reason — text (nullable)
   - adjusted — boolean
   - created_at, updated_at — timestamps

4. `order_counter` — single-row table for the next order number:
   - next_number — integer

## Security
- This is a single-tenant app with no sign-in screen (admin uses a simple password, not Supabase auth).
- RLS enabled on all tables.
- Policies use `TO anon, authenticated` so the anon-key client can read/write.
- Menu items and settings: public read, public write (admin manages via same anon key).
- Orders: public read + insert (customers create orders), public update + delete (admin manages).
*/

-- App settings (single row)
CREATE TABLE IF NOT EXISTS app_settings (
  id text PRIMARY KEY DEFAULT 'singleton',
  currency text NOT NULL DEFAULT 'EGP',
  restaurant_name text NOT NULL DEFAULT '',
  whatsapp text NOT NULL DEFAULT '',
  logo jsonb,
  theme text DEFAULT 'auto',
  branches jsonb DEFAULT '[]'::jsonb,
  delivery jsonb DEFAULT '{}'::jsonb,
  takeaway jsonb DEFAULT '{}'::jsonb,
  payments jsonb DEFAULT '{}'::jsonb,
  version bigint DEFAULT extract(epoch from now())::bigint,
  updated_at timestamptz DEFAULT now()
);

ALTER TABLE app_settings ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_read_settings" ON app_settings;
CREATE POLICY "anon_read_settings" ON app_settings FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_settings" ON app_settings;
CREATE POLICY "anon_insert_settings" ON app_settings FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_settings" ON app_settings;
CREATE POLICY "anon_update_settings" ON app_settings FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_settings" ON app_settings;
CREATE POLICY "anon_delete_settings" ON app_settings FOR DELETE
  TO anon, authenticated USING (true);

-- Menu items (all categories in one table)
CREATE TABLE IF NOT EXISTS menu_items (
  id text PRIMARY KEY,
  category text NOT NULL,
  en_name text NOT NULL DEFAULT '',
  ar_name text NOT NULL DEFAULT '',
  group_name text,
  price_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  stuffed_json jsonb,
  image_json jsonb,
  sauce_color text,
  pasta_images jsonb,
  extra_category text,
  side_column text,
  side_highlight boolean,
  sort_order integer NOT NULL DEFAULT 0,
  hidden boolean NOT NULL DEFAULT false,
  sold_out boolean NOT NULL DEFAULT false,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

ALTER TABLE menu_items ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_read_menu" ON menu_items;
CREATE POLICY "anon_read_menu" ON menu_items FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_menu" ON menu_items;
CREATE POLICY "anon_insert_menu" ON menu_items FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_menu" ON menu_items;
CREATE POLICY "anon_update_menu" ON menu_items FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_menu" ON menu_items;
CREATE POLICY "anon_delete_menu" ON menu_items FOR DELETE
  TO anon, authenticated USING (true);

CREATE INDEX IF NOT EXISTS idx_menu_items_category ON menu_items(category);

-- Orders
CREATE TABLE IF NOT EXISTS orders (
  id text PRIMARY KEY,
  number integer NOT NULL,
  status text NOT NULL DEFAULT 'new',
  type text NOT NULL DEFAULT 'delivery',
  customer jsonb NOT NULL DEFAULT '{}'::jsonb,
  lines jsonb NOT NULL DEFAULT '[]'::jsonb,
  subtotal numeric NOT NULL DEFAULT 0,
  delivery_fee numeric NOT NULL DEFAULT 0,
  total numeric NOT NULL DEFAULT 0,
  currency text NOT NULL DEFAULT 'EGP',
  payment text NOT NULL DEFAULT 'cod',
  payment_label text NOT NULL DEFAULT '',
  note text NOT NULL DEFAULT '',
  history jsonb NOT NULL DEFAULT '[]'::jsonb,
  cancel_reason text NOT NULL DEFAULT '',
  adjusted boolean NOT NULL DEFAULT false,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

ALTER TABLE orders ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_read_orders" ON orders;
CREATE POLICY "anon_read_orders" ON orders FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_orders" ON orders;
CREATE POLICY "anon_insert_orders" ON orders FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_orders" ON orders;
CREATE POLICY "anon_update_orders" ON orders FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_orders" ON orders;
CREATE POLICY "anon_delete_orders" ON orders FOR DELETE
  TO anon, authenticated USING (true);

CREATE INDEX IF NOT EXISTS idx_orders_number ON orders(number);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
CREATE INDEX IF NOT EXISTS idx_orders_created_at ON orders(created_at DESC);

-- Order counter (single row)
CREATE TABLE IF NOT EXISTS order_counter (
  id text PRIMARY KEY DEFAULT 'singleton',
  next_number integer NOT NULL DEFAULT 1001
);

ALTER TABLE order_counter ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_read_counter" ON order_counter;
CREATE POLICY "anon_read_counter" ON order_counter FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_counter" ON order_counter;
CREATE POLICY "anon_insert_counter" ON order_counter FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_counter" ON order_counter;
CREATE POLICY "anon_update_counter" ON order_counter FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_counter" ON order_counter;
CREATE POLICY "anon_delete_counter" ON order_counter FOR DELETE
  TO anon, authenticated USING (true);
