"""Convert events table to time-based partitioning.

Revision ID: 0003_events_partitioning
Revises: 0002_outbox_and_audit
Create Date: 2026-11-06

The events table grows unbounded as gateways send telemetry. Range
partitioning by observed_at (monthly) keeps queries fast and allows
old partitions to be archived or dropped without affecting current data.

This migration:
1. Creates a new partitioned table with a composite primary key
   (id, observed_at) — PostgreSQL requires the partition key in all
   unique constraints including the primary key
2. Creates monthly partitions for the current and next two months
3. Copies data from the old events table
4. Drops the old table and renames the new one
5. Recreates all indexes

In production, use pg_partman or a cron job to create future partitions
ahead of time. The create_monthly_partition() function is included for
convenience.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0003_events_partitioning"
down_revision: str | None = "0002_outbox_and_audit"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Create a function to create monthly partitions on demand
    op.execute("""
        CREATE OR REPLACE FUNCTION create_monthly_partition(
            partition_year int,
            partition_month int
        ) RETURNS void AS $$
        DECLARE
            partition_name text;
            start_date timestamptz;
            end_date timestamptz;
        BEGIN
            partition_name := 'events_y' || partition_year
                || '_m' || lpad(partition_month::text, 2, '0');
            start_date := make_timestamptz(partition_year, partition_month, 1, 0, 0, 0);
            end_date := start_date + interval '1 month';

            EXECUTE format(
                'CREATE TABLE IF NOT EXISTS %I PARTITION OF events
                 FOR VALUES FROM (%L) TO (%L)',
                partition_name, start_date, end_date
            );
        END;
        $$ LANGUAGE plpgsql;
    """)

    # Create the new partitioned table with a composite primary key.
    # PostgreSQL requires the partition key (observed_at) to be included
    # in all unique constraints and the primary key of a partitioned table.
    # We use LIKE events INCLUDING DEFAULTS INCLUDING CONSTRAINTS to copy
    # column definitions, but we explicitly define the primary key with
    # the partition key included.
    op.execute("""
        CREATE TABLE events_partitioned (
            LIKE events INCLUDING DEFAULTS INCLUDING GENERATED INCLUDING CONSTRAINTS
        ) PARTITION BY RANGE (observed_at);
    """)

    # Drop the copied id-only primary key and replace with a composite one
    op.execute("""
        ALTER TABLE events_partitioned
        DROP CONSTRAINT IF EXISTS events_pkey;
    """)
    op.execute("""
        ALTER TABLE events_partitioned
        DROP CONSTRAINT IF EXISTS events_partitioned_pkey;
    """)
    op.execute("""
        ALTER TABLE events_partitioned
        ADD CONSTRAINT events_partitioned_pkey PRIMARY KEY (id, observed_at);
    """)

    # Create partitions for current month and next two months
    op.execute("""
        DO $$
        DECLARE
            cur_date timestamptz := date_trunc('month', now());
            i int;
            part_name text;
            start_date timestamptz;
            end_date timestamptz;
        BEGIN
            FOR i IN 0..2 LOOP
                start_date := cur_date + (i || ' months')::interval;
                end_date := start_date + interval '1 month';
                part_name := 'events_y' || to_char(start_date, 'YYYY')
                    || '_m' || to_char(start_date, 'MM');

                EXECUTE format(
                    'CREATE TABLE IF NOT EXISTS %I PARTITION OF events_partitioned
                     FOR VALUES FROM (%L) TO (%L)',
                    part_name, start_date, end_date
                );
            END LOOP;

            -- Create a default partition for any out-of-range dates
            EXECUTE 'CREATE TABLE IF NOT EXISTS events_default'
                || ' PARTITION OF events_partitioned DEFAULT';
        END;
    """)

    # Copy existing data into the partitioned table
    op.execute("""
        INSERT INTO events_partitioned
        SELECT * FROM events
        ON CONFLICT DO NOTHING;
    """)

    # Drop the old table and rename
    op.execute("DROP TABLE events CASCADE;")
    op.execute("ALTER TABLE events_partitioned RENAME TO events;")
    op.execute("ALTER INDEX events_partitioned_pkey RENAME TO events_pkey;")

    # Recreate tenant-scoped indexes
    op.create_index("ix_events_tenant_id", "events", ["tenant_id"])
    op.create_index("ix_events_source", "events", ["source", "source_event_id"])
    op.create_index("ix_events_observed_at", "events", ["observed_at"])
    op.create_index("ix_events_gateway_id", "events", ["gateway_id"])


def downgrade() -> None:
    # Revert to a non-partitioned events table
    op.execute("""
        CREATE TABLE events_nonpartitioned (
            LIKE events INCLUDING ALL
        );
    """)
    op.execute("""
        INSERT INTO events_nonpartitioned
        SELECT * FROM events
        ON CONFLICT DO NOTHING;
    """)
    op.execute("DROP TABLE events CASCADE;")
    op.execute("ALTER TABLE events_nonpartitioned RENAME TO events;")

    op.execute("DROP FUNCTION IF EXISTS create_monthly_partition(int, int);")

    # Recreate indexes
    op.create_index("ix_events_tenant_id", "events", ["tenant_id"])
    op.create_index("ix_events_source", "events", ["source", "source_event_id"])
    op.create_index("ix_events_observed_at", "events", ["observed_at"])
    op.create_index("ix_events_gateway_id", "events", ["gateway_id"])
