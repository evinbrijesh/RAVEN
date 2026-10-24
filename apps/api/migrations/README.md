# Migrations

The MVP applies the canonical schema (`app/infrastructure/db/schema.sql`)
idempotently at startup — no migration framework is needed for the hackathon
profile.

`0001_init.sql` is the versioned baseline for a future migration tool
(Alembic is the likely choice when PostgreSQL lands). Keep it in sync with the
canonical schema or regenerate it when the schema changes.
