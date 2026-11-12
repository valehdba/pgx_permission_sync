EXTENSION    = pgx_permission_sync
EXTVERSION   = 1.2

DATA         = $(wildcard sql/*--*.sql)
EXTRA_CLEAN  =

REGRESS      = pgx_permission_sync drift
REGRESS_OPTS = --inputdir=test

PG_CONFIG   ?= pg_config
PGXS        := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
