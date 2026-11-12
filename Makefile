EXTENSION    = pgx_permission_sync
EXTVERSION   = 1.1

DATA         = $(wildcard sql/*--*.sql)
EXTRA_CLEAN  =

REGRESS      = pgx_permission_sync
REGRESS_OPTS = --inputdir=test

PG_CONFIG   ?= pg_config
PGXS        := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
