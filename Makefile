EXTENSION    = pgx_permission_sync
EXTVERSION   = 1.0

DATA         = $(wildcard sql/*--*.sql)
EXTRA_CLEAN  =

PG_CONFIG   ?= pg_config
PGXS        := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
