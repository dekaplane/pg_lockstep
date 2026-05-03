EXTENSION = pg_lockstep
DATA = pg_lockstep--0.1.0.sql pg_lockstep--0.1.0--0.1.1.sql pg_lockstep--0.1.1.sql pg_lockstep--0.1.1--0.1.2.sql pg_lockstep--0.1.2.sql

REGRESS = smoke
REGRESS_OPTS = --inputdir=tests

PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
