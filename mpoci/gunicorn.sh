#!/bin/bash

NAME="mpoci"
FLASKDIR=/opt/mpoci/mpoci
SOCKFILE=/opt/mpoci/mpoci/sock
USER=root
GROUP=root
NUM_WORKERS=20

echo "Starting $NAME"

# Create the run directory if it doesn't exist
RUNDIR=$(dirname $SOCKFILE)
test -d $RUNDIR || mkdir -p $RUNDIR

# Start your gunicorn
exec gunicorn hello:app -b 0.0.0.0:8080 \
  --name $NAME \

  --workers $NUM_WORKERS \
  --user=$USER --group=$GROUP \
  --timeout 3600 --graceful-timeout 600 --limit-request-line 0 --limit-request-field_size 0 \
  --bind=unix:$SOCKFILE

    Contact GitHub API Training Shop Blog About
