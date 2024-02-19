#!/bin/sh

if [ -z "$1" ]; then
  TTY=`tty`
  TEMPFILE=/tmp/pager_${TTY##*/}
else
  TEMPFILE=/tmp/$1
fi

rm -f $TEMPFILE $TEMPFILE.fifo $TEMPFILE.pid $TEMPFILE.lock
echo 'kill `cat '$TEMPFILE'.pid`; echo>'$TEMPFILE'.lock; cat>'$TEMPFILE'.fifo; EC=$?; [ $EC = 141 ] && EC=0; exit $EC' >$TEMPFILE
chmod +x $TEMPFILE
mkfifo $TEMPFILE.fifo $TEMPFILE.lock
START=1
while true; do 
  [ -n "$START" ] && echo "export PAGER=$TEMPFILE" >$TEMPFILE.fifo &
  cat $TEMPFILE.fifo|less -R &
  PID=$!
  echo $PID >$TEMPFILE.pid
  [ -z "$START" ] && cat $TEMPFILE.lock >/dev/null
  wait $PID
  if [ $? = 15 ]; then
    unset START
  else
    [ -n "$START" ] && break
    START=1
  fi
done
rm -f $TEMPFILE $TEMPFILE.fifo $TEMPFILE.pid $TEMPFILE.lock
