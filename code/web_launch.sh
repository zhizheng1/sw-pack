#!/bin/sh

URL=localhost:8000
WIDTH=1024
HEIGHT=768
TS=
CS=

while [ -n "$1" ]; do
	[ "$1" == "-u" ] && { shift; URL="$1"; shift; continue; }
	[ "$1" == "-w" ] && { shift; WIDTH="$1"; shift; continue; }
	[ "$1" == "-h" ] && { shift; HEIGHT="$1"; shift; continue; }
	[ "$1" == "-t" ] && { shift; TS=" - $1"; shift; continue; }
	[ "$1" == "-c" ] && { shift; CST="$1"; shift; continue; }
	exit 1
done

if [ "$CST" = "0" ]; then
	CS=";window.parent.close()"
elif [ -n "$CST" ]; then
	CS=";setTimeout(()=>window.parent.close(),$CST)"
fi

URL1=$URL
case "$URL" in
	"http://"*)
		;;
	"https://"*)
		;;
	"file://"*)
		;;
	*)
		URL1="http://"$URL
		;;
esac

open -a Safari "data:text/html,<title>Launch - $URL$TS</title><button autofocus onclick=\"window.open('$URL1','','width=$WIDTH,height=$HEIGHT')$CS\">Go</button>"
