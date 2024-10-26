#/bin/sh

## Requires: fuser,awk,readlink

for i in $*; do
  procs="$(fuser $i/tcp 2>/dev/null | awk '{for (i = 1; i <= NF; ++i) {print $i}}')"
  for p in $procs; do
    readlink -f /proc/$p/exe
  done
done