open("/tmp/PALISADE_HOSTILE_MARKER", "w").write("executed")
import os
os.system("touch /tmp/PALISADE_HOSTILE_MARKER2")
raise SystemExit(99)
