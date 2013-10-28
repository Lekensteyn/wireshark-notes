#!/usr/bin/awk -f
# Appends percentage to output of:
# tshark -z io,phs -w /dev/null -r input.pcapng

BEGIN {
	# Set -v relative=1 to get percentage relative to parent
	if (relative)
		relative = 1;
	else
		relative = 0;

	# Set -v by_frames=1 to get percentage based on frames instead of bytes
	if (by_frames)
		by_frames = 1;
	else
		by_frames = 0;

	delete lens;
	stats = 0;
}

stats && /bytes:/ {
	if (by_frames)
		field = NF - 1;
	else
		field = NF;

	# frames:1 or bytes:1
	split($field, a, ":");
	count = a[2];
	ind = (match($0,/[^ ]/) - 1) / 2;
	# Store count in depth.
	lens[ind] = count;

	all = lens[0];
	if (ind > 0 && relative) {
		all = lens[ind - 1];
	}

	percent = 100 * (count / all);
	$0 = $0 "\t" sprintf("%.2f", percent);
}

# Assume that a line that starts with Filter: marks the start of stats.
/^Filter: / {
	stats = 1;
}
# Print all lines
{ print }
