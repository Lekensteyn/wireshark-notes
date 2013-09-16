#!/usr/bin/awk -f
# Tries to prepend the number matching a Cipher Suite (or 0 if none is found)
# Author: Peter Wu <lekensteyn@gmail.com>

BEGIN {
	# must be a file of format '(decimal number) TLS_(...)'
	if (!suites) suites="suites.txt";

	# Read all name to number mappings from file
	while ((getline < suites) > 0) {
		if ($2 ~ /^TLS_/) {
			name_to_num[$2] = $1;
		}
	}
}
{
	for (i = 1; i <= NF; i++) {
		if ($i ~ /^TLS_/) {
			num = name_to_num[$i];
			if (!num) num = 0;
			$i = num " " $i;
		}
	}
	print;
}
