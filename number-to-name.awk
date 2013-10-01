#!/usr/bin/awk -f
# Tries to map a number to name (or a question mark if not found)
# Author: Peter Wu <lekensteyn@gmail.com>

BEGIN {
	if (!cmd) cmd = "openssl ciphers -V";
	# alternative: cat suites.txt

	while ((cmd | getline) > 0) {
		if ($1 ~ /^[0-9]+/) {
			# suites.txt format: <decimal-number> <name>
			num = $1;
			name = $2;
			number_to_name[num] = name;
		} else if (split($0, a, / +- +|[, ]+/) >= 2) {
			# `openssl ciphers -V` format:
			# 0xHH,0xHH - <name> ...
			num = strtonum(a[2]) * 256 + strtonum(a[3]);
			name = a[4];
			number_to_name[num] = name;
		}
	}
}
{
	for (i = 1; i <= NF; i++) {
		if ($i ~ /^[0-9]+$/) {
			name = number_to_name[$i];
			if (!name) name = "?";
			$i = $i " " name;
		}
	}
	print;
}
