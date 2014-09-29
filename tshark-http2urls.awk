#!/usr/bin/awk -f
# Shows URLs from a tshark -O http dump
BEGIN {
    FS = "[ :]+";
    OFS = "\t";
}
function find(regex, haystack) {
    haystack = $0;
    regex = "^ *\\[" regex ": ";
    if (haystack ~ regex) {
        sub(regex, "", haystack); sub(/\]$/, "", haystack);
        $0 = haystack;
        return 1;
    }
    return 0;
}

/^Frame / {
    frame_no = $2;
    in_request = 0;
    in_response = 0;
}
next_http {
    if ($2 ~ /^HTTP\//) {   # response
        if ($3 == 200) {
            in_request = 0;
            in_response = 1;
        }
    } else {                # request
        if ($2 == "GET") {
            in_request = 1;
            in_response = 0;
        }
    }
    next_http = 0;
}
/^Hypertext Transfer Protocol/ { next_http = 1; }

in_request && find("Full request URI") {
    urls[frame_no] = $0;
}
in_response {
    n = split("Content-Length Last-Modified", header_names, " ");
    for (i = 1; i <= n; i++) {
        header_name = header_names[i];
        if ($2 == header_name) {
            sub("^ *" header_name ": ", ""); sub(/\\r\\n$/, "");
            headers[header_name, frame_no] = $0;
        }
    }
}
# Print response if a request matched this frame number
in_response && find("Request in frame") && urls[$1] {
    req_frame_no = $1;
    #printf("%-7d ", frame_no);
    printf("%10d %-29s %s\n",
            headers["Content-Length", frame_no],
            headers["Last-Modified", frame_no],
            urls[req_frame_no]);
}

# vim: set sw=4 et ts=4:
