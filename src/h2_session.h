#ifndef DOHD_H2_SESSION_H
#define DOHD_H2_SESSION_H

enum dohd_h2_stream_close_action {
    DOHD_H2_STREAM_CLOSE_IGNORE = 0,
    DOHD_H2_STREAM_CLOSE_DESTROY = 1,
};

enum dohd_h2_stream_close_action dohd_h2_stream_close_action(int has_request,
        int owner_matches);

#endif
