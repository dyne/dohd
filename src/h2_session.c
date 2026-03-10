#include "h2_session.h"

enum dohd_h2_stream_close_action dohd_h2_stream_close_action(int has_request,
        int owner_matches)
{
    if (!has_request || !owner_matches)
        return DOHD_H2_STREAM_CLOSE_IGNORE;

    return DOHD_H2_STREAM_CLOSE_DESTROY;
}
