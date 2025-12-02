#include "asn1c_internal.h"
#include "asn1c_out.h"

/*
 * Add an elementary chunk of target language text
 * into appropriate output stream.
 */
int
asn1c_compiled_output(arg_t *arg, const char *source, int lineno, const char *func, const char *fmt,
                      ...) {
	struct compiler_stream_destination_s *dst;
	const char *p;
	int lf_found;
	va_list ap;
	out_chunk_t *m;
	int ret;

	switch(arg->target->target) {
	case OT_IGNORE:
		return 0;
	default:
		dst = &arg->target->destination[arg->target->target];
		break;
	}

	/*
	 * Make sure the output has a single LF and only at the end.
	 */
	for(lf_found = 0, p = fmt; *p; p++) {
		if(*p == '\n') {
			lf_found++;
			assert(p[1] == '\0');
		}
	}
	assert(lf_found <= 1);

	/*
	 * Print out the indentation.
	 */
	if(dst->indented == 0) {
		int i = dst->indent_level;
		if (i < 0) {
			/* fatal error */
			fprintf(stderr, "target %d : Indent level %d ?!\n", arg->target->target, i);
			exit(1);
		}
		dst->indented = 1;
		while(i--) {
			ret = asn1c_compiled_output(arg, source, lineno, func, "\t");
			if(ret == -1) return -1;
		}
	}
	if(lf_found)
		dst->indented = 0;

    size_t debug_reserve_size = 0;
    if(lf_found && (arg->flags & A1C_DEBUG_OUTPUT_ORIGIN_LINES)) {
        debug_reserve_size =
            sizeof("\t// :100000 ()") + strlen(source) + strlen(func);
    }

	/*
	 * Allocate buffer.
	 */
	m = calloc(1, sizeof(out_chunk_t));
	if(m == NULL) return -1;

	m->len = 16;
	do {
		void *tmp;
		m->len <<= 2;
		tmp = realloc(m->buf, m->len + debug_reserve_size);
		if(tmp) {
			m->buf = (char *)tmp;
		} else {
			free(m->buf);
			free(m);
			return -1;
		}
		va_start(ap, fmt);
		ret = vsnprintf(m->buf, m->len, fmt, ap);
		va_end(ap);
	} while(ret >= (m->len - 1) || ret < 0);

	m->len = ret;

    /* Print out the origin of the lines */
    if(lf_found && (arg->flags & A1C_DEBUG_OUTPUT_ORIGIN_LINES)) {
        assert(m->buf[m->len - 1] == '\n');
        ret = snprintf(m->buf + m->len - 1, debug_reserve_size,
                       "\t// %s:%03d %s()\n", source, lineno, func);
        assert(ret > 0 && (size_t)ret < debug_reserve_size);
        m->len = m->len - 1 + ret;
    }

	/* Deduplicate includes within the same section */
	if(arg->target->target == OT_INCLUDES
	|| arg->target->target == OT_FWD_DECLS
	|| arg->target->target == OT_POST_INCLUDE) {
		out_chunk_t *v;
		TQ_FOR(v, &dst->chunks, next) {
			if(m->len == v->len
			&& !memcmp(m->buf, v->buf, m->len))
				break;
		}
		if(v) {
			/* Entry is already present. Skip it. */
			free(m->buf);
			free(m);
			return 0;
		}
		
		/* Cross-section deduplication for INCLUDES and POST_INCLUDE.
		 * This prevents circular dependency issues where the same include appears
		 * in both sections due to multiple code paths in complex specifications.
		 * 
		 * Strategy: POST_INCLUDE is preferred over INCLUDES because it breaks
		 * circular dependencies by placing includes after typedefs.
		 * 
		 * - When adding to INCLUDES: skip if already in POST_INCLUDE
		 * - When adding to POST_INCLUDE: remove from INCLUDES if present
		 * 
		 * This ensures includes end up in POST_INCLUDE when needed for circular
		 * dependency resolution, regardless of generation order. */
		if(arg->target->target == OT_INCLUDES) {
			struct compiler_stream_destination_s *post_include_dst = 
				&arg->target->destination[OT_POST_INCLUDE];
			TQ_FOR(v, &post_include_dst->chunks, next) {
				if(m->len == v->len
				&& !memcmp(m->buf, v->buf, m->len)) {
					/* Same include exists in POST_INCLUDE, skip INCLUDES version */
					free(m->buf);
					free(m);
					return 0;
				}
			}
		} else if(arg->target->target == OT_POST_INCLUDE) {
			struct compiler_stream_destination_s *includes_dst = 
				&arg->target->destination[OT_INCLUDES];
			out_chunk_t **prev = &includes_dst->chunks.tq_head;
			TQ_FOR(v, &includes_dst->chunks, next) {
				if(m->len == v->len
				&& !memcmp(m->buf, v->buf, m->len)) {
					/* Same include exists in INCLUDES, remove it and keep POST_INCLUDE version */
					*prev = v->next.tq_next;
					if(v->next.tq_next == NULL) {
						includes_dst->chunks.tq_tail = prev;
					}
					free(v->buf);
					free(v);
					break;
				}
				prev = &v->next.tq_next;
			}
		}
	}

	TQ_ADD(&dst->chunks, m, next);

	return 0;
}
