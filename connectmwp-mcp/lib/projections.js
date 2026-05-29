// Response projections for connectMWP MCP tools.
//
// The MCP tool surface ships JSON to an AI client, which spends real money on
// every token. The WP plugin already hand-projects its REST responses (it does
// NOT return raw WP_REST_Response shapes with `_links` / `_embedded`), but the
// envelope still includes a few load-bearing-only-on-error fields and at least
// one duplicate (`url` and `link` are identical for posts). These projections
// strip what the AI doesn't need + introduce a consistent `pagination` object
// on list responses so the AI can drive the next call without asking the user.
//
// CONTRACT:
//   * Every projection takes the raw plugin response and returns a new object.
//     Never mutates input.
//   * On success responses (`success: true`), strip `success` (tautological)
//     and apply field-level cleanups.
//   * On error responses (`success: false`), pass through unchanged — the
//     `error` field is the AI's only signal of what went wrong.
//   * If the response shape is unrecognized (e.g. the plugin shipped a new
//     field we don't know about), pass through unchanged — never lossy.
//
// Pure functions; no I/O. Safe to import anywhere.
// All projections subject to the v2.0.22 CHANGELOG enumeration of dropped
// fields — README + SUPPORT_TRAINING note the behavior.

/**
 * Build the canonical pagination object from total / per_page / offset.
 * Returns null when total is missing (plugin didn't paginate the response).
 */
export function buildPagination(total, perPage, offset) {
  if (typeof total !== 'number') return null;
  const safePerPage = Math.max(1, perPage || 0);
  const safeOffset = Math.max(0, offset || 0);
  const consumed = safeOffset + safePerPage;
  const hasMore = consumed < total;
  return {
    total,
    per_page: safePerPage,
    offset: safeOffset,
    next_offset: hasMore ? consumed : null,
    has_more: hasMore,
  };
}

/**
 * Drop duplicate `link` field when it equals `url` (plugin always sets both
 * to the same value for post entities; carrying both wastes tokens).
 */
function dedupeUrlLink(post) {
  if (post && typeof post === 'object' && post.url && post.link && post.url === post.link) {
    const { link, ...rest } = post;
    return rest;
  }
  return post;
}

/**
 * connectmwp_get_posts: { success, posts, total, has_more } →
 * { pagination, posts } on success; pass through on error.
 */
export function projectGetPosts(raw, requestedLimit, requestedOffset) {
  if (!raw || typeof raw !== 'object') return raw;
  if (raw.success === false) return raw;
  if (!Array.isArray(raw.posts)) return raw;

  const posts = raw.posts.map(dedupeUrlLink);
  const pagination = buildPagination(raw.total, requestedLimit, requestedOffset);
  const out = { posts };
  if (pagination) out.pagination = pagination;
  return out;
}

/**
 * connectmwp_get_post: { success, post } → { post } on success.
 */
export function projectGetPost(raw) {
  if (!raw || typeof raw !== 'object') return raw;
  if (raw.success === false) return raw;
  if (!raw.post) return raw;
  return { post: dedupeUrlLink(raw.post) };
}

/**
 * connectmwp_create_post / connectmwp_update_post: pass through but strip
 * `success: true` since the HTTP status implies it; pass error envelopes
 * unchanged.
 */
export function projectMutatePost(raw) {
  if (!raw || typeof raw !== 'object') return raw;
  if (raw.success === false) return raw;
  if (raw.success === true) {
    const { success, ...rest } = raw;
    return dedupeUrlLink(rest);
  }
  return raw;
}

/**
 * connectmwp_delete_post: { success, deleted, id, ... } → { deleted, id, ... }
 */
export function projectDeletePost(raw) {
  if (!raw || typeof raw !== 'object') return raw;
  if (raw.success === false) return raw;
  if (raw.success === true) {
    const { success, ...rest } = raw;
    return rest;
  }
  return raw;
}

/**
 * connectmwp_upload_media: { success, id, source_url, ... } →
 * { id, source_url, ... }
 */
export function projectUploadMedia(raw) {
  if (!raw || typeof raw !== 'object') return raw;
  if (raw.success === false) return raw;
  if (raw.success === true) {
    const { success, ...rest } = raw;
    return rest;
  }
  return raw;
}

/**
 * connectmwp_list_tags / connectmwp_list_categories. Same envelope as
 * get_posts (success + items + total/has_more, with the items field named
 * after the taxonomy: `tags` or `categories`).
 */
export function projectListTaxonomy(raw, itemsKey, requestedLimit, requestedOffset) {
  if (!raw || typeof raw !== 'object') return raw;
  if (raw.success === false) return raw;
  if (!Array.isArray(raw[itemsKey])) return raw;

  const items = raw[itemsKey];
  const pagination = buildPagination(raw.total, requestedLimit, requestedOffset);
  const out = { [itemsKey]: items };
  if (pagination) out.pagination = pagination;
  return out;
}

/**
 * connectmwp_create_category / connectmwp_create_tag: { success, id, name } →
 * { id, name }.
 */
export function projectCreateTaxonomy(raw) {
  if (!raw || typeof raw !== 'object') return raw;
  if (raw.success === false) return raw;
  if (raw.success === true) {
    const { success, ...rest } = raw;
    return rest;
  }
  return raw;
}
