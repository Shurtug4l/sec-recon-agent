// Report URLs are untrusted input: nvd_url is written by the model (any
// HttpUrl passes the schema), and on /r every field comes from whoever built
// the link. Rendering them verbatim would let a prompt injection or a forged
// permalink plant an off-site link under this origin. Only the reference
// hosts the tools actually cite get an href; anything else renders as text.
const ALLOWED_HOSTS = new Set(["nvd.nist.gov", "attack.mitre.org"]);

export function allowedHref(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" && ALLOWED_HOSTS.has(parsed.hostname)
      ? parsed.href
      : null;
  } catch {
    return null;
  }
}
