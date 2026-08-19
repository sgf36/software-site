# software.spencerfields.com

The business site: the face of Spencer Fields as a software publisher, above the
individual product sites at `easy-post.spencerfields.com` and
`wren.spencerfields.com`.

One page, no build step, no third-party requests. The favicon is an inline SVG
data URI and the styles are inline, so the page makes no network request to
anything — which is also what its own copy claims about the software, and that
claim should stay true of the site describing it.

## Deploying

Uploads to `/home2/spencgh6/software.spencerfields.com` through the cPanel API,
the same token as the other sites (Credential Manager, `cpanel-easypost-site`).
There is no separate deploy script yet; the files are few enough to send with
`Fileman/upload_files`.

## Rules for editing

**Every claim here must already be true on a product site.** This page is a
summary, not a source: status, platforms and capabilities live on the product
sites and are repeated here. Pricing is deliberately NOT repeated, because two
copies of a price drift apart.

**Never publish the home address.** The registered address is the Lytchett
Matravers one; that is the entire reason it exists.

Product status goes stale: Wren is "in review" and the mobile companion is
"Android now", and both change when a store decides something.
