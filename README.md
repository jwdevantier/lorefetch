# Lorefetch

Lorefetch is a simplistic and naive alternative to using Lei for fetching search results from a public-inbox
instance as a mbox file or maildir.

Specifically, it:

1. Directs queries to https://lore.kernel.org
2. Solves the anti-bot Anubis protection challenge
3. Submits a search query (same HTTP interface as the UI presents), either local to a list or across all lists
4. Downloads a gzipped mbox file containing the **threads** with matching messages
5. Writes the mbox or equivalent maildir to disk


When writing your queries, you may be interested in [this post](https://lore.kernel.org/amd-gfx/_/text/help/)
which provides some additional notes on the Xapian query syntax.

# See also

* [The lore.kernel.org API](https://blog.kworkflow.org/the-lore.kernel.org-api/)
