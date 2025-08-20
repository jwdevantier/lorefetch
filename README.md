# Lorefetch

Lorefetch is a simplistic and naive alternative to using Lei for fetching search results from a public-inbox
instance as a mbox file or maildir.

Specifically, it:

1. Directs queries to https://lore.kernel.org
2. Solves the anti-bot Anubis protection challenge
3. Submits a search query (same HTTP interface as the UI presents), either local to a list or across all lists
4. Downloads a gzipped mbox file containing the **threads** with matching messages
5. Writes the mbox or equivalent maildir to disk

## Building

```
go build
```

Then you get a binary called `lorefetch`.

## Usage example
```
Usage: ./lorefetch --query 'search terms' [options]

Download relevant mailing list threads from lore.kernel.org

Options:
  -l string
    	Mailing list name (shorthand)
  -list string
    	Mailing list name
  -maildir
    	Save as maildir format (creates cur/new/tmp directories)
  -q string
    	Xapian search query (shorthand)
  -query string
    	Xapian search query (required)
  -s string
    	Save to file instead of importing (shorthand)
  -save-to string
    	Save to file instead of importing
  -v	Enable verbose logging (shorthand)
  -verbose
    	Enable verbose logging

Examples:
  * all threads in the last 6 months there jane.example.org is in the CC or TO header
    ./lorefetch --query 'l:qemu-devel AND (t:jane@example.org OR f:jane@example.org) AND rt:6.month.ago..now'
  * limit search to linux-kernel list
    ./lorefetch --query 'tcp congestion' --list linux-kernel
  * all mail where PATCH is in the subject line of the netdev list
    ./lorefetch --query 's:PATCH AND l:netdev'

Xapian search syntax:
  l:list-name    - mailing list
  f:email        - from address
  t:email        - to address
  c:email        - cc address
  s:subject      - subject line
  AND, OR, NOT   - boolean operators
  "exact phrase" - exact phrase matching
```

## Notes on searching

When writing your queries, you may be interested in [this post](https://lore.kernel.org/amd-gfx/_/text/help/)
which provides some additional notes on the Xapian query syntax.

## See also

* [The lore.kernel.org API](https://blog.kworkflow.org/the-lore.kernel.org-api/)
