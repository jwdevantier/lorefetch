# Lorefetch

Lorefetch is a simplistic and naive alternative to using Lei for fetching search results from a public-inbox
instance as a mbox file or maildir.

Specifically, it:

1. Directs queries to https://lore.kernel.org
2. Solves the anti-bot Anubis protection challenge
3. Submits a search query (same HTTP interface as the UI presents), either local to a list or across all lists
4. Downloads a gzipped mbox file containing the **threads** with matching messages
5. Writes the mbox or equivalent maildir to disk

IF you write to a maildir, then lorefetch now supports synchronizing (writing new mail only).

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
    	-list shorthand
  -list string
    	Mailing list name
  -maildir string
    	Save as maildir format (creates cur/new/tmp directories)
  -mbox string
    	Save as mbox file
  -q string
    	-query shorthand
  -query string
    	Xapian search query (required)
  -v	-verbose shorthand
  -verbose
    	verbosity level (0=quiet, 1=info, 2=debug)

Examples:
  * all threads in the last 6 months there jane.example.org is in the CC or TO header
    ./lorefetch --query 'l:qemu-devel AND (t:jane@example.org OR f:jane@example.org) AND rt:6.month.ago..now'
  * limit search to linux-kernel list
    ./lorefetch --query 'tcp congestion' --list linux-kernel
  * all mail where PATCH is in the subject line of the netdev list
    ./lorefetch --query 's:PATCH AND l:netdev'

Xapian search syntax:
Lorefetch, like lei, submits queries to the remote public-inbox instance.
public-inbox servers in turn use Xapian for search.

Xapian queries are built by one or more search-prefixes using the AND, OR and NOT operators and parentheses () for grouping

The following is a list of search prefixes supported by public-inbox:
    s:           match within Subject  e.g. s:"a quick brown fox"
    d:           match date-time range, git "approxidate" formats supported
                 Open-ended ranges such as `d:last.week..' and
                 `d:..2.days.ago' are supported
    b:           match within message body, including text attachments
    nq:          match non-quoted text within message body
    q:           match quoted text within message body
    n:           match filename of attachment(s)
    t:           match within the To header
    c:           match within the Cc header
    f:           match within the From header
    a:           match within the To, Cc, and From headers
    tc:          match within the To and Cc headers
    l:           match contents of the List-Id header
    bs:          match within the Subject and body
    dfn:         match filename from diff
    dfa:         match diff removed (-) lines
    dfb:         match diff added (+) lines
    dfhh:        match diff hunk header context (usually a function name)
    dfctx:       match diff context lines
    dfpre:       match pre-image git blob ID
    dfpost:      match post-image git blob ID
    dfblob:      match either pre or post-image git blob ID
    patchid:     match `git patch-id --stable' output
    rt:          match received time, like `d:' if sender's clock was correct
    forpatchid:  the `X-For-Patch-ID' mail header  e.g. forpatchid:stable
    changeid:    the `X-Change-ID' mail header  e.g. changeid:stable

  Most prefixes are probabilistic, meaning they support stemming
  and wildcards ('*').  Ranges (such as 'd:') and boolean prefixes
  do not support stemming or wildcards.
  The upstream Xapian query parser documentation fully explains
  the query syntax:

    https://xapian.org/docs/queryparser.html
```

## Notes on searching

When writing your queries, you may be interested in [this post](https://lore.kernel.org/amd-gfx/_/text/help/)
which provides some additional notes on the Xapian query syntax.

## See also

* [The lore.kernel.org API](https://blog.kworkflow.org/the-lore.kernel.org-api/)
