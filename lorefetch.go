// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Jesper Devantier <jwd@defmacro.it>

// Download mailing list threads from a public-inbox instance like lore.kernel.org
// All threads for mail matching the provided query is included.
//
// Results can be written out as a mailbox (mbox) file or into a maildir.
// In case of maildir, each mail is written to a file using the sha1 hash
// of its message-id.
// A cache is also created, marking each mail written to disk. This prevents
// Lorefetch from continuously re-adding mail which the user has deleted or moved.
package main

import (
	"compress/gzip"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	baseURL   = "https://lore.kernel.org"
	userAgent = "Lorefetch/1.x (https://github.com/jwdevantier/lorefetch)"

	fetchTimeoutSeconds = 60
	cacheVersion        = 1
	mailFileMode        = 0644
	maildirMode         = 0755
)

func dbgLog(fmt string, args ...any) {
	if config.Verbose >= 1 {
		log.Printf(fmt, args...)
	}
}

type VerbosityFlag int

func (v *VerbosityFlag) String() string {
	return fmt.Sprintf("%d", *v)
}

func (v *VerbosityFlag) Set(value string) error {
	*v++
	return nil
}

func (v *VerbosityFlag) IsBoolFlag() bool {
	return true
}

type Config struct {
	Query   string
	List    string
	Maildir string
	Mbox    string
	Verbose VerbosityFlag
}

type AnubisChallenge struct {
	Challenge string `json:"challenge"`
	Rules     struct {
		Algorithm  string `json:"algorithm"`
		Difficulty int    `json:"difficulty"`
		ReportAs   int    `json:"report_as"`
	} `json:"rules"`
}

type LoreSearcher struct {
	client  *http.Client
	verbose bool
}

type MaildirCache struct {
	Version int
	/// <sha1('msg-id') -> bool
	Cache map[string]bool
}

func NewMaildirCache() *MaildirCache {
	return &MaildirCache{
		Version: cacheVersion,
		Cache:   make(map[string]bool),
	}
}

func (c *MaildirCache) Exists(msgIdHash string) bool {
	return c.Cache[msgIdHash]
}

func (c *MaildirCache) Add(msgIdHash string) {
	c.Cache[msgIdHash] = true
}

func NewLoreSearcher(verbose bool) *LoreSearcher {
	jar, _ := cookiejar.New(nil)
	return &LoreSearcher{
		client: &http.Client{
			Timeout: fetchTimeoutSeconds * time.Second,
			Jar:     jar,
		},
		verbose: verbose,
	}
}

func (ls *LoreSearcher) log(format string, args ...interface{}) {
	if ls.verbose {
		log.Printf(format, args...)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (ls *LoreSearcher) solveAnubisChallenge(challenge string, difficulty int) (string, int, error) {
	ls.log("Solving Anubis challenge: %s (difficulty %d)", challenge, difficulty)

	nonce := 0
	for {
		input := challenge + strconv.Itoa(nonce)
		hash := sha256.Sum256([]byte(input))
		hashStr := hex.EncodeToString(hash[:])

		// Check if first N hex characters are zeros (difficulty level)
		if strings.HasPrefix(hashStr, strings.Repeat("0", difficulty)) {
			ls.log("Found solution: hash=%s, nonce=%d", hashStr, nonce)
			return hashStr, nonce, nil
		}

		nonce++
		if nonce%10000 == 0 {
			ls.log("Tried %d nonces...", nonce)
		}
	}
}

func (ls *LoreSearcher) handleAnubisChallengeFromResponse(body, originalURL string) error {
	// Extract challenge data from script tags
	challengeRe := regexp.MustCompile(`<script id="anubis_challenge" type="application/json">([^<]+)</script>`)
	match := challengeRe.FindStringSubmatch(body)
	if len(match) < 2 {
		// Debug: let's see what we have
		ls.log("Response body (first 500 chars): %s", body[:min(500, len(body))])
		return fmt.Errorf("could not extract Anubis challenge data")
	}

	// Parse the challenge (simplified - just extract the parts we need)
	challengeData := match[1]
	challengeRe2 := regexp.MustCompile(`"challenge":"([^"]+)"`)
	difficultyRe := regexp.MustCompile(`"difficulty":(\d+)`)

	challengeMatch := challengeRe2.FindStringSubmatch(challengeData)
	difficultyMatch := difficultyRe.FindStringSubmatch(challengeData)

	if len(challengeMatch) < 2 || len(difficultyMatch) < 2 {
		ls.log("Challenge data: %s", challengeData)
		return fmt.Errorf("could not parse challenge parameters")
	}

	challenge := challengeMatch[1]
	difficulty, err := strconv.Atoi(difficultyMatch[1])
	if err != nil {
		return fmt.Errorf("parsing difficulty: %w", err)
	}

	// Solve the challenge
	hash, nonce, err := ls.solveAnubisChallenge(challenge, difficulty)
	if err != nil {
		return fmt.Errorf("solving challenge: %w", err)
	}

	// Submit the solution - this should set the auth cookie
	passURL := fmt.Sprintf("%s/.within.website/x/cmd/anubis/api/pass-challenge?response=%s&nonce=%d&redir=%s&elapsedTime=5000",
		baseURL, hash, nonce, url.QueryEscape(originalURL))

	ls.log("Submitting challenge solution to: %s", passURL)

	// Create request with proper headers
	req, err := http.NewRequest("GET", passURL, nil)
	if err != nil {
		return fmt.Errorf("creating challenge request: %w", err)
	}

	// Set headers similar to browser
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Referer", originalURL)
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	resp2, err := ls.client.Do(req)
	if err != nil {
		return fmt.Errorf("submitting challenge: %w", err)
	}
	defer resp2.Body.Close()

	ls.log("Challenge submission response status: %d", resp2.StatusCode)

	// Check if we got the auth cookie
	cookies := ls.client.Jar.Cookies(req.URL)
	for _, cookie := range cookies {
		if strings.Contains(cookie.Name, "anubis-auth") {
			ls.log("Got Anubis auth cookie: %s", cookie.Name)
		}
	}

	// The response might be a redirect or HTML page - that's expected
	respBody, _ := io.ReadAll(resp2.Body)
	ls.log("Challenge response length: %d bytes", len(respBody))

	return nil
}

func (ls *LoreSearcher) FetchMbox(query, mailingList string) (string, error) {
	// Determine search URL with query parameters
	baseSearchURL := baseURL + "/all/"
	if mailingList != "" {
		baseSearchURL = baseURL + "/" + mailingList + "/"
	}

	// Create URL with query parameters for the form action
	u, err := url.Parse(baseSearchURL)
	if err != nil {
		return "", fmt.Errorf("parsing URL: %w", err)
	}
	q := u.Query()
	q.Set("q", query)
	q.Set("x", "m") // This will be the form action URL
	u.RawQuery = q.Encode()
	searchURL := u.String()

	ls.log("Fetching mbox from: %s", searchURL)
	ls.log("Query: %s", query)

	// Create POST request to the form with full threads parameter
	data := url.Values{}
	data.Set("x", "full threads") // This triggers mbox download

	req, err := http.NewRequest("POST", searchURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}

	// Set headers to match your curl command
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", baseURL)
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Referer", searchURL)
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Priority", "u=0, i")

	// Execute the request
	resp, err := ls.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("request returned status %d", resp.StatusCode)
	}

	// Handle response - check if it's gzipped
	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return "", fmt.Errorf("creating gzip reader: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	// Read the mbox content
	content, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("reading content: %w", err)
	}

	mboxContent := string(content)
	ls.log("Received %d bytes (%d lines)", len(content), strings.Count(mboxContent, "\n"))

	// Check if we got an Anubis challenge instead of mbox content
	if strings.Contains(mboxContent, "Making sure you&#39;re not a bot") || strings.Contains(mboxContent, "anubis_challenge") {
		ls.log("Detected Anubis bot protection, solving challenge...")

		// Solve the Anubis challenge using the current response
		if err := ls.handleAnubisChallengeFromResponse(mboxContent, searchURL); err != nil {
			return "", fmt.Errorf("handling Anubis protection: %w", err)
		}

		// Retry the original request
		ls.log("Retrying original request after solving challenge")

		// Create a fresh POST request (the original might be consumed)
		retryReq, err := http.NewRequest("POST", searchURL, strings.NewReader(data.Encode()))
		if err != nil {
			return "", fmt.Errorf("creating retry request: %w", err)
		}

		// Copy all headers from original request
		retryReq.Header = req.Header.Clone()

		resp2, err := ls.client.Do(retryReq)
		if err != nil {
			return "", fmt.Errorf("retry request failed: %w", err)
		}
		defer resp2.Body.Close()

		ls.log("Retry response status: %d", resp2.StatusCode)

		if resp2.StatusCode != http.StatusOK {
			// Log response body for debugging
			retryBody, _ := io.ReadAll(resp2.Body)
			ls.log("Retry response body (first 500 chars): %s", string(retryBody)[:min(500, len(retryBody))])
			return "", fmt.Errorf("retry request returned status %d", resp2.StatusCode)
		}

		// Handle response again (with gzip if needed)
		reader2 := io.Reader(resp2.Body)
		if resp2.Header.Get("Content-Encoding") == "gzip" {
			gzReader, err := gzip.NewReader(resp2.Body)
			if err != nil {
				return "", fmt.Errorf("creating gzip reader: %w", err)
			}
			defer gzReader.Close()
			reader2 = gzReader
		}

		content2, err := io.ReadAll(reader2)
		if err != nil {
			return "", fmt.Errorf("reading retry content: %w", err)
		}

		mboxContent = string(content2)
		ls.log("Retry received %d bytes (%d lines)", len(content2), strings.Count(mboxContent, "\n"))
	}

	// Check if content is gzipped (starts with gzip magic bytes)
	if len(mboxContent) > 2 && mboxContent[0] == '\x1f' && mboxContent[1] == '\x8b' {
		ls.log("Detected gzipped content, decompressing...")

		gzReader, err := gzip.NewReader(strings.NewReader(mboxContent))
		if err != nil {
			return "", fmt.Errorf("creating gzip reader: %w", err)
		}
		defer gzReader.Close()

		decompressed, err := io.ReadAll(gzReader)
		if err != nil {
			return "", fmt.Errorf("decompressing content: %w", err)
		}

		mboxContent = string(decompressed)
		ls.log("Decompressed to %d bytes (%d lines)", len(decompressed), strings.Count(mboxContent, "\n"))
	}

	// Basic validation - mbox should contain "From " lines
	if !strings.Contains(mboxContent, "From ") {
		return "", fmt.Errorf("response doesn't appear to be mbox format")
	}

	return mboxContent, nil
}

func validateMaildirPath(destPath string) error {
	// Check if any of the subdirectories exist
	subdirs := []string{"cur", "new", "tmp"}
	for _, subdir := range subdirs {
		subPath := filepath.Join(destPath, subdir)
		if _, err := os.Stat(subPath); err != nil {
			return fmt.Errorf("invalid maildir '%s' - sub-directory '%s' missing", destPath, subdir)
		}
	}

	return nil
}

func createMaildirStructure(destPath string) error {
	subdirs := []string{"cur", "new", "tmp"}
	for _, subdir := range subdirs {
		subPath := filepath.Join(destPath, subdir)
		if err := os.MkdirAll(subPath, maildirMode); err != nil {
			return fmt.Errorf("creating directory %s: %w", subPath, err)
		}
	}
	return nil
}

func parseMboxMessages(mboxContent string) []string {
	var messages []string
	lines := strings.Split(mboxContent, "\n")
	var currentMessage strings.Builder

	for i, line := range lines {
		// Start of new message (From line)
		if strings.HasPrefix(line, "From ") && i > 0 {
			// Save previous message if it has content
			if currentMessage.Len() > 0 {
				messages = append(messages, currentMessage.String())
				currentMessage.Reset()
			}
		}

		// Add line to current message (skip the "From " line itself)
		if !strings.HasPrefix(line, "From ") {
			if currentMessage.Len() > 0 {
				currentMessage.WriteString("\n")
			}
			currentMessage.WriteString(line)
		}
	}

	// Add the last message
	if currentMessage.Len() > 0 {
		messages = append(messages, currentMessage.String())
	}

	return messages
}

func cachePath(maildirPath string) string {
	return filepath.Join(maildirPath, ".lorefetch-cache.gob")
}

func loadCache(maildirPath string) (*MaildirCache, error) {
	cachePath := cachePath(maildirPath)
	file, err := os.Open(cachePath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("opening cache file: %w", err)
	}
	defer file.Close()

	var cache MaildirCache
	decoder := gob.NewDecoder(file)
	if err := decoder.Decode(&cache); err != nil {
		return nil, fmt.Errorf("decoding cache: %w", err)
	}
	dbgLog("loaded cache of %d entries\n", len(cache.Cache))
	return &cache, nil
}

func loadOrInitCache(maildirPath string) (*MaildirCache, error) {
	cache, err := loadCache(maildirPath)
	if cache == nil && err == nil {
		dbgLog("failed to load cache, initializing from existing content...")
		m, err := initCache(maildirPath)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize maildir cache: %w", err)
		}
		return &MaildirCache{
			Version: cacheVersion,
			Cache:   m,
		}, nil
	}
	return cache, err
}

func saveCache(cache *MaildirCache, maildirPath string) error {
	dbgLog("saving cache")
	cachePath := cachePath(maildirPath)

	file, err := os.Create(cachePath)
	if err != nil {
		return fmt.Errorf("creating cache file: %w", err)
	}
	defer file.Close()

	enc := gob.NewEncoder(file)
	if err := enc.Encode(cache); err != nil {
		return fmt.Errorf("encoding cache: %w", err)
	}
	return nil
}

func initCache(maildirPath string) (map[string]bool, error) {
	existingMail := make(map[string]bool)

	entries, err := os.ReadDir(filepath.Join(maildirPath, "new"))
	if err != nil {
		// TODO: include original error
		return nil, fmt.Errorf("failed to read path '%s/new': %w", maildirPath, err)
	}

	for _, entry := range entries {
		existingMail[entry.Name()] = true
	}

	entries, err = os.ReadDir(filepath.Join(maildirPath, "cur"))
	if err != nil {
		// TODO: include original error
		return nil, fmt.Errorf("failed to read path '%s/cur'", maildirPath)
	}

	for _, entry := range entries {
		filename := entry.Name()
		ndxOfColon2 := strings.LastIndex(filename, ":2")
		if ndxOfColon2 == -1 {
			// not a mail file
			continue
		}
		existingMail[filename[:ndxOfColon2]] = true
	}

	return existingMail, nil
}

func saveAsMaildir(mboxContent, destPath string) error {
	messages := parseMboxMessages(mboxContent)
	if len(messages) == 0 {
		return fmt.Errorf("no messages found in mbox content")
	}
	newPath := filepath.Join(destPath, "new")

	cache, err := loadOrInitCache(destPath)
	if err != nil {
		return fmt.Errorf("failed to get a cache: %w", err)
	}

	numSaved := 0
	for i, message := range messages {
		rdr := strings.NewReader(message)
		msg, err := mail.ReadMessage(rdr)
		if err != nil {
			return fmt.Errorf("cannot parse mail entry %d", i)
		}
		msgId := msg.Header.Get("Message-ID")
		if msgId == "" {
			panic("assertion failed - found message w/o a Message-ID")
		}

		hash := sha1.Sum([]byte(msgId))

		// hash of message-id
		filename := fmt.Sprintf("%x", hash)

		if cache.Exists(filename) {
			continue // skip
		}

		filePath := filepath.Join(newPath, filename)
		if err := os.WriteFile(filePath, []byte(message), mailFileMode); err != nil {
			return fmt.Errorf("writing message to %s: %w", filePath, err)
		}
		cache.Add(filename)
		numSaved += 1
	}

	log.Printf("%d new of %d messages fetched", numSaved, len(messages))
	if err = saveCache(cache, destPath); err != nil {
		log.Printf("warning: failed to save maildir cache")
	}
	return nil
}

var config Config

func main() {

	flag.StringVar(&config.Query, "query", "", "Xapian search query (required)")
	flag.StringVar(&config.Query, "q", "", "-query shorthand")
	flag.StringVar(&config.List, "list", "", "Mailing list name")
	flag.StringVar(&config.List, "l", "", "-list shorthand")
	flag.StringVar(&config.Maildir, "maildir", "", "Save as maildir format (creates cur/new/tmp directories)")
	flag.StringVar(&config.Mbox, "mbox", "", "Save as mbox file")
	flag.Var(&config.Verbose, "verbose", "verbosity level (0=quiet, 1=info, 2=debug)")
	flag.Var(&config.Verbose, "v", "-verbose shorthand")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s --query 'search terms' [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Download relevant mailing list threads from lore.kernel.org\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  * all threads in the last 6 months there jane.example.org is in the CC or TO header\n")
		fmt.Fprintf(os.Stderr, "    %s --query 'l:qemu-devel AND (t:jane@example.org OR f:jane@example.org) AND rt:6.month.ago..now'\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  * limit search to linux-kernel list\n")
		fmt.Fprintf(os.Stderr, "    %s --query 'tcp congestion' --list linux-kernel\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  * all mail where PATCH is in the subject line of the netdev list\n")
		fmt.Fprintf(os.Stderr, "    %s --query 's:PATCH AND l:netdev'\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nXapian search syntax:\n")
		fmt.Fprintf(os.Stderr, "Lorefetch, like lei, submits queries to the remote public-inbox instance.\n")
		fmt.Fprintf(os.Stderr, "public-inbox servers in turn use Xapian for search.\n\n")
		fmt.Fprintf(os.Stderr, "Xapian queries are built by one or more search-prefixes using the AND, OR and NOT operators and parentheses () for grouping\n\n")
		fmt.Fprintf(os.Stderr, "The following is a list of search prefixes supported by public-inbox:\n")
		fmt.Fprintf(os.Stderr, "    s:           match within Subject  e.g. s:\"a quick brown fox\"\n")
		fmt.Fprintf(os.Stderr, "    d:           match date-time range, git \"approxidate\" formats supported\n")
		fmt.Fprintf(os.Stderr, "                 Open-ended ranges such as `d:last.week..' and\n")
		fmt.Fprintf(os.Stderr, "                 `d:..2.days.ago' are supported\n")
		fmt.Fprintf(os.Stderr, "    b:           match within message body, including text attachments\n")
		fmt.Fprintf(os.Stderr, "    nq:          match non-quoted text within message body\n")
		fmt.Fprintf(os.Stderr, "    q:           match quoted text within message body\n")
		fmt.Fprintf(os.Stderr, "    n:           match filename of attachment(s)\n")
		fmt.Fprintf(os.Stderr, "    t:           match within the To header\n")
		fmt.Fprintf(os.Stderr, "    c:           match within the Cc header\n")
		fmt.Fprintf(os.Stderr, "    f:           match within the From header\n")
		fmt.Fprintf(os.Stderr, "    a:           match within the To, Cc, and From headers\n")
		fmt.Fprintf(os.Stderr, "    tc:          match within the To and Cc headers\n")
		fmt.Fprintf(os.Stderr, "    l:           match contents of the List-Id header\n")
		fmt.Fprintf(os.Stderr, "    bs:          match within the Subject and body\n")
		fmt.Fprintf(os.Stderr, "    dfn:         match filename from diff\n")
		fmt.Fprintf(os.Stderr, "    dfa:         match diff removed (-) lines\n")
		fmt.Fprintf(os.Stderr, "    dfb:         match diff added (+) lines\n")
		fmt.Fprintf(os.Stderr, "    dfhh:        match diff hunk header context (usually a function name)\n")
		fmt.Fprintf(os.Stderr, "    dfctx:       match diff context lines\n")
		fmt.Fprintf(os.Stderr, "    dfpre:       match pre-image git blob ID\n")
		fmt.Fprintf(os.Stderr, "    dfpost:      match post-image git blob ID\n")
		fmt.Fprintf(os.Stderr, "    dfblob:      match either pre or post-image git blob ID\n")
		fmt.Fprintf(os.Stderr, "    patchid:     match `git patch-id --stable' output\n")
		fmt.Fprintf(os.Stderr, "    rt:          match received time, like `d:' if sender's clock was correct\n")
		fmt.Fprintf(os.Stderr, "    forpatchid:  the `X-For-Patch-ID' mail header  e.g. forpatchid:stable\n")
		fmt.Fprintf(os.Stderr, "    changeid:    the `X-Change-ID' mail header  e.g. changeid:stable\n\n")
		fmt.Fprintf(os.Stderr, "  Most prefixes are probabilistic, meaning they support stemming\n")
		fmt.Fprintf(os.Stderr, "  and wildcards ('*').  Ranges (such as 'd:') and boolean prefixes\n")
		fmt.Fprintf(os.Stderr, "  do not support stemming or wildcards.\n")
		fmt.Fprintf(os.Stderr, "  The upstream Xapian query parser documentation fully explains\n")
		fmt.Fprintf(os.Stderr, "  the query syntax:\n\n")
		fmt.Fprintf(os.Stderr, "    https://xapian.org/docs/queryparser.html\n")

	}

	flag.Parse()

	if config.Query == "" {
		fmt.Fprintf(os.Stderr, "Error: --query is required\n\n")
		flag.Usage()
		os.Exit(1)
	}

	if config.Maildir != "" && config.Mbox != "" {
		fmt.Fprintf(os.Stderr, "Error: cannot BOTH save to mbox and maildir\n")
		flag.Usage()
		os.Exit(1)
	}

	// Initialize components
	searcher := NewLoreSearcher(config.Verbose >= 2)

	// Fetch mbox content directly
	mboxContent, err := searcher.FetchMbox(config.Query, config.List)
	if err != nil {
		log.Fatalf("Failed to fetch mbox: %v", err)
	}

	if strings.TrimSpace(mboxContent) == "" {
		log.Fatal("No results found for your search query")
	}

	if config.Maildir != "" {
		log.Printf("Retrieved mbox with %d lines", strings.Count(mboxContent, "\n"))
		// Check if destination exists
		if _, err := os.Stat(config.Maildir); err == nil {
			if err := validateMaildirPath(config.Maildir); err != nil {
				log.Fatalf("Maildir validation failed: %v", err)
			}
		} else {
			// Create maildir structure
			if err := createMaildirStructure(config.Maildir); err != nil {
				log.Fatalf("Failed to create maildir structure: %v", err)
			}
		}

		// Save as maildir
		if err := saveAsMaildir(mboxContent, config.Maildir); err != nil {
			log.Fatalf("Failed to save as maildir: %v", err)
		}
	} else if config.Mbox != "" {
		log.Printf("Retrieved mbox with %d lines", strings.Count(mboxContent, "\n"))
		// Save as regular mbox file
		if err := os.WriteFile(config.Mbox, []byte(mboxContent), 0644); err != nil {
			log.Fatalf("Failed to save file: %v", err)
		}
	} else {
		fmt.Println(mboxContent)
	}
}
