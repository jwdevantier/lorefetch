// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Jesper Devantier <jwd@defmacro.it>
package main

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
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
)

type Config struct {
	Query   string
	List    string
	SaveTo  string
	Maildir bool
	Verbose bool
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

func NewLoreSearcher(verbose bool) *LoreSearcher {
	jar, _ := cookiejar.New(nil)
	return &LoreSearcher{
		client: &http.Client{
			Timeout: 60 * time.Second,
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
	// Check if destination exists
	if _, err := os.Stat(destPath); err == nil {
		return fmt.Errorf("destination path %s already exists", destPath)
	}

	// Check if any of the subdirectories exist
	subdirs := []string{"cur", "new", "tmp"}
	for _, subdir := range subdirs {
		subPath := filepath.Join(destPath, subdir)
		if _, err := os.Stat(subPath); err == nil {
			return fmt.Errorf("maildir subdirectory %s already exists", subPath)
		}
	}

	return nil
}

func createMaildirStructure(destPath string) error {
	subdirs := []string{"cur", "new", "tmp"}
	for _, subdir := range subdirs {
		subPath := filepath.Join(destPath, subdir)
		if err := os.MkdirAll(subPath, 0755); err != nil {
			return fmt.Errorf("creating directory %s: %w", subPath, err)
		}
	}
	return nil
}

func generateMaildirFilename() string {
	timestamp := time.Now().Unix()
	pid := os.Getpid()
	hostname, _ := os.Hostname()
	return fmt.Sprintf("%d.%d.%s:2,", timestamp, pid, hostname)
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

func saveAsMaildir(mboxContent, destPath string) error {
	messages := parseMboxMessages(mboxContent)
	if len(messages) == 0 {
		return fmt.Errorf("no messages found in mbox content")
	}

	curPath := filepath.Join(destPath, "cur")
	for i, message := range messages {
		filename := generateMaildirFilename()
		// Add a counter to ensure uniqueness
		if i > 0 {
			parts := strings.Split(filename, ":")
			parts[0] = fmt.Sprintf("%s_%d", parts[0], i)
			filename = strings.Join(parts, ":")
		}

		filePath := filepath.Join(curPath, filename)
		if err := os.WriteFile(filePath, []byte(message), 0644); err != nil {
			return fmt.Errorf("writing message to %s: %w", filePath, err)
		}
	}

	log.Printf("Saved %d messages to maildir %s", len(messages), destPath)
	return nil
}

func main() {
	var config Config

	flag.StringVar(&config.Query, "query", "", "Xapian search query (required)")
	flag.StringVar(&config.Query, "q", "", "Xapian search query (shorthand)")
	flag.StringVar(&config.List, "list", "", "Mailing list name")
	flag.StringVar(&config.List, "l", "", "Mailing list name (shorthand)")
	flag.StringVar(&config.SaveTo, "save-to", "", "Save to file instead of importing")
	flag.StringVar(&config.SaveTo, "s", "", "Save to file instead of importing (shorthand)")
	flag.BoolVar(&config.Maildir, "maildir", false, "Save as maildir format (creates cur/new/tmp directories)")
	flag.BoolVar(&config.Verbose, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&config.Verbose, "v", false, "Enable verbose logging (shorthand)")

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
		fmt.Fprintf(os.Stderr, "  l:list-name    - mailing list\n")
		fmt.Fprintf(os.Stderr, "  f:email        - from address\n")
		fmt.Fprintf(os.Stderr, "  t:email        - to address\n")
		fmt.Fprintf(os.Stderr, "  c:email        - cc address\n")
		fmt.Fprintf(os.Stderr, "  s:subject      - subject line\n")
		fmt.Fprintf(os.Stderr, "  AND, OR, NOT   - boolean operators\n")
		fmt.Fprintf(os.Stderr, "  \"exact phrase\" - exact phrase matching\n")
	}

	flag.Parse()

	if config.Query == "" {
		fmt.Fprintf(os.Stderr, "Error: --query is required\n\n")
		flag.Usage()
		os.Exit(1)
	}

	if config.SaveTo == "" {
		fmt.Fprintf(os.Stderr, "Error: --save-to is required\n\n")
		flag.Usage()
		os.Exit(1)
	}

	// Initialize components
	searcher := NewLoreSearcher(config.Verbose)

	// Fetch mbox content directly
	mboxContent, err := searcher.FetchMbox(config.Query, config.List)
	if err != nil {
		log.Fatalf("Failed to fetch mbox: %v", err)
	}

	if strings.TrimSpace(mboxContent) == "" {
		log.Fatal("No results found for your search query")
	}

	log.Printf("Retrieved mbox with %d lines", strings.Count(mboxContent, "\n"))

	if config.Maildir {
		// Validate maildir path
		if err := validateMaildirPath(config.SaveTo); err != nil {
			log.Fatalf("Maildir validation failed: %v", err)
		}

		// Create maildir structure
		if err := createMaildirStructure(config.SaveTo); err != nil {
			log.Fatalf("Failed to create maildir structure: %v", err)
		}

		// Save as maildir
		if err := saveAsMaildir(mboxContent, config.SaveTo); err != nil {
			log.Fatalf("Failed to save as maildir: %v", err)
		}
	} else {
		// Save as regular mbox file
		if err := os.WriteFile(config.SaveTo, []byte(mboxContent), 0644); err != nil {
			log.Fatalf("Failed to save file: %v", err)
		}
	}
}
