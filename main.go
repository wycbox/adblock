package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type parserFunc func(from io.Reader, to io.Writer) error

type Rule struct {
	URL    string
	Parser parserFunc
}

type Rules []Rule

type RuleFile struct {
	Filename string
	Rules    Rules
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	generatedAt := time.Now().In(time.FixedZone("CST", 8*60*60)).Format("2006-01-02 15:04:05")
	for _, ruleFile := range RuleFiles {
		domains, err := aggregateRules(ctx, ruleFile.Rules)
		if err != nil {
			fmt.Fprintf(os.Stderr, "生成 %s 失败: %v\n", ruleFile.Filename, err)
			os.Exit(1)
		}

		output := filepath.Join("rules", ruleFile.Filename)
		if err := writeDomains(output, generatedAt, ruleFile.Filename, domains); err != nil {
			fmt.Fprintf(os.Stderr, "写入 %s 失败: %v\n", output, err)
			os.Exit(1)
		}

		fmt.Printf("已生成 %s，共 %d 条域名\n", output, len(domains))
	}
}

func newFile(url string, parser parserFunc) Rule {
	return Rule{URL: url, Parser: parser}
}

func defaultParser(predefined ...string) parserFunc {
	return func(from io.Reader, to io.Writer) error {
		for i := range predefined {
			fmt.Fprintf(to, "%s\n", predefined[i])
		}
		_, err := io.Copy(to, from)
		return err
	}
}

func hostsParser(ip string) parserFunc {
	return func(from io.Reader, to io.Writer) error {
		s := bufio.NewScanner(from)
		s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for s.Scan() {
			fields := strings.Fields(s.Text())
			if len(fields) < 2 || fields[0] != ip {
				continue
			}
			fmt.Fprintf(to, "%s\n", fields[1])
		}
		return s.Err()
	}
}

func dnsmasqParser(from io.Reader, to io.Writer) error {
	s := bufio.NewScanner(from)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		domain, ok := strings.CutPrefix(line, "server=/")
		if !ok {
			domain, ok = strings.CutPrefix(line, "address=/")
		}
		if !ok {
			continue
		}
		domain, _, ok = strings.Cut(domain, "/")
		if !ok || domain == "" {
			continue
		}
		if _, err := fmt.Fprintf(to, "%s\n", domain); err != nil {
			return err
		}
	}
	return s.Err()
}

func aggregateRules(ctx context.Context, rules Rules) ([]string, error) {
	seen := make(map[string]struct{})
	for _, rule := range rules {
		domains, err := loadRule(ctx, rule)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", rule.URL, err)
		}
		for _, domain := range domains {
			seen[domain] = struct{}{}
		}
	}

	domains := make([]string, 0, len(seen))
	for domain := range seen {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	return domains, nil
}

func loadRule(ctx context.Context, rule Rule) ([]string, error) {
	body, err := download(ctx, rule.URL)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	var parsed bytes.Buffer
	if err := rule.Parser(body, &parsed); err != nil {
		return nil, err
	}
	return readDomains(&parsed)
}

func download(ctx context.Context, ruleURL string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ruleURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "adblock-rule-generator")

	client := http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("bad status code: %d", resp.StatusCode)
	}
	return resp.Body, nil
}

func readDomains(from io.Reader) ([]string, error) {
	s := bufio.NewScanner(from)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var domains []string
	for s.Scan() {
		domain, ok := normalizeDomain(s.Text())
		if ok {
			domains = append(domains, domain)
		}
	}
	return domains, s.Err()
}

func normalizeDomain(line string) (string, bool) {
	line = strings.TrimSpace(strings.TrimPrefix(line, "\ufeff"))
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") || strings.HasPrefix(line, "@@") {
		return "", false
	}

	fields := strings.Fields(line)
	if len(fields) > 1 && net.ParseIP(fields[0]) != nil {
		line = fields[1]
	} else if len(fields) > 0 {
		line = fields[0]
	}

	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "||")
	line = strings.TrimPrefix(line, "*.")
	line = strings.TrimPrefix(line, ".")
	line, _, _ = strings.Cut(line, "^")
	line, _, _ = strings.Cut(line, "$")

	if strings.Contains(line, "://") {
		u, err := url.Parse(line)
		if err != nil || u.Hostname() == "" {
			return "", false
		}
		line = u.Hostname()
	} else if host, _, err := net.SplitHostPort(line); err == nil {
		line = host
	}

	line, _, _ = strings.Cut(line, "/")
	line = strings.ToLower(strings.Trim(line, "."))
	if !validDomain(line) {
		return "", false
	}
	return line, true
}

func validDomain(domain string) bool {
	if domain == "" || len(domain) > 253 || !strings.Contains(domain, ".") || net.ParseIP(domain) != nil {
		return false
	}

	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func writeDomains(path string, generatedAt string, version string, domains []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	var data bytes.Buffer
	fmt.Fprintf(&data, "#生成时间: %s\n", generatedAt)
	fmt.Fprintf(&data, "#版本: %s\n", version)
	for _, domain := range domains {
		fmt.Fprintf(&data, "%s\n", domain)
	}
	return os.WriteFile(path, data.Bytes(), 0o644)
}
