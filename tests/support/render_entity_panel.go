// Render the shipped templates with Go's actual text/template engine.
// This helper implements only the documented helpers these panels use.
// It is a test tool, not part of the collector or a replacement for BloodHound.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"text/template"
)

type request struct {
	Templates  map[string]string
	Properties map[string]any
}

func main() {
	if err := render(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func render() error {
	var input request
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		return fmt.Errorf("read template input: %w", err)
	}
	// These templates use optional strings and lists of strings, not arbitrary objects.
	functions := template.FuncMap{
		"default": func(fallback any, value any) any {
			if value == nil || value == "" {
				return fallback
			}
			return value
		},
		"trim":  strings.TrimSpace,
		"upper": strings.ToUpper,
		"trimSuffix": func(suffix string, value string) string {
			return strings.TrimSuffix(value, suffix)
		},
		"replace": func(old string, replacement string, value string) string {
			return strings.ReplaceAll(value, old, replacement)
		},
		"contains": func(needle string, value string) bool {
			return strings.Contains(value, needle)
		},
		"hasPrefix": func(prefix string, value string) bool {
			return strings.HasPrefix(value, prefix)
		},
		"list": func(values ...any) []any { return values },
		"compact": func(values []any) []any {
			var result []any
			for _, value := range values {
				if value != nil && value != "" {
					result = append(result, value)
				}
			}
			return result
		},
		"uniq": func(values []any) ([]any, error) {
			strings, err := stringList(values)
			if err != nil {
				return nil, err
			}
			seen := make(map[string]bool)
			var result []any
			for _, value := range strings {
				if !seen[value] {
					result = append(result, value)
					seen[value] = true
				}
			}
			return result, nil
		},
		"sortAlpha": func(values []any) ([]string, error) {
			result, err := stringList(values)
			if err != nil {
				return nil, err
			}
			sort.Strings(result)
			return result, nil
		},
		"first": func(values []any) any {
			if len(values) == 0 {
				return nil
			}
			return values[0]
		},
		"rest": func(values []any) []any {
			if len(values) == 0 {
				return nil
			}
			return values[1:]
		},
		"join": func(separator string, values []any) (string, error) {
			result, err := stringList(values)
			if err != nil {
				return "", err
			}
			return strings.Join(result, separator), nil
		},
		"toJson": func(value any) (string, error) {
			result, err := json.Marshal(value)
			return string(result), err
		},
		"fromJson": func(value string) any {
			var result any
			// Sprig's fromJson returns nil for invalid JSON rather than an error.
			if err := json.Unmarshal([]byte(value), &result); err != nil {
				return nil
			}
			return result
		},
		"b64enc": func(value string) string {
			return base64.StdEncoding.EncodeToString([]byte(value))
		},
		"urlquery": url.QueryEscape,
	}
	output := make(map[string]string)
	for name, source := range input.Templates {
		panel, err := template.New(name).Funcs(functions).Parse(source)
		if err != nil {
			return fmt.Errorf("parse %s: %w", name, err)
		}
		var content bytes.Buffer
		if err := panel.Execute(&content, input); err != nil {
			return fmt.Errorf("render %s: %w", name, err)
		}
		output[name] = content.String()
	}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		return fmt.Errorf("write rendered panels: %w", err)
	}
	return nil
}

// stringList checks the string-array contract at the JSON test-process boundary.
func stringList(values []any) ([]string, error) {
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("expected a string-list item, got %T", value)
		}
		result = append(result, text)
	}
	return result, nil
}
