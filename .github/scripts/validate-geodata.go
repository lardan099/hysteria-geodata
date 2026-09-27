package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	router "github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

func splitRequired(value string) []string {
	if value == "" {
		return nil
	}

	items := strings.Split(value, ",")
	result := make([]string, 0, len(items))
	for _, item := range items {
		if item = strings.ToUpper(strings.TrimSpace(item)); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func domainKey(domain *router.Domain) string {
	value := domain.GetValue()
	if domain.GetType() != router.Domain_Regex {
		value = strings.ToLower(value)
	}

	attributes := make([]string, 0, len(domain.GetAttribute()))
	for _, attribute := range domain.GetAttribute() {
		attributes = append(attributes, fmt.Sprintf(
			"%s:%t:%d",
			strings.ToLower(attribute.GetKey()),
			attribute.GetBoolValue(),
			attribute.GetIntValue(),
		))
	}
	sort.Strings(attributes)

	return fmt.Sprintf("%d|%s|%s", domain.GetType(), value, strings.Join(attributes, ","))
}

func cidrKey(cidr *router.CIDR) string {
	ip := net.IP(cidr.GetIp()).String()
	if ip == "<nil>" {
		ip = strings.ToLower(cidr.GetIpAddr())
	}
	return fmt.Sprintf("%s/%d", ip, cidr.GetPrefix())
}

func validateRequired(kind string, present map[string]int, required []string) error {
	for _, name := range required {
		count, ok := present[name]
		if !ok {
			return fmt.Errorf("%s list %q is missing", kind, name)
		}
		if count == 0 {
			return fmt.Errorf("%s list %q is empty", kind, name)
		}
	}
	return nil
}

func validateGeoIP(path string, required []string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var list router.GeoIPList
	if err := proto.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("decode geoip: %w", err)
	}

	present := make(map[string]int, len(list.GetEntry()))
	for _, entry := range list.GetEntry() {
		name := strings.ToUpper(strings.TrimSpace(entry.GetCountryCode()))
		if _, exists := present[name]; exists {
			return fmt.Errorf("duplicate geoip list %q", name)
		}

		seen := make(map[string]struct{}, len(entry.GetCidr()))
		for _, cidr := range entry.GetCidr() {
			key := cidrKey(cidr)
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate CIDR %q in geoip list %q", key, name)
			}
			seen[key] = struct{}{}
		}
		present[name] = len(seen)
	}

	if err := validateRequired("geoip", present, required); err != nil {
		return err
	}
	fmt.Printf("geoip: %d lists validated with no duplicate CIDRs\n", len(present))
	return nil
}

func validateGeoSite(path string, required []string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var list router.GeoSiteList
	if err := proto.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("decode geosite: %w", err)
	}

	present := make(map[string]int, len(list.GetEntry()))
	for _, entry := range list.GetEntry() {
		name := strings.ToUpper(strings.TrimSpace(entry.GetCountryCode()))
		if _, exists := present[name]; exists {
			return fmt.Errorf("duplicate geosite list %q", name)
		}

		seen := make(map[string]struct{}, len(entry.GetDomain()))
		for _, domain := range entry.GetDomain() {
			key := domainKey(domain)
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate domain rule %q in geosite list %q", domain.GetValue(), name)
			}
			seen[key] = struct{}{}
		}
		present[name] = len(seen)
	}

	if err := validateRequired("geosite", present, required); err != nil {
		return err
	}
	fmt.Printf("geosite: %d lists validated with no duplicate domain rules\n", len(present))
	return nil
}

func main() {
	geoIPPath := flag.String("geoip", "", "path to geoip.dat")
	geoSitePath := flag.String("geosite", "", "path to geosite.dat")
	requiredGeoIP := flag.String("require-geoip", "", "comma-separated required GeoIP lists")
	requiredGeoSite := flag.String("require-geosite", "", "comma-separated required GeoSite lists")
	flag.Parse()

	if *geoIPPath == "" || *geoSitePath == "" {
		fmt.Fprintln(os.Stderr, "both -geoip and -geosite are required")
		os.Exit(2)
	}

	if err := validateGeoIP(*geoIPPath, splitRequired(*requiredGeoIP)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := validateGeoSite(*geoSitePath, splitRequired(*requiredGeoSite)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
