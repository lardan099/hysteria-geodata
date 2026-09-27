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

func writeProto(path string, message proto.Message) error {
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func deduplicateGeoIP(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}

	var list router.GeoIPList
	if err := proto.Unmarshal(data, &list); err != nil {
		return 0, fmt.Errorf("decode geoip: %w", err)
	}

	removed := 0
	for _, entry := range list.GetEntry() {
		seen := make(map[string]struct{}, len(entry.GetCidr()))
		unique := entry.Cidr[:0]
		for _, cidr := range entry.GetCidr() {
			key := cidrKey(cidr)
			if _, exists := seen[key]; exists {
				removed++
				continue
			}
			seen[key] = struct{}{}
			unique = append(unique, cidr)
		}
		entry.Cidr = unique
	}

	if err := writeProto(path, &list); err != nil {
		return 0, fmt.Errorf("write geoip: %w", err)
	}
	return removed, nil
}

func deduplicateGeoSite(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}

	var list router.GeoSiteList
	if err := proto.Unmarshal(data, &list); err != nil {
		return 0, fmt.Errorf("decode geosite: %w", err)
	}

	removed := 0
	for _, entry := range list.GetEntry() {
		seen := make(map[string]struct{}, len(entry.GetDomain()))
		unique := entry.Domain[:0]
		for _, domain := range entry.GetDomain() {
			key := domainKey(domain)
			if _, exists := seen[key]; exists {
				removed++
				continue
			}
			seen[key] = struct{}{}
			unique = append(unique, domain)
		}
		entry.Domain = unique
	}

	if err := writeProto(path, &list); err != nil {
		return 0, fmt.Errorf("write geosite: %w", err)
	}
	return removed, nil
}

func main() {
	geoIPPath := flag.String("geoip", "", "path to geoip.dat")
	geoSitePath := flag.String("geosite", "", "path to geosite.dat")
	flag.Parse()

	if *geoIPPath == "" || *geoSitePath == "" {
		fmt.Fprintln(os.Stderr, "both -geoip and -geosite are required")
		os.Exit(2)
	}

	removedGeoIP, err := deduplicateGeoIP(*geoIPPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	removedGeoSite, err := deduplicateGeoSite(*geoSitePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Printf("removed %d duplicate CIDRs and %d duplicate domain rules\n", removedGeoIP, removedGeoSite)
}
