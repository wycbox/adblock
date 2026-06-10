package main

var RuleFiles = []RuleFile{
	{Filename: "adblock.txt", Rules: AdblockStable},
	{Filename: "adblock-preview.txt", Rules: AdblockPreview},
	{Filename: "adblock-test.txt", Rules: AdblockTest},
}

var (
	AdblockStable  = Rules{AdblockDNS, Adblock1, Adblock2}
	AdblockPreview = Rules{AdblockDNS, Adblock4, Adblock5}
	AdblockTest    = Rules{AdblockDNS, Adblock4, Adblock5}
)

var AdblockDNS = newFile(
	"https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/refs/heads/master/discretion/dns.txt",
	defaultParser(),
)

var Adblock1 = newFile(
	"https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/ADBLOCK_RULE_COLLECTION_DOMAIN_Lite.txt",
	defaultParser(),
)

var Adblock2 = newFile(
	"https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt",
	defaultParser(),
)

var Adblock3 = newFile(
	"https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockhosts.txt",
	hostsParser("0.0.0.0"),
)

var Adblock4 = newFile(
	"https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/dnsmasq_big.txt",
	dnsmasqParser,
)

var Adblock5 = newFile(
	"https://raw.githubusercontent.com/lingeringsound/10007_auto/master/all",
	hostsParser("0.0.0.0"),
)
