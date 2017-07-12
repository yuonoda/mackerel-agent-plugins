package mpnetstat

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	mp "github.com/mackerelio/go-mackerel-plugin-helper"
)

// NetstatPlugin mackerel plugin for netstat
type NetstatPlugin struct {
	Prefix string
}

/*
{
    "IpExt": {
        "InBcastOctets": 0.0,
        "InBcastPkts": 0.0,
        "InCEPkts": 0.0,
        "InCsumErrors": 0.0,
        "InECT0Pkts": 0.0,
        "InECT1Pkts": 0.0,
        "InMcastOctets": 0.0,
        "InMcastPkts": 0.0,
        "InNoECTPkts": 0.0,
        "InNoRoutes": 0.0,
        "InOctets": 0.0,
        "InTruncatedPkts": 0.0,
        "OutBcastOctets": 0.0,
        "OutBcastPkts": 0.0,
        "OutMcastOctets": 0.0,
        "OutMcastPkts": 0.0,
        "OutOctets": 0.0
    },
    "TcpExt": {
        "ArpFilter": 0.0,
        "BusyPollRxPackets": 0.0,
        "DelayedACKLocked": 0.0,
        "DelayedACKLost": 0.0,
        "DelayedACKs": 0.0,
        "EmbryonicRsts": 0.0,
        "IPReversePathFilter": 0.0,
        "ListenDrops": 0.0,
        "ListenOverflows": 0.0,
        "LockDroppedIcmps": 0.0,
        "OfoPruned": 0.0,
        "OutOfWindowIcmps": 0.0,
        "PAWSActive": 0.0,
        "PAWSEstab": 0.0,
        "PAWSPassive": 0.0,
        "PruneCalled": 0.0,
        "RcvPruned": 0.0,
        "SyncookiesFailed": 0.0,
        "SyncookiesRecv": 0.0,
        "SyncookiesSent": 0.0,
        "TCPACKSkippedChallenge": 0.0,
        "TCPACKSkippedFinWait2": 0.0,
        "TCPACKSkippedPAWS": 0.0,
        "TCPACKSkippedSeq": 0.0,
        "TCPACKSkippedSynRecv": 0.0,
        "TCPACKSkippedTimeWait": 0.0,
        "TCPAbortFailed": 0.0,
        "TCPAbortOnClose": 0.0,
        "TCPAbortOnData": 0.0,
        "TCPAbortOnLinger": 0.0,
        "TCPAbortOnMemory": 0.0,
        "TCPAbortOnTimeout": 0.0,
        "TCPAutoCorking": 0.0,
        "TCPBacklogDrop": 0.0,
        "TCPChallengeACK": 0.0,
        "TCPDSACKIgnoredNoUndo": 0.0,
        "TCPDSACKIgnoredOld": 0.0,
        "TCPDSACKOfoRecv": 0.0,
        "TCPDSACKOfoSent": 0.0,
        "TCPDSACKOldSent": 0.0,
        "TCPDSACKRecv": 0.0,
        "TCPDSACKUndo": 0.0,
        "TCPDeferAcceptDrop": 0.0,
        "TCPDirectCopyFromBacklog": 0.0,
        "TCPDirectCopyFromPrequeue": 0.0,
        "TCPFACKReorder": 0.0,
        "TCPFastOpenActive": 0.0,
        "TCPFastOpenActiveFail": 0.0,
        "TCPFastOpenCookieReqd": 0.0,
        "TCPFastOpenListenOverflow": 0.0,
        "TCPFastOpenPassive": 0.0,
        "TCPFastOpenPassiveFail": 0.0,
        "TCPFastRetrans": 0.0,
        "TCPForwardRetrans": 0.0,
        "TCPFromZeroWindowAdv": 0.0,
        "TCPFullUndo": 0.0,
        "TCPHPAcks": 0.0,
        "TCPHPHits": 0.0,
        "TCPHPHitsToUser": 0.0,
        "TCPHystartDelayCwnd": 0.0,
        "TCPHystartDelayDetect": 0.0,
        "TCPHystartTrainCwnd": 0.0,
        "TCPHystartTrainDetect": 0.0,
        "TCPKeepAlive": 0.0,
        "TCPLossFailures": 0.0,
        "TCPLossProbeRecovery": 0.0,
        "TCPLossProbes": 0.0,
        "TCPLossUndo": 0.0,
        "TCPLostRetransmit": 0.0,
        "TCPMD5Failure": 0.0,
        "TCPMD5NotFound": 0.0,
        "TCPMD5Unexpected": 0.0,
        "TCPMTUPFail": 0.0,
        "TCPMTUPSuccess": 0.0,
        "TCPMemoryPressures": 0.0,
        "TCPMinTTLDrop": 0.0,
        "TCPOFODrop": 0.0,
        "TCPOFOMerge": 0.0,
        "TCPOFOQueue": 0.0,
        "TCPOrigDataSent": 0.0,
        "TCPPartialUndo": 0.0,
        "TCPPrequeueDropped": 0.0,
        "TCPPrequeued": 0.0,
        "TCPPureAcks": 0.0,
        "TCPRcvCoalesce": 0.0,
        "TCPRcvCollapsed": 0.0,
        "TCPRenoFailures": 0.0,
        "TCPRenoRecovery": 0.0,
        "TCPRenoRecoveryFail": 0.0,
        "TCPRenoReorder": 0.0,
        "TCPReqQFullDoCookies": 0.0,
        "TCPReqQFullDrop": 0.0,
        "TCPRetransFail": 0.0,
        "TCPSACKDiscard": 0.0,
        "TCPSACKReneging": 0.0,
        "TCPSACKReorder": 0.0,
        "TCPSYNChallenge": 0.0,
        "TCPSackFailures": 0.0,
        "TCPSackMerged": 0.0,
        "TCPSackRecovery": 0.0,
        "TCPSackRecoveryFail": 0.0,
        "TCPSackShiftFallback": 0.0,
        "TCPSackShifted": 0.0,
        "TCPSchedulerFailed": 0.0,
        "TCPSlowStartRetrans": 0.0,
        "TCPSpuriousRTOs": 0.0,
        "TCPSpuriousRtxHostQueues": 0.0,
        "TCPSynRetrans": 0.0,
        "TCPTSReorder": 0.0,
        "TCPTimeWaitOverflow": 0.0,
        "TCPTimeouts": 0.0,
        "TCPToZeroWindowAdv": 0.0,
        "TCPWantZeroWindowAdv": 0.0,
        "TCPWinProbe": 0.0,
        "TW": 0.0,
        "TWKilled": 0.0,
        "TWRecycled": 0.0
    },
    "time": 1499757088
}
*/

// GraphDefinition interface for mackerelplugin
func (m NetstatPlugin) GraphDefinition() map[string]mp.Graphs {
	labelPrefix := strings.Title(m.Prefix)
	return map[string]mp.Graphs{
		"TcpExt": {
			Label: (labelPrefix + " TcpExt"),
			Unit:  "float",
			Metrics: []mp.Metrics{
				{Name: "tcphp_acks", Label: "TCP HP Acks"},
				{Name: "tcphp_hits", Label: "CGO Call Num"},
			},
		},
		"IpExt": {
			Label: (labelPrefix + " IpExt"),
			Unit:  "float",
			Metrics: []mp.Metrics{
				{Name: "in_octets", Label: "In Octets"},
				{Name: "out_octets", Label: "Out Octets"},
			},
		},
	}
}

// FetchMetrics interface for mackerelplugin
func (m NetstatPlugin) FetchMetrics() (map[string]interface{}, error) {
	f, err := os.Open("/tmp/netstat")
	if err != nil {
		return make(map[string]interface{}), err
	}
	defer f.Close()

	stat := make(map[string]interface{})
	metrics := make(map[string]map[string][]string)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		rep := regexp.MustCompile(`:\s+`)
		arr := rep.Split(scanner.Text(), 2)
		category := arr[0]
		content := arr[1]

		if _, ok := metrics[category]; ok {
			rep := regexp.MustCompile(`\s+`)
			vals := rep.Split(content, -1)
			metrics[category]["vals"] = vals
		} else {
			metrics[category] = make(map[string][]string)
			rep := regexp.MustCompile(`\s+`)
			keys := rep.Split(content, -1)
			metrics[category]["keys"] = keys
		}
	}
	if serr := scanner.Err(); serr != nil {
		return make(map[string]interface{}), err
	}

	for _, metric := range metrics {
		newStat, err := zipMetric(metric["keys"], metric["vals"])
		if err != nil {
			return nil, err
		}

		mergeStat(stat, newStat)
	}

	// log.Printf("%+v", stat)
	return stat, err
}

func zipMetric(keys, vals []string) (map[string]interface{}, error) {
	stat := make(map[string]interface{})

	if len(keys) != len(vals) {
		return nil, fmt.Errorf("zip: arguments must be of same length")
	}

	for i, v := range vals {
		stat[camelToSnake(keys[i])] = v
	}

	return stat, nil
}

func mergeStat(dst, src map[string]interface{}) {
	for k, v := range src {
		dst[k] = v
	}
}

func camelToSnake(s string) string {
	camel := regexp.MustCompile("(^[^A-Z]*|[A-Z]*)([A-Z][^A-Z]+|$)")
	var a []string
	for _, sub := range camel.FindAllStringSubmatch(s, -1) {
		if sub[1] != "" {
			a = append(a, sub[1])
		}
		if sub[2] != "" {
			a = append(a, sub[2])
		}
	}
	return strings.ToLower(strings.Join(a, "_"))
}

// Do the plugin
func Do() {
	optPrefix := flag.String("metric-key-prefix", "netstat", "Metric key prefix")
	optTempfile := flag.String("tempfile", "", "Temp file name")
	flag.Parse()

	var netstat NetstatPlugin
	netstat.Prefix = *optPrefix

	helper := mp.NewMackerelPlugin(netstat)

	helper.Tempfile = *optTempfile
	helper.Run()
}
