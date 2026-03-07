package exporter

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	lsPrefix     = `^[^ ]+ `
	lsIPAddrPart = `[a-f0-9:.]+`
	lsIPNetPart  = lsIPAddrPart + `/\d+`
	lsConnPart   = `"(?P<conname>[^"]+)"(?P<coninst>\[\d+])?`
	lsConn       = `(?P<prefix>` +
		lsPrefix +
		lsConnPart +
		`)` +
		`:[ ]+`
	lsAddr = `(?P<leftclient>` + lsIPNetPart + `===)?` +
		`(?P<leftaddr>` + lsIPAddrPart + `)` +
		`(?P<lefthost><[^>]+?>)?` +
		`(?P<leftid>\[[^\]]+?])?` +
		`(?P<lefthop>---` + lsIPAddrPart + `)?` +
		`\.\.\.` +
		`(?P<righthop>` + lsIPAddrPart + `---)?` +
		`(?P<rightaddr>` + lsIPAddrPart + `|%any)` +
		`(?P<righthost><[^>]+>)?` +
		`(?P<rightid>\[[^\]]+])?` +
		`(?P<rightclient>===` + lsIPNetPart + `)?;`
	lsState = `(?P<prefix>` +
		lsPrefix +
		`#(?P<serialno>\d+): ` +
		lsConnPart +
		`)` +
		`(:\d+(\(tcp\))?)?` +
		`(` + lsIPAddrPart + `)?(:[^ ]+)? `
)

var lsStates = map[string]float64{
	"STATE_MAIN_R0":        0,
	"STATE_MAIN_I1":        1,
	"STATE_MAIN_R1":        2,
	"STATE_MAIN_I2":        3,
	"STATE_MAIN_R2":        4,
	"STATE_MAIN_I3":        5,
	"STATE_MAIN_R3":        6,
	"STATE_MAIN_I4":        7,
	"STATE_AGGR_R0":        8,
	"STATE_AGGR_I1":        9,
	"STATE_AGGR_R1":        10,
	"STATE_AGGR_I2":        11,
	"STATE_AGGR_R2":        12,
	"STATE_QUICK_R0":       13,
	"STATE_QUICK_I1":       14,
	"STATE_QUICK_R1":       15,
	"STATE_QUICK_I2":       16,
	"STATE_QUICK_R2":       17,
	"STATE_INFO":           18,
	"STATE_INFO_PROTECTED": 19,
	"STATE_XAUTH_R0":       20,
	"STATE_XAUTH_R1":       21,
	"STATE_MODE_CFG_R0":    22,
	"STATE_MODE_CFG_R1":    23,
	"STATE_MODE_CFG_R2":    24,
	"STATE_MODE_CFG_I1":    25,
	"STATE_XAUTH_I0":       26,
	"STATE_XAUTH_I1":       27,

	"STATE_V2_PARENT_I0":            29,
	"STATE_V2_PARENT_I1":            30,
	"STATE_V2_PARENT_I2":            31,
	"STATE_V2_PARENT_R0":            32,
	"STATE_V2_PARENT_R1":            33,
	"STATE_V2_IKE_AUTH_CHILD_I0":    34,
	"STATE_V2_IKE_AUTH_CHILD_R0":    35,
	"STATE_V2_NEW_CHILD_I0":         36,
	"STATE_V2_NEW_CHILD_I1":         37,
	"STATE_V2_REKEY_IKE_I0":         38,
	"STATE_V2_REKEY_IKE_I1":         39,
	"STATE_V2_REKEY_CHILD_I0":       40,
	"STATE_V2_REKEY_CHILD_I1":       41,
	"STATE_V2_NEW_CHILD_R0":         42,
	"STATE_V2_REKEY_IKE_R0":         43,
	"STATE_V2_REKEY_CHILD_R0":       44,
	"STATE_V2_ESTABLISHED_IKE_SA":   45,
	"STATE_V2_ESTABLISHED_CHILD_SA": 46,
	"STATE_V2_IKE_SA_DELETE":        47,
	"STATE_V2_CHILD_SA_DELETE":      48,
}

var (
	lsConnRE = regexp.MustCompile(lsConn)
	lsAddrRE = regexp.MustCompile(lsAddr)
)

var (
	lsStateRE     = regexp.MustCompile(lsState)
	lsParentIDRE  = regexp.MustCompile(`; (isakmp|ISAKMP SA |IKE SA )#(?P<parentid>\d+)`)
	lsStateNameRE = regexp.MustCompile(`(STATE_\w+)`)
	lsSPIRE       = regexp.MustCompile(`([a-z]+)[?:.][a-f0-9]+@` + lsIPAddrPart)
	lsTrafficRE   = regexp.MustCompile(`(AHin|AHout|ESPin|ESPout|IPCOMPin|IPCOMPout)=(\d+)(B|KB|MB)`)
	lsUsernameRE  = regexp.MustCompile(` username=(.+)$`)
)

var lsStatsRE = regexp.MustCompile(`IKE SAs: total\((\d+)\), half-open\((\d+)\)`)

var lsTrafficStatusRE = regexp.MustCompile(
	lsPrefix + `#(?P<serialno>\d+): ` + lsConnPart + `, type=[^,]+, add_time=[0-9]+, inBytes=(?P<inbytes>[0-9]+), outBytes=(?P<outbytes>[0-9]+)(, maxBytes=(?P<maxbytes>[^,]+))?, id=.*`)

func copyIkeSA(other *ikeSA) *ikeSA {
	return &ikeSA{
		Name:          other.Name,
		LocalHost:     other.LocalHost,
		LocalID:       other.LocalID,
		RemoteHost:    other.RemoteHost,
		RemoteID:      other.RemoteID,
		UID:           other.UID,
		Version:       other.Version,
		LocalVIPs:     other.LocalVIPs,
		RemoteVIPs:    other.RemoteVIPs,
		Established:   other.Established,
		RemoteXAuthID: other.RemoteXAuthID,
		RemoteEAPID:   other.RemoteEAPID,
		State:         "STATE_V2_IKE_SA_DELETE",
		ChildSAs:      make(map[string]*childSA),
	}
}

func makeChildSAName(sa *childSA) string {
	return fmt.Sprintf("%s-%d", sa.Name, sa.UID)
}

func ikeSAVersion(state string) uint8 {
	if strings.HasPrefix(state, "STATE_V2_") {
		return 2
	} else {
		return 1
	}
}

func (e *Exporter) scrapeLibreswan(b []byte) (m metrics, ok bool) {
	// keys are names, values are bare IKE SAs without serial
	ikeSAs := make(map[string]*ikeSA)
	// keys are serials
	childSAs := make(map[string]*childSA)
	// keys are serials
	ikeSAsById := make(map[string]*ikeSA)
	parentIds := make(map[string]string)
	localTS := make(map[string]string)
	remoteTS := make(map[string]string)
	lines := strings.Split(string(b)+"\n", "\n")
	for i := 0; i < len(lines); i++ {
		if matches := findNamedSubmatch(lsConnRE, lines[i]); matches != nil {
			name := matches["conname"] + matches["coninst"]
			s := strings.TrimPrefix(lines[i], matches["prefix"])
			if m := findNamedSubmatch(lsAddrRE, s); m != nil {
				localTS[name] = strings.Trim(m["leftclient"], "=")
				remoteTS[name] = strings.Trim(m["rightclient"], "=")
				localID := m["leftid"]
				if localID != "" {
					localID = strings.TrimPrefix(localID[1:len(localID)-1], "@")
				}
				remoteID := m["rightid"]
				if remoteID != "" {
					remoteID = strings.TrimPrefix(remoteID[1:len(remoteID)-1], "@")
				}
				ikeSAs[name] = &ikeSA{
					Name:       name,
					LocalHost:  m["leftaddr"],
					LocalID:    localID,
					RemoteHost: m["rightaddr"],
					RemoteID:   remoteID,
					ChildSAs:   make(map[string]*childSA),
				}
			}
		} else if matches := findNamedSubmatch(lsStateRE, lines[i]); matches != nil {
			name := matches["conname"] + matches["coninst"]
			serialno := matches["serialno"]
			n, _ := strconv.ParseUint(serialno, 10, 32)
			child := false
			if parentidMatch := findNamedSubmatch(lsParentIDRE, lines[i]); parentidMatch != nil {
				child = true
				parentIds[serialno] = parentidMatch["parentid"]
				childSAs[serialno] = &childSA{
					Name: name,
					UID:  uint32(n),
				}
				if s := localTS[name]; s != "" {
					childSAs[serialno].LocalTS = append(childSAs[serialno].LocalTS, s)
				}
				if s := remoteTS[name]; s != "" {
					childSAs[serialno].RemoteTS = append(childSAs[serialno].RemoteTS, s)
				}
			}
			for ; i < len(lines); i++ {
				if strings.HasPrefix(lines[i], matches["prefix"]) {
					s := strings.TrimPrefix(lines[i], matches["prefix"])
					if child {
						if ikeSA, ok := ikeSAsById[parentIds[serialno]]; ok {
							ikeSA.ChildSAs[makeChildSAName(childSAs[serialno])] = childSAs[serialno]
						} else if ikeSA, ok := e.prevM.ikeSAsById[parentIds[serialno]]; ok {
							newIkeSA := copyIkeSA(ikeSA)
							ikeSAsById[parentIds[serialno]] = newIkeSA
							newIkeSA.ChildSAs[makeChildSAName(childSAs[serialno])] = childSAs[serialno]
						} else if ikeSA, ok := ikeSAs[name]; ok {
							newIkeSA := copyIkeSA(ikeSA)
							newIkeSAUid, _ := strconv.ParseUint(parentIds[serialno], 10, 32)
							newIkeSA.UID = uint32(newIkeSAUid)
							ikeSAsById[parentIds[serialno]] = newIkeSA
							newIkeSA.ChildSAs[makeChildSAName(childSAs[serialno])] = childSAs[serialno]
						}
						if m := lsStateNameRE.FindStringSubmatch(s); m != nil {
							childSAs[serialno].State = m[1]
							if ikeSA, ok := ikeSAsById[parentIds[serialno]]; ok {
								ikeSA.Version = ikeSAVersion(m[1])
							}
						}
						for _, m := range lsSPIRE.FindAllStringSubmatch(s, -1) {
							if m[1] == "tun" {
								childSAs[serialno].Mode = "TUNNEL"
								break
							}
						}
						for _, m := range lsTrafficRE.FindAllStringSubmatch(s, -1) {
							n, _ = strconv.ParseUint(m[2], 10, 64)
							switch m[3] {
							case "MB":
								n *= 1024
								fallthrough
							case "KB":
								n *= 1024
							}
							switch m[1] {
							case "AHin", "AHout":
								childSAs[serialno].Protocol = "AH"
							case "ESPin", "ESPout":
								childSAs[serialno].Protocol = "ESP"
							case "IPCOMPin", "IPCOMPout":
								childSAs[serialno].Protocol = "IPCOMP"
							}
							switch strings.TrimPrefix(m[1], childSAs[serialno].Protocol) {
							case "in":
								childSAs[serialno].InBytes = n
							case "out":
								childSAs[serialno].OutBytes = n
							}
						}
						if m := lsUsernameRE.FindStringSubmatch(s); m != nil {
							if ikeSA, ok := ikeSAsById[parentIds[serialno]]; ok {
								ikeSA.RemoteXAuthID = m[1]
							}
						}
					} else {
						if ikeSABase, ok := ikeSAs[name]; ok {
							newIkeSA := copyIkeSA(ikeSABase)
							newIkeSA.UID = uint32(n)
							if existingIkeSA, existing := ikeSAsById[serialno]; existing {
								newIkeSA.ChildSAs = existingIkeSA.ChildSAs
							}
							ikeSAsById[serialno] = newIkeSA
						}
						if m := lsStateNameRE.FindStringSubmatch(s); m != nil {
							if ikeSA, ok := ikeSAsById[serialno]; ok {
								ikeSA.State = m[1]
								ikeSA.Version = ikeSAVersion(m[1])
							}
						}
					}
				} else {
					i--
					break
				}
			}
		} else if matches := lsStatsRE.FindStringSubmatch(lines[i]); matches != nil {
			n, _ := strconv.ParseUint(matches[1], 10, 64)
			m.Stats.IKESAs.Total = n
			n, _ = strconv.ParseUint(matches[2], 10, 64)
			m.Stats.IKESAs.HalfOpen = n
		} else if matches := findNamedSubmatch(lsTrafficStatusRE, lines[i]); matches != nil {
			serialNo := matches["serialno"]
			inBytes, _ := strconv.ParseUint(matches["inbytes"], 10, 64)
			outBytes, _ := strconv.ParseUint(matches["outbytes"], 10, 64)
			childSAs[serialNo].InBytes = inBytes
			childSAs[serialNo].OutBytes = outBytes
		}
	}
	m.ikeSAsById = ikeSAsById
	for _, ikeSA := range ikeSAsById {
		if ikeSA.UID > 0 {
			m.IKESAs = append(m.IKESAs, ikeSA)
		}
	}
	ok = true
	return
}

func findNamedSubmatch(re *regexp.Regexp, s string) map[string]string {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return nil
	}
	result := make(map[string]string)
	for i, name := range re.SubexpNames() {
		if i > 0 && name != "" {
			result[name] = m[i]
		}
	}
	return result
}

func init() {
	for k, v := range lsStates {
		ikeSAStates[k] = v
		childSAStates[k] = v
	}
}
