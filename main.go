package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const onlyUserProcs = true

type dpair struct{ r, w uint64 }
type nq struct{ rx, tx uint64; ns string }

var ws = regexp.MustCompile(`[[:space:]]+`)

func u64(s string) uint64 { v, _ := strconv.ParseUint(s, 10, 64); return v }

func pname(pid int) string {
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
		if n := strings.TrimSpace(string(b)); n != "" { return n }
	}
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		if n := strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " ")); n != "" { return n }
	}
	return "unknown"
}

func snapDisk() map[int]dpair {
	out := make(map[int]dpair)
	d, _ := os.ReadDir("/proc")
	for _, e := range d {
		if !e.IsDir() { continue }
		pid, err := strconv.Atoi(e.Name()); if err != nil { continue }
		b, err := os.ReadFile("/proc/" + e.Name() + "/io"); if err != nil { continue }
		var r, w uint64
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			t := sc.Text()
			if strings.HasPrefix(t, "read_bytes:")  { r = u64(strings.TrimSpace(strings.TrimPrefix(t, "read_bytes:"))) }
			if strings.HasPrefix(t, "write_bytes:") { w = u64(strings.TrimSpace(strings.TrimPrefix(t, "write_bytes:"))) }
		}
		out[pid] = dpair{r, w}
	}
	return out
}

// TCP-only via INET_DIAG: per-PID cumulative bytes_received/bytes_acked (like `ss -p`).
func snapNet() map[int]nq {
	out := make(map[int]nq)

	inodeToPID := make(map[uint64]int, 1<<15)
	pidNS := make(map[int]string, 1<<15)

	d, _ := os.ReadDir("/proc")
	for _, e := range d {
		if !e.IsDir() { continue }
		pid, err := strconv.Atoi(e.Name()); if err != nil { continue }

		ns := "?"
		if tgt, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid)); err == nil && tgt != "" { ns = tgt }
		pidNS[pid] = ns

		fds, _ := os.ReadDir("/proc/" + e.Name() + "/fd")
		for _, fd := range fds {
			tgt, err := os.Readlink("/proc/" + e.Name() + "/fd/" + fd.Name())
			if err != nil || !strings.HasPrefix(tgt, "socket:[") || !strings.HasSuffix(tgt, "]") { continue }
			ino, _ := strconv.ParseUint(tgt[8:len(tgt)-1], 10, 64)
			if ino != 0 { inodeToPID[ino] = pid }
		}
	}

	add := func(fam uint8) {
		msgs, err := netlink.SocketDiagTCPInfo(fam)
		if err != nil { return }
		for _, m := range msgs {
			if m == nil || m.InetDiagMsg == nil || m.TCPInfo == nil { continue }
			ino := uint64(m.InetDiagMsg.INode)
			pid, ok := inodeToPID[ino]; if !ok { continue }
			cur := out[pid]
			cur.rx += m.TCPInfo.Bytes_received
			cur.tx += m.TCPInfo.Bytes_acked
			if cur.ns == "" { cur.ns = pidNS[pid] }
			out[pid] = cur
		}
	}
	add(uint8(unix.AF_INET))
	add(uint8(unix.AF_INET6))
	return out
}

type row struct {
	pid   int
	comm  string
	rbps, wbps float64
	nrx,  ntx  float64
	ns    string // kept for filtering; not printed
}

func human(bps float64) string {
	u := []string{"B/s","KiB/s","MiB/s","GiB/s","TiB/s"}
	i := 0
	for bps >= 1024 && i < len(u)-1 { bps /= 1024; i++ }
	return fmt.Sprintf("%.1f %s", bps, u[i])
}

func fit(s string, n int) string { r := []rune(s); if len(r) > n { return string(r[:n]) }; return s }

func main() {
	_ = filepath.WalkDir("/proc", func(string, os.DirEntry, error) error { return nil })
	prevD := snapDisk()
	prevN := snapNet()

	// Baseline #1: /proc/net/dev (procfs aggregation)
	var prevProcRx, prevProcTx uint64
	if bb, err := os.ReadFile("/proc/net/dev"); err == nil {
		sc := bufio.NewScanner(bytes.NewReader(bb))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "Inter-") || strings.HasPrefix(line, "face") { continue }
			parts := strings.Split(line, ":"); if len(parts) != 2 { continue }
			f := ws.Split(strings.TrimSpace(parts[1]), -1); if len(f) < 16 { continue }
			prevProcRx += u64(f[0]); prevProcTx += u64(f[8])
		}
	}

	// Baseline #2: rtnetlink per-if counters (works without /sys)
	var prevRTNLrx, prevRTNLtx uint64
	if links, err := netlink.LinkList(); err == nil {
		for _, l := range links {
			if st := l.Attrs().Statistics; st != nil {
				prevRTNLrx += st.RxBytes
				prevRTNLtx += st.TxBytes
			}
		}
	}

	t0 := time.Now()
	for {
		time.Sleep(time.Second)
		t1 := time.Now()
		dt := t1.Sub(t0).Seconds(); if dt <= 0 { dt = 1 }

		curD := snapDisk()
		curN := snapNet()

		var sysDiskRbps, sysDiskWbps float64
		var rows []row
		seen := make(map[int]struct{})
		for k := range prevD { seen[k] = struct{}{} }
		for k := range curD  { seen[k] = struct{}{} }
		for k := range curN  { seen[k] = struct{}{} }

		for pid := range seen {
			p0d, ok0d := prevD[pid]
			p1d, ok1d := curD[pid]
			var rbps, wbps float64
			if ok0d && ok1d {
				dr := int64(p1d.r) - int64(p0d.r); if dr < 0 { dr = 0 }
				dw := int64(p1d.w) - int64(p0d.w); if dw < 0 { dw = 0 }
				rbps = float64(dr)/dt
				wbps = float64(dw)/dt
			}
			sysDiskRbps += rbps
			sysDiskWbps += wbps

			p0n, ok0n := prevN[pid]
			p1n, ok1n := curN[pid]
			var nrx, ntx float64; ns := ""
			if ok0n && ok1n {
				drx := int64(p1n.rx) - int64(p0n.rx); if drx < 0 { drx = 0 }
				dtx := int64(p1n.tx) - int64(p0n.tx); if dtx < 0 { dtx = 0 }
				nrx = float64(drx)/dt
				ntx = float64(dtx)/dt
				ns = p1n.ns
			}

			comm := pname(pid)

			if onlyUserProcs {
				kthread := false
				if bb, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
					kthread = len(bytes.Trim(bb, "\x00")) == 0
				}
				if ns == "?" { kthread = true }
				if strings.HasPrefix(comm, "kworker") || strings.HasPrefix(comm, "ksoftirqd") ||
					strings.HasPrefix(comm, "kthreadd") || strings.HasPrefix(comm, "rcu_") ||
					strings.HasPrefix(comm, "migration/") || strings.HasPrefix(comm, "irq/") ||
					strings.HasPrefix(comm, "cpuhp/") {
					kthread = true
				}
				if kthread { continue }
			}

			if rbps==0 && wbps==0 && nrx==0 && ntx==0 { continue }

			rows = append(rows, row{
				pid: pid, comm: comm,
				rbps: rbps, wbps: wbps,
				nrx: nrx,  ntx:  ntx,
				ns:  ns,
			})
		}

		// System NET totals: procfs view
		var curProcRx, curProcTx uint64
		if bb, err := os.ReadFile("/proc/net/dev"); err == nil {
			sc := bufio.NewScanner(bytes.NewReader(bb))
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" || strings.HasPrefix(line, "Inter-") || strings.HasPrefix(line, "face") { continue }
				parts := strings.Split(line, ":"); if len(parts) != 2 { continue }
				f := ws.Split(strings.TrimSpace(parts[1]), -1); if len(f) < 16 { continue }
				curProcRx += u64(f[0]); curProcTx += u64(f[8])
			}
		}
		sysNetRxBpsProc := float64(int64(curProcRx)-int64(prevProcRx)) / dt
		sysNetTxBpsProc := float64(int64(curProcTx)-int64(prevProcTx)) / dt
		if sysNetRxBpsProc < 0 { sysNetRxBpsProc = 0 }
		if sysNetTxBpsProc < 0 { sysNetTxBpsProc = 0 }
		prevProcRx, prevProcTx = curProcRx, curProcTx

		// System NET totals: rtnetlink view (independent of /sys)
		var curRTNLrx, curRTNLtx uint64
		if links, err := netlink.LinkList(); err == nil {
			for _, l := range links {
				if st := l.Attrs().Statistics; st != nil {
					curRTNLrx += st.RxBytes
					curRTNLtx += st.TxBytes
				}
			}
		}
		sysNetRxBpsRTNL := float64(int64(curRTNLrx)-int64(prevRTNLrx)) / dt
		sysNetTxBpsRTNL := float64(int64(curRTNLtx)-int64(prevRTNLtx)) / dt
		if sysNetRxBpsRTNL < 0 { sysNetRxBpsRTNL = 0 }
		if sysNetTxBpsRTNL < 0 { sysNetTxBpsRTNL = 0 }
		prevRTNLrx, prevRTNLtx = curRTNLrx, curRTNLtx

		// Choose dominant metric and sort
		maxR, maxW, maxNRX, maxNTX := 0.0, 0.0, 0.0, 0.0
		for _, r := range rows {
			if r.rbps > maxR { maxR = r.rbps }
			if r.wbps > maxW { maxW = r.wbps }
			if r.nrx  > maxNRX { maxNRX = r.nrx }
			if r.ntx  > maxNTX { maxNTX = r.ntx }
		}
		sortBy := "DISK_R"
		key := func(r row) float64 { return r.rbps }
		if maxW >= maxR && maxW >= maxNRX && maxW >= maxNTX { sortBy = "DISK_W"; key = func(r row) float64 { return r.wbps } }
		if maxNRX >= maxR && maxNRX >= maxW && maxNRX >= maxNTX { sortBy = "NET_RX"; key = func(r row) float64 { return r.nrx } }
		if maxNTX >= maxR && maxNTX >= maxW && maxNTX >= maxNRX { sortBy = "NET_TX"; key = func(r row) float64 { return r.ntx } }

		sort.Slice(rows, func(i, j int) bool {
			ai, aj := key(rows[i]), key(rows[j])
			if ai == aj {
				si := rows[i].rbps + rows[i].wbps + rows[i].nrx + rows[i].ntx
				sj := rows[j].rbps + rows[j].wbps + rows[j].nrx + rows[j].ntx
				return si > sj
			}
			return ai > aj
		})

		fmt.Print("\033[H\033[2J")
		fmt.Printf("per-proc DISK bytes/s + TCP bytes/s (INET_DIAG)  %s   [sort=%s]\n", time.Now().Format(time.RFC3339), sortBy)
		fmt.Printf("SYSTEM TOTAL:           DISK_R %-12s  DISK_W %-12s  NET_RX %-12s  NET_TX %-12s\n",
			human(sysDiskRbps), human(sysDiskWbps), human(sysNetRxBpsProc), human(sysNetTxBpsProc))
		fmt.Printf("SYSTEM TOTAL (rtnetlink)                        NET_RX %-12s  NET_TX %-12s\n\n",
			human(sysNetRxBpsRTNL), human(sysNetTxBpsRTNL))

		fmt.Printf("%-6s %-26s %12s %12s %12s %12s\n",
			"PID", "COMM", "DISK_R", "DISK_W", "NET_RX", "NET_TX")
		n := 20; if len(rows) < n { n = len(rows) }
		for i := 0; i < n; i++ {
			r := rows[i]
			fmt.Printf("%-6d %-26s %12s %12s %12s %12s\n",
				r.pid, fit(r.comm, 26), human(r.rbps), human(r.wbps), human(r.nrx), human(r.ntx))
		}

		prevD, prevN, t0 = curD, curN, t1
	}
}
