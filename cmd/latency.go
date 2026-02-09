package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"dnsdoc/internal/dnsprobe"

	"github.com/logrusorgru/aurora/v4"
	"github.com/spf13/cobra"
)

var (
	latencyBench   bool
	latencyBrute   int
	latencyDomains string
	latencyCompare string
)

var latencyCmd = &cobra.Command{
	Use:   "latency [dns-server]",
	Short: "Measure detailed DNS request timings (serial) and caching behavior (bench/brute). Optionally compare two resolvers.",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var server string
		if len(args) == 1 {
			server = args[0]
		} else {
			s, err := dnsprobe.SystemDefaultDNSServer()
			if err != nil {
				return fmt.Errorf("no dns-server arg and failed to detect system default resolver: %w", err)
			}
			server = s
		}

		ctx := context.Background()
		timeout := 3 * time.Second

		var domains []string
		if strings.TrimSpace(latencyDomains) != "" {
			for _, d := range strings.Split(latencyDomains, ",") {
				d = strings.TrimSpace(d)
				if d == "" {
					continue
				}
				domains = append(domains, d)
			}
			if len(domains) == 0 {
				return fmt.Errorf("--domains provided but no valid domains found after parsing")
			}
		} else {
			random128, err := dnsprobe.RandomDomain128WithCOM()
			if err != nil {
				return err
			}
			domains = []string{
				"google.com",
				"earentir.dev",
				random128,
			}
		}

		au := aurora.New(aurora.WithColors(true))

		for _, name := range domains {
			if strings.TrimSpace(latencyCompare) == "" {
				r, err := dnsprobe.ProbeA(ctx, server, name, timeout)
				if err != nil {
					printErrorBlock(server, name, err)
				} else {
					printResultBlock(r)
				}

				if latencyBench {
					bench := dnsprobe.BenchmarkSerial(ctx, server, name, timeout, 10)
					printBenchmarkBlock("bench (serial x10)", bench)
				}

				if latencyBrute > 0 {
					br := dnsprobe.BenchmarkConcurrent(ctx, server, name, timeout, latencyBrute)
					printBenchmarkBlock(fmt.Sprintf("brute (concurrent x%d)", latencyBrute), br)
				}
				continue
			}

			rA, errA := dnsprobe.ProbeA(ctx, server, name, timeout)
			rB, errB := dnsprobe.ProbeA(ctx, latencyCompare, name, timeout)

			fmt.Printf("\n=== %s (compare) ===\n", name)
			fmt.Printf("A:\t%s\n", server)
			fmt.Printf("B:\t%s\n", latencyCompare)

			if errA != nil || errB != nil {
				if errA != nil {
					fmt.Printf("\nA error:\t%v\n", errA)
				}
				if errB != nil {
					fmt.Printf("B error:\t%v\n", errB)
				}
			} else {
				printCompareTimingsTable(au, rA, rB)
			}

			if latencyBench {
				benchA := dnsprobe.BenchmarkSerial(ctx, server, name, timeout, 10)
				benchB := dnsprobe.BenchmarkSerial(ctx, latencyCompare, name, timeout, 10)
				printCompareBenchmarkTimingsTable(au, "bench (serial x10)", benchA, benchB)
			}

			if latencyBrute > 0 {
				brA := dnsprobe.BenchmarkConcurrent(ctx, server, name, timeout, latencyBrute)
				brB := dnsprobe.BenchmarkConcurrent(ctx, latencyCompare, name, timeout, latencyBrute)
				printCompareBenchmarkTimingsTable(au, fmt.Sprintf("brute (concurrent x%d)", latencyBrute), brA, brB)
			}
		}

		return nil
	},
}

func init() {
	latencyCmd.Flags().StringVar(&latencyDomains, "domains", "", "CSV of domains to test (overrides the default set). Example: --domains google.com,example.org")
	latencyCmd.Flags().StringVar(&latencyCompare, "compare", "", "Compare against another DNS server (host or host:port). Example: --compare 9.9.9.9")
	latencyCmd.Flags().BoolVar(&latencyBench, "bench", false, "Repeat serially 10 times after the first request and print averages (caching check).")
	latencyCmd.Flags().IntVar(&latencyBrute, "brute", 0, "Run N requests concurrently per domain and print averages (default disabled; typical N=250).")
}

func printErrorBlock(server, name string, err error) {
	fmt.Printf("\n=== %s ===\n", name)
	fmt.Printf("server:\t%s\n", server)
	fmt.Printf("error:\t%v\n", err)
}

func printResultBlock(r dnsprobe.Result) {
	fmt.Printf("\n=== %s ===\n", r.QName)
	fmt.Printf("server:\t%s\n", r.Server)
	fmt.Printf("network:\t%s\n", r.Network)
	fmt.Printf("local:\t%s\n", r.LocalAddr)
	fmt.Printf("remote:\t%s\n", r.RemoteAddr)
	fmt.Printf("timeout:\t%s\n", r.Timeout)
	fmt.Printf("qtype:\tA\n")

	fmt.Printf("\nresponse:\n")
	fmt.Printf("  rcode:\t%s\n", r.RCode)
	fmt.Printf("  id:\t%d\n", r.MsgID)
	fmt.Printf("  flags:\tQR=%t AA=%t TC=%t RD=%t RA=%t AD=%t CD=%t\n",
		r.Flags.QR, r.Flags.AA, r.Flags.TC, r.Flags.RD, r.Flags.RA, r.Flags.AD, r.Flags.CD)
	fmt.Printf("  counts:\tanswer=%d authority=%d additional=%d\n", r.AnswerCount, r.NSCount, r.ExtraCount)
	fmt.Printf("  sizes:\tquery=%dB response=%dB\n", r.QuerySizeBytes, r.ResponseSizeBytes)

	if len(r.Answers) > 0 {
		fmt.Printf("  answers:\n")
		for _, a := range r.Answers {
			fmt.Printf("    - %s\tTTL=%d\n", a.Value, a.TTL)
		}
	}

	fmt.Printf("\nTimings (wall-clock):\n")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "phase\tduration\tnotes")
	fmt.Fprintf(w, "total\t%s\t-\n", r.Timings.Total)
	fmt.Fprintf(w, "dial\t%s\tudp dial to server\n", r.Timings.Dial)
	fmt.Fprintf(w, "pack\t%s\tdns message -> wire bytes\n", r.Timings.Pack)
	fmt.Fprintf(w, "write\t%s\twrite query bytes\n", r.Timings.Write)
	fmt.Fprintf(w, "read\t%s\tread response bytes\n", r.Timings.Read)
	fmt.Fprintf(w, "unpack\t%s\twire bytes -> dns message\n", r.Timings.Unpack)
	fmt.Fprintf(w, "rtt(approx)\t%s\twrite+read (useful for caching deltas)\n", r.Timings.RTTApprox)
	_ = w.Flush()
}

func printBenchmarkBlock(label string, b dnsprobe.Benchmark) {
	fmt.Printf("\n%s:\n", label)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "metric\tvalue")
	fmt.Fprintf(w, "attempts\t%d\n", b.Attempts)
	fmt.Fprintf(w, "success\t%d\n", b.Success)
	fmt.Fprintf(w, "fail\t%d\n", b.Fail)
	fmt.Fprintf(w, "avg_total\t%s\n", b.Avg.Total)
	fmt.Fprintf(w, "avg_dial\t%s\n", b.Avg.Dial)
	fmt.Fprintf(w, "avg_pack\t%s\n", b.Avg.Pack)
	fmt.Fprintf(w, "avg_write\t%s\n", b.Avg.Write)
	fmt.Fprintf(w, "avg_read\t%s\n", b.Avg.Read)
	fmt.Fprintf(w, "avg_unpack\t%s\n", b.Avg.Unpack)
	fmt.Fprintf(w, "avg_rtt(approx)\t%s\n", b.Avg.RTTApprox)
	_ = w.Flush()
}

func printCompareTimingsTable(au *aurora.Aurora, a dnsprobe.Result, b dnsprobe.Result) {
	fmt.Printf("\nTimings compare (lower is better):\n")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "phase\tA\tB\tnotes")

	printCompareDurRow(au, w, "total", a.Timings.Total, b.Timings.Total, "-")
	printCompareDurRow(au, w, "dial", a.Timings.Dial, b.Timings.Dial, "udp dial to server")
	printCompareDurRow(au, w, "pack", a.Timings.Pack, b.Timings.Pack, "dns message -> wire bytes")
	printCompareDurRow(au, w, "write", a.Timings.Write, b.Timings.Write, "write query bytes")
	printCompareDurRow(au, w, "read", a.Timings.Read, b.Timings.Read, "read response bytes")
	printCompareDurRow(au, w, "unpack", a.Timings.Unpack, b.Timings.Unpack, "wire bytes -> dns message")
	printCompareDurRow(au, w, "rtt(approx)", a.Timings.RTTApprox, b.Timings.RTTApprox, "write+read")

	_ = w.Flush()
}

func printCompareBenchmarkTimingsTable(au *aurora.Aurora, label string, a dnsprobe.Benchmark, b dnsprobe.Benchmark) {
	fmt.Printf("\n%s compare (lower is better):\n", label)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "phase\tA\tB\tnotes")

	printCompareDurRow(au, w, "avg_total", a.Avg.Total, b.Avg.Total, "-")
	printCompareDurRow(au, w, "avg_dial", a.Avg.Dial, b.Avg.Dial, "udp dial to server")
	printCompareDurRow(au, w, "avg_pack", a.Avg.Pack, b.Avg.Pack, "dns message -> wire bytes")
	printCompareDurRow(au, w, "avg_write", a.Avg.Write, b.Avg.Write, "write query bytes")
	printCompareDurRow(au, w, "avg_read", a.Avg.Read, b.Avg.Read, "read response bytes")
	printCompareDurRow(au, w, "avg_unpack", a.Avg.Unpack, b.Avg.Unpack, "wire bytes -> dns message")
	printCompareDurRow(au, w, "avg_rtt(approx)", a.Avg.RTTApprox, b.Avg.RTTApprox, "write+read")

	_ = w.Flush()
}

func printCompareDurRow(au *aurora.Aurora, w *tabwriter.Writer, label string, a time.Duration, b time.Duration, notes string) {
	aS, bS := colorPairLowerBetter(au, a, b)
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", label, aS, bS, notes)
}

func colorPairLowerBetter(au *aurora.Aurora, a time.Duration, b time.Duration) (string, string) {
	if a == b {
		s := a.String()
		return fmt.Sprint(au.Gray(12, s)), fmt.Sprint(au.Gray(12, s))
	}
	if a < b {
		return fmt.Sprint(au.Green(a.String())), fmt.Sprint(au.Red(b.String()))
	}
	return fmt.Sprint(au.Red(a.String())), fmt.Sprint(au.Green(b.String()))
}
