package main

import (
	"bytes"
	"fmt"
	"image/color"
	"os"

	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/vg"
)

type benchSummary struct {
	totalFiles        int
	totalUncompressed int64
	results           []benchResult
}

type benchResult struct {
	name            string
	totalCompressed int64
	cpuUsage        int64
}

func (s *benchSummary) printCSV() {
	fmt.Printf("Total files: %d\n", s.totalFiles)
	fmt.Printf("Total uncompressed: %d bytes\n", s.totalUncompressed)
	fmt.Print("\n", string(s.csvBytes()))
}

func (s *benchSummary) toCSV(filename string) error {
	return os.WriteFile(filename, s.csvBytes(), 0o600)
}

func (s *benchSummary) csvBytes() []byte {
	buf := bytes.NewBuffer(make([]byte, 0, 1024))
	buf.WriteString("Compressor,Total compressed,CPU usage\n")
	for _, r := range s.results {
		_, _ = fmt.Fprintf(buf, "%s,%d,%d\n", r.name, r.totalCompressed, r.cpuUsage)
	}
	return buf.Bytes()
}

func (s *benchSummary) toBarChart(filename string) error {
	p := plot.New()

	p.Title.Text = "Compression Results"
	p.Y.Label.Text = "Go Compressors"
	p.X.Label.Text = "in % (smaller is better)"

	// Order results by compression rate, but put "none" last, so it is plotted on top.
	none := s.results[0]
	for i := 1; i < len(s.results); i++ {
		s.results[i-1] = s.results[i]
	}
	s.results[len(s.results)-1] = none

	// Calculate compression rates as percentages.
	compressionRates := make(plotter.Values, len(s.results))
	for i, r := range s.results {
		compressionRates[i] = percent(s.totalUncompressed, r.totalCompressed)
	}

	// Find the maximum CPU usage and use it as "100%".
	maxCPUUsage := int64(0)
	for _, r := range s.results {
		maxCPUUsage = max(maxCPUUsage, r.cpuUsage)
	}

	// Calculate CPU usage as percentages.
	cpuUsages := make(plotter.Values, len(s.results))
	for i, r := range s.results {
		cpuUsages[i] = percent(maxCPUUsage, r.cpuUsage)
	}

	labels := make([]string, len(s.results))
	for i, r := range s.results {
		labels[i] = r.name
	}

	bars, err := plotter.NewBarChart(compressionRates, vg.Points(20))
	if err != nil {
		return err
	}

	bars.Horizontal = true
	bars.LineStyle.Width = vg.Length(0)
	bars.Color = color.RGBA{R: 0, G: 0, B: 128, A: 255}
	bars.Offset = -vg.Points(10)
	p.Legend.Add("Compressed size", bars)

	bars2, err := plotter.NewBarChart(cpuUsages, vg.Points(20))
	if err != nil {
		return err
	}

	bars2.Horizontal = true
	bars2.LineStyle.Width = vg.Length(0)
	bars2.Color = color.RGBA{R: 128, G: 0, B: 0, A: 255}
	bars2.Offset = vg.Points(10)
	p.Legend.Add("CPU usage", bars2)

	p.Add(bars, bars2)
	p.NominalY(labels...)

	// Save the plot to a PNG file.
	if err := p.Save(10*vg.Inch, 10*vg.Inch, filename); err != nil {
		return err
	}

	return nil
}

func percent(total, part int64) float64 {
	return (float64(part) / float64(total)) * 100
}
