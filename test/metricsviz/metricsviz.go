// Copyright 2024 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package metricsviz charts profiling metrics data and renders them to HTML.
package metricsviz

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/adler32"
	"html"
	"os"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/components"
	"github.com/go-echarts/go-echarts/v2/opts"
	echartstypes "github.com/go-echarts/go-echarts/v2/types"
	"google.golang.org/protobuf/encoding/protojson"
	"gvisor.dev/gvisor/pkg/metric"
	mpb "gvisor.dev/gvisor/pkg/metric/metric_go_proto"
)

const (
	htmlRawLogsPrefix = "GVISOR RAW LOGS:"
	htmlRawLogsSuffix = "/END OF RAW GVISOR LOGS"
)

// MetricName is the name of a metric.
type MetricName string

// Metric is the full metadata about a metric.
type Metric struct {
	// Name is the name of the metric.
	Name MetricName
	// Metadata is the metadata of the metric.
	Metadata *mpb.MetricMetadata
}

// MetricAndFields is a metric name and a set of field values.
type MetricAndFields struct {
	// MetricName is the name of the metric.
	MetricName MetricName
	// FieldValues is the comma-concatenated version of the field values.
	FieldValues string
}

// Point is a single data point at a given time within a time series.
type Point struct {
	// When is the time at which the value was measured.
	When time.Time
	// Value is the value that was measured at that time.
	Value uint64
}

// TimeSeries describes the evolution of a metric (for a given set of field
// values) over time.
type TimeSeries struct {
	// Metric is the metric being measured.
	Metric *Metric
	// Fields is the set of field values of the metric.
	FieldValues map[string]string
	// Data is the timestamped set of data points for this metric and field
	// values.
	Data []Point
}

// String returns the name of the timeseries.
func (ts *TimeSeries) String() string {
	if len(ts.FieldValues) == 0 {
		return ts.ChartTitle()
	}
	orderedFields := make([]string, 0, len(ts.FieldValues))
	for f := range ts.FieldValues {
		orderedFields = append(orderedFields, f)
	}
	sort.Strings(orderedFields)
	var b strings.Builder
	b.WriteString(string(ts.Metric.Name))
	b.WriteString("{")
	for i, f := range orderedFields {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(f)
		b.WriteString("=")
		b.WriteString(ts.FieldValues[f])
	}
	b.WriteString("}")
	return b.String()
}

// ChartTitle returns a string appropriate for using as a chart title when
// this timeseries is the only metric being shown on a chart.
func (ts *TimeSeries) ChartTitle() string {
	if desc := strings.TrimSuffix(ts.Metric.Metadata.GetDescription(), "."); desc != "" {
		return desc
	}
	return string(ts.Metric.Name)
}

// Data maps metrics and field values to timeseries.
type Data struct {
	startTime       time.Time
	rawLogs         string
	data            map[MetricAndFields]*TimeSeries
	collectionStats *metric.CollectionStats
}

// HTMLOptions are options for generating an HTML page with charts of the
// metrics data.
type HTMLOptions struct {
	// Title is the title of this set of charts.
	Title string

	// ContainerName is the name of the container for which the metrics were
	// collected. May be empty; usually only specified when there are more
	// than one container involved in a single test or benchmark.
	ContainerName string

	// When is the time at which the measurements were taken.
	When time.Time
}

type chart struct {
	Title  string
	Series []*TimeSeries
}

// isCumulative returns whether the given series are all cumulative or all
// not cumulative. It returns an error if the series are a mix of cumulative
// and non-cumulative timeseries.
func (c *chart) isCumulative() (bool, error) {
	var isCumulative bool
	for i, ts := range c.Series {
		tsCumulative := ts.Metric.Metadata.GetCumulative()
		if i == 0 {
			isCumulative = tsCumulative
		} else if isCumulative != tsCumulative {
			return false, fmt.Errorf("series %d (%v) is cumulative=%v, but series 0 (%v) is cumulative=%v", i, ts, tsCumulative, c.Series[0], isCumulative)
		}
	}
	return isCumulative, nil
}

// getXAxis returns the X axis labels for the chart.
func (c *chart) getXAxis() ([]string, error) {
	// Determine the resolution for the timestamps on the X axis.
	// We do this depending on how long the time series we are charting is.
	var xAxisResolution time.Duration
	if len(c.Series) == 0 || len(c.Series[0].Data) < 2 {
		return nil, errors.New("no series or not enough data points in series")
	}
	xMinTime := c.Series[0].Data[0].When
	xMaxTime := c.Series[0].Data[len(c.Series[0].Data)-1].When
	xDuration := xMaxTime.Sub(xMinTime)
	switch {
	case xDuration <= 11*time.Second:
		xAxisResolution = time.Nanosecond
	case xDuration <= 91*time.Second:
		xAxisResolution = time.Microsecond
	case xDuration <= 16*time.Minute:
		xAxisResolution = time.Millisecond
	default:
		xAxisResolution = time.Second
	}
	formatXAxis := func(t time.Time) string {
		secondTimestamp := t.Format("15:04:05")
		nanos := t.Nanosecond()
		onlyNanos := nanos % 1_000
		onlyMicros := (nanos / 1_000) % 1_000
		onlyMillis := (nanos / 1_000_000) % 1_000
		switch xAxisResolution {
		case time.Nanosecond:
			return fmt.Sprintf("%s.%03d_%03d_%03d", secondTimestamp, onlyMillis, onlyMicros, onlyNanos)
		case time.Microsecond:
			return fmt.Sprintf("%s.%03d_%03d", secondTimestamp, onlyMillis, onlyMicros)
		case time.Millisecond:
			return fmt.Sprintf("%s.%03d", secondTimestamp, onlyMillis)
		case time.Second:
			return secondTimestamp
		default:
			panic("invalid x axis resolution")
		}
	}
	var xAxis []string
	for i, ts := range c.Series {
		if i == 0 {
			// Define the X axis.
			xAxis = make([]string, len(ts.Data))
			for i, p := range ts.Data {
				xAxis[i] = formatXAxis(p.When)
			}
		} else {
			// Check that the X axis is the same for all series.
			if len(xAxis) != len(ts.Data) {
				return nil, fmt.Errorf("series %d has %d data points, but series 0 has %d", i, len(ts.Data), len(xAxis))
			}
			for j, p := range ts.Data {
				if xAxis[j] != formatXAxis(p.When) {
					return nil, fmt.Errorf("series %d and series 0 differ at data point %d: %q vs %q", i, j, xAxis[j], formatXAxis(p.When))
				}
			}
		}
	}
	return xAxis, nil
}

// series returns a single line series of the chart.
func (c *chart) series(ts *TimeSeries, isCumulative bool) ([]opts.LineData, error) {
	const (
		windowDuration  = time.Second
		minTimeToReport = 10 * time.Millisecond
	)
	seriesData := make([]opts.LineData, len(ts.Data))
	if isCumulative {
		timeSeriesIsLongEnough := false
		lastValidXIndex := 0
		for i, p := range ts.Data {
			baselineWhen := p.When.Add(-windowDuration)
			foundExactIndex := -1
			foundBeforeIndex := -1
			foundAfterIndex := -1
		baselineSearch:
			for j := lastValidXIndex; j <= i; j++ {
				jWhen := ts.Data[j].When
				switch {
				case jWhen.Equal(baselineWhen):
					foundExactIndex = j
					break baselineSearch
				case jWhen.Before(baselineWhen):
					foundBeforeIndex = j
				case jWhen.After(baselineWhen) && foundAfterIndex == -1:
					foundAfterIndex = j
					break baselineSearch
				default:
					return nil, fmt.Errorf("non-ordered timestamps in timeseries: %v", ts.Data)
				}
			}
			switch {
			case foundExactIndex != -1:
				lastValidXIndex = foundExactIndex
				baseline := ts.Data[foundExactIndex].Value
				seriesData[i] = opts.LineData{Value: p.Value - baseline, YAxisIndex: 0}
			case foundBeforeIndex != -1 && foundAfterIndex != -1:
				lastValidXIndex = foundBeforeIndex
				// Interpolate between the two points.
				baselineBefore := ts.Data[foundBeforeIndex].Value
				baselineAfter := ts.Data[foundAfterIndex].Value
				baselineDelta := baselineAfter - baselineBefore
				whenBefore := ts.Data[foundBeforeIndex].When
				whenAfter := ts.Data[foundAfterIndex].When
				whenDelta := whenAfter.Sub(whenBefore)
				baselineWhenFraction := float64(baselineWhen.Sub(whenBefore)) / float64(whenDelta)
				baseline := baselineBefore + uint64(float64(baselineDelta)*baselineWhenFraction)
				seriesData[i] = opts.LineData{Value: p.Value - baseline, YAxisIndex: 0, Symbol: "none"}
				timeSeriesIsLongEnough = true
			case p.When.Sub(ts.Data[0].When) >= minTimeToReport:
				// We don't yet have enough points to get a full `windowDuration`'s
				// worth of data, but we do have enough data to report something if
				// we assume that the rate can be extrapolated from the first point
				// until now.
				baselineBefore := ts.Data[0].Value
				baselineAfter := p.Value
				baselineDelta := baselineAfter - baselineBefore
				whenBefore := ts.Data[0].When
				whenAfter := p.When
				whenDelta := whenAfter.Sub(whenBefore)
				interpolationMultiplier := float64(windowDuration.Nanoseconds()) / float64(whenDelta.Nanoseconds())
				seriesData[i] = opts.LineData{Value: uint64(float64(baselineDelta) * interpolationMultiplier), YAxisIndex: 0, Symbol: "none"}
				timeSeriesIsLongEnough = true
			default:
				// Happens naturally for points too early in the timeseries,
				// set the point to nil.
				seriesData[i] = opts.LineData{Value: nil, YAxisIndex: 0, Symbol: "none"}
			}
		}
		if !timeSeriesIsLongEnough {
			return nil, fmt.Errorf("metric %v is cumulative but timeseries data for it is smaller than minimum chartable duration (%v), please run the workload for longer for cumulative timeseries to become meaningful", ts.Metric.Name, minTimeToReport)
		}
	} else {
		// Non-cumulative time series are more straightforward.
		for i, p := range ts.Data {
			seriesData[i] = opts.LineData{Value: p.Value, YAxisIndex: 0, Symbol: "none"}
		}
	}
	return seriesData, nil
}

// Charter creates a Charter for this chart.
func (c *chart) Charter() (components.Charter, error) {
	lineChart := charts.NewLine()
	yAxis := opts.YAxis{
		Scale: true,
		Show:  true,
	}
	isCumulative, err := c.isCumulative()
	if err != nil {
		return nil, fmt.Errorf("cannot determine cumulative-ness of the chart: %w", err)
	}
	xAxis, err := c.getXAxis()
	if err != nil {
		return nil, fmt.Errorf("cannot determine X axis of the chart: %w", err)
	}
	for _, ts := range c.Series {
		seriesData, err := c.series(ts, isCumulative)
		if err != nil {
			return nil, fmt.Errorf("cannot determine series data for %v: %w", ts, err)
		}
		lineChart.AddSeries(
			ts.String(),
			seriesData,
			charts.WithLabelOpts(opts.Label{Show: false}),
		)
	}
	chartTitle := c.Title
	if isCumulative {
		chartTitle += " per second"
		yAxis.Name = "per second"
	}
	lineChart.SetXAxis(xAxis)
	lineChart.SetGlobalOptions(
		charts.WithTitleOpts(opts.Title{Title: chartTitle}),
		charts.WithInitializationOpts(opts.Initialization{Theme: echartstypes.ThemeVintage}),
		charts.WithXAxisOpts(opts.XAxis{
			Show:        true,
			Data:        []string{"foo", "bar"},
			SplitNumber: 24,
			AxisLabel:   &opts.AxisLabel{Show: true},
		}),
		charts.WithYAxisOpts(yAxis, 0),
		charts.WithLegendOpts(opts.Legend{
			Show:         true,
			SelectedMode: "multiple",
			Orient:       "vertical",
			Right:        "5%",
			Padding:      []int{24, 8},
		}),
		charts.WithDataZoomOpts(opts.DataZoom{Type: "inside", XAxisIndex: 0}),
		charts.WithDataZoomOpts(opts.DataZoom{Type: "slider", XAxisIndex: 0}),
		charts.WithDataZoomOpts(opts.DataZoom{Type: "inside", YAxisIndex: []int{}}),
		charts.WithTooltipOpts(opts.Tooltip{Show: true, Trigger: "axis"}),
		charts.WithToolboxOpts(opts.Toolbox{
			Show: true,
			Feature: &opts.ToolBoxFeature{
				SaveAsImage: &opts.ToolBoxFeatureSaveAsImage{Name: "📸 PNG", Show: true, Type: "png"},
			},
		}),
	)
	lineChart.Validate()
	return lineChart, nil
}

const connectAllChartsJavascript = `
<script type="text/javascript">
let all_charts = [];
document.querySelectorAll('canvas, div').forEach(function(element) {
	const maybe_chart = echarts.getInstanceByDom(element);
	if (maybe_chart) {
		all_charts.push(maybe_chart);
	}
});
if (all_charts.length > 1) {
	echarts.connect(all_charts);
}
</script>
`

// ToHTML generates an HTML page with charts of the metrics data.
func (d *Data) ToHTML(opts HTMLOptions) (string, error) {
	page := components.NewPage()
	var chartTitleRoot string
	if opts.ContainerName == "" {
		chartTitleRoot = opts.Title
		page.PageTitle = fmt.Sprintf("Metrics for %s at %v", opts.Title, opts.When.Format(time.DateTime))
	} else {
		chartTitleRoot = fmt.Sprintf("%s [%s]", opts.Title, opts.ContainerName)
		page.PageTitle = fmt.Sprintf("Metrics for %s (container %s) at %v", opts.Title, opts.ContainerName, opts.When.Format(time.DateTime))
	}
	page.Theme = echartstypes.ThemeVintage
	page.SetLayout(components.PageFlexLayout)

	// Find which groups contain which metrics that we're seeing in the data.
	groupsToMetricNames := make(map[GroupName][]MetricName, len(d.data))
	for maf := range d.data {
		for groupName, metricsInGroup := range Groups {
			if slices.Contains(metricsInGroup, maf.MetricName) && !slices.Contains(groupsToMetricNames[groupName], maf.MetricName) {
				groupsToMetricNames[groupName] = append(groupsToMetricNames[groupName], maf.MetricName)
			}
		}
	}

	// Find which groups for which we have data for at least 2 metrics.
	// These metrics will be displayed in the group charts only.
	// The rest of the metrics will be displayed in their own chart.
	metricToGroups := make(map[MetricName][]GroupName, len(d.data))
	for groupName, activeGroupMetrics := range groupsToMetricNames {
		if len(activeGroupMetrics) >= 2 {
			for _, m := range activeGroupMetrics {
				metricToGroups[m] = append(metricToGroups[m], groupName)
			}
		}
	}

	// Now go through the data and group it by the chart it'll end up in.
	chartNameToChart := make(map[string]*chart, len(d.data))
	var chartNames []string
	for maf, ts := range d.data {
		groupsForMetric := metricToGroups[maf.MetricName]
		if len(groupsForMetric) > 0 {
			// Group metric chart.
			for _, groupName := range groupsForMetric {
				chartName := string(groupName)
				c, ok := chartNameToChart[chartName]
				if !ok {
					c = &chart{Title: fmt.Sprintf("%s: %s", chartTitleRoot, groupName)}
					chartNameToChart[chartName] = c
					chartNames = append(chartNames, chartName)
				}
				c.Series = append(c.Series, ts)
			}
		} else {
			// Individual metric chart.
			chartName := string(maf.MetricName)
			c, ok := chartNameToChart[chartName]
			if !ok {
				c = &chart{Title: fmt.Sprintf("%s: %s", chartTitleRoot, ts.ChartTitle())}
				chartNameToChart[chartName] = c
				chartNames = append(chartNames, chartName)
			}
			c.Series = append(c.Series, ts)
		}
	}
	sort.Strings(chartNames)
	for _, chartName := range chartNames {
		c := chartNameToChart[chartName]
		charter, err := c.Charter()
		if err != nil {
			return "", fmt.Errorf("failed to create charter for %q: %w", chartName, err)
		}
		page.AddCharts(charter)
	}
	page.InitAssets()
	page.Validate()
	var b bytes.Buffer
	if err := page.Render(&b); err != nil {
		return "", fmt.Errorf("failed to render page: %w", err)
	}
	pageHTML := b.String()

	// Insert raw logs in the HTML file itself as a comment.
	const headTag = "<head>"
	headTagIndex := strings.Index(pageHTML, headTag)
	if headTagIndex == -1 {
		return "", fmt.Errorf("no <head> tag found in HTML")
	}
	headTagFinishIndex := headTagIndex + len(headTag)
	pageHTML = pageHTML[:headTagFinishIndex] + "\n<!--\n" + htmlRawLogsPrefix + "\n" + d.rawLogs + "\n" + htmlRawLogsSuffix + "\n-->\n" + pageHTML[headTagFinishIndex:]

	// Add stats and warnings to the HTML file at the top of the page.
	const beginBodyTag = "<body>"
	beginBodyTagIndex := strings.Index(pageHTML, beginBodyTag)
	if beginBodyTagIndex == -1 {
		return "", fmt.Errorf("no <body> tag found in HTML")
	}
	var statsHTML strings.Builder
	statsHTML.WriteString("<ul>")
	var warningsHTML strings.Builder
	haveWarning := false
	if d.collectionStats != nil {
		d.collectionStats.Log(func(format string, val ...any) {
			statsHTML.WriteString("<li>")
			statsHTML.WriteString(html.EscapeString(fmt.Sprintf(format, val...)))
			statsHTML.WriteString("</li>")
		}, func(format string, val ...any) {
			if !haveWarning {
				warningsHTML.WriteString(`<div style="color: #990000; background: #FFF0F0; font-weight: bold; border: 2px solid #FF0000; padding: 1em;">`)
				warningsHTML.WriteString("<strong>WARNING</strong>: ")
				haveWarning = true
			}
			warningsHTML.WriteString(html.EscapeString(fmt.Sprintf(format, val...)))
			warningsHTML.WriteString("<br/>")
		})
	}
	statsHTML.WriteString("</ul>")
	if haveWarning {
		warningsHTML.WriteString("</div>")
	}
	pageHTML = pageHTML[:beginBodyTagIndex+len(beginBodyTag)] + warningsHTML.String() + statsHTML.String() + pageHTML[beginBodyTagIndex+len(beginBodyTag):]

	// Insert a script to link the charts' X axis together.
	const endBodyTag = "</body>"
	endBodyTagIndex := strings.Index(pageHTML, endBodyTag)
	if endBodyTagIndex == -1 {
		return "", fmt.Errorf("no </body> tag found in HTML")
	}
	pageHTML = pageHTML[:endBodyTagIndex] + connectAllChartsJavascript + pageHTML[endBodyTagIndex:]

	return pageHTML, nil
}

// ErrNoMetricData is returned when no metrics data is found in logs.
var ErrNoMetricData = errors.New("no metrics data found")

// Parse parses metrics data out of the given logs containing
// profiling metrics data.
// If `hasPrefix`, only lines prefixed with `metric.MetricsPrefix`
// will be parsed. If false, all lines will be parsed, and the
// prefix will be stripped if it is found.
// If the log does not contain any metrics data, ErrNoMetricData is returned.
// If the log does contain data but not all lines can be validated, an error
// is returned but the returned `*Data` is still populated as much as
// possible.
func Parse(logs string, hasPrefix bool) (*Data, error) {
	data := &Data{rawLogs: logs, data: make(map[MetricAndFields]*TimeSeries)}
	var header []MetricAndFields
	metricsMeta := make(map[MetricName]*Metric)
	lineChecksum := adler32.New()
	overallChecksum := adler32.New()
	checkedHash := false
	lineHashMismatch := false
	metricsLineFound := false
	var gotErrs []error
	for _, line := range strings.Split(logs, "\n") {
		if hasPrefix && !strings.HasPrefix(line, metric.MetricsPrefix) {
			continue
		}
		if line == "" {
			continue
		}
		metricsLineFound = true
		lineData := strings.TrimPrefix(line, metric.MetricsPrefix)

		// Check for hash match.
		if strings.HasPrefix(lineData, metric.MetricsHashIndicator) {
			hash := strings.TrimPrefix(lineData, metric.MetricsHashIndicator)
			wantHashInt64, err := strconv.ParseUint(strings.TrimPrefix(hash, "0x"), 16, 32)
			if err != nil {
				gotErrs = append(gotErrs, fmt.Errorf("invalid hash line: %q: %w", line, err))
				continue
			}
			checkedHash = true
			wantHash := uint32(wantHashInt64)
			if gotHash := overallChecksum.Sum32(); gotHash != wantHash {
				// If there has already been a line checksum mismatch, we already know
				// that the overall checksum won't match either, so no need to add
				// another error about it here.
				if !lineHashMismatch {
					gotErrs = append(gotErrs, fmt.Errorf("checksum mismatch: computed 0x%x, logs said it should be 0x%x. This is likely due to a log buffer overrun or similar issue causing some lines to be omitted; please configure the container or the runtime to allow higher logging volume", gotHash, wantHash))
				}
			}
			continue
		}

		// If it's not a hash line, add it to the hash regardless of which other
		// type of line it is.
		overallChecksum.Write([]byte(lineData))
		overallChecksum.Write([]byte("\n"))

		if hasPrefix {
			// There should be a per-line checksum at the end of each line.
			tabSplit := strings.Split(lineData, "\t")
			if len(tabSplit) < 2 {
				gotErrs = append(gotErrs, fmt.Errorf("invalid line: %q (no tab separator found)", line))
				continue
			}
			lineChecksum.Reset()
			lineChecksum.Write([]byte(strings.Join(tabSplit[:len(tabSplit)-1], "\t")))
			wantLineChecksum := fmt.Sprintf("0x%x", lineChecksum.Sum32())
			if gotLineChecksum := tabSplit[len(tabSplit)-1]; gotLineChecksum != wantLineChecksum {
				gotErrs = append(gotErrs, fmt.Errorf("per-line checksum mismatch: computed 0x%x, line said it should be 0x%x (%q). This is likely due to a log buffer overrun or similar issue causing some lines to be omitted; please configure the container or the runtime to allow higher logging volume", wantLineChecksum, gotLineChecksum, line))
				lineHashMismatch = true
				continue
			}
			lineData = strings.Join(tabSplit[:len(tabSplit)-1], "\t")
		}

		if strings.HasPrefix(lineData, metric.MetricsMetaIndicator) {
			lineMetadata := strings.TrimPrefix(lineData, metric.MetricsMetaIndicator)
			components := strings.Split(lineMetadata, "\t")
			if len(components) != 2 {
				return nil, fmt.Errorf("invalid meta line: %q", line)
			}
			name := MetricName(components[0])
			var metadata mpb.MetricMetadata
			if err := protojson.Unmarshal([]byte(components[1]), &metadata); err != nil {
				return nil, fmt.Errorf("invalid metric metadata line: %q", line)
			}
			metricsMeta[name] = &Metric{
				Name:     name,
				Metadata: &metadata,
			}
			continue
		}

		if strings.HasPrefix(lineData, metric.MetricsStartTimeIndicator) {
			timestamp, err := strconv.ParseUint(strings.TrimPrefix(lineData, metric.MetricsStartTimeIndicator), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid start time line: %q: %w", line, err)
			}
			const nanosPerSecond = 1_000_000_000
			data.startTime = time.Unix(int64(timestamp/nanosPerSecond), int64(timestamp%nanosPerSecond))
			continue
		}

		if strings.HasPrefix(lineData, metric.MetricsStatsIndicator) {
			stats, err := metric.ParseCollectionStats(lineData)
			if err != nil {
				return nil, fmt.Errorf("invalid stats line: %q: %w", line, err)
			}
			if data.collectionStats != nil {
				return nil, errors.New("multiple stats lines found in logs")
			}
			data.collectionStats = stats
			continue
		}

		// Check for the header line.
		if header == nil {
			// Assume the first non-metadata line is the header.
			headerCells := strings.Split(lineData, "\t")
			if headerCells[0] != metric.TimeColumn {
				return nil, fmt.Errorf("invalid header line: %q", line)
			}
			for i, cell := range headerCells[1:] {
				if hasPrefix && i == len(headerCells)-2 && cell == "Checksum" {
					// Ignore this column name; it is the column indicator for the per-line checksum.
					continue
				}
				var name MetricName
				var fieldCombination string
				leftBracketIndex := strings.Index(cell, "[")
				if leftBracketIndex != -1 {
					name = MetricName(cell[:leftBracketIndex])
					rightBracketIndex := strings.Index(cell, "]")
					if rightBracketIndex == -1 {
						return nil, fmt.Errorf("invalid header line: %q (%q has '[' bracket but no closing ']' at the end)", line, cell)
					}
					fieldCombination = cell[leftBracketIndex+1 : rightBracketIndex]
				} else {
					name = MetricName(cell)
				}
				metricMeta, ok := metricsMeta[name]
				if !ok {
					return nil, fmt.Errorf("invalid header line: %q (unknown metric %q)", line, name)
				}
				maf := MetricAndFields{MetricName: name, FieldValues: fieldCombination}
				header = append(header, maf)
				var fieldValues map[string]string
				if fieldCombination != "" {
					fieldsMeta := metricMeta.Metadata.GetFields()
					fieldValuesSplit := strings.Split(fieldCombination, ",")
					if len(fieldValuesSplit) != len(fieldsMeta) {
						return nil, fmt.Errorf("invalid header line: %q (metric %q has %d fields (%v), but %d field values were found in column header: %q)", line, name, len(fieldsMeta), fieldsMeta, len(fieldValuesSplit), fieldCombination)
					}
					fieldValues = make(map[string]string, len(fieldsMeta))
					for i, fieldMeta := range fieldsMeta {
						fieldValue := fieldValuesSplit[i]
						if !slices.Contains(fieldMeta.GetAllowedValues(), fieldValue) {
							return nil, fmt.Errorf("invalid header line: %q (metric %q has field %q that the header column claims to be %q, which is not in the allowed values: %v)", line, name, fieldMeta.GetFieldName(), fieldValue, fieldMeta.GetAllowedValues())
						}
						fieldValues[fieldMeta.GetFieldName()] = fieldValue
					}
				}
				data.data[maf] = &TimeSeries{Metric: metricsMeta[name], FieldValues: fieldValues}
			}
			continue
		}

		// Regular lines.
		tabularData := strings.Split(lineData, "\t")
		if len(tabularData) != len(header)+1 {
			return nil, fmt.Errorf("invalid data line: %q with %d components which does not match header which has %d components. This is likely due to a log buffer overrun or similar issue causing the line to be cut off; please configure the container or the runtime to allow higher logging volume", line, len(tabularData), len(header))
		}
		offsetNanos, err := strconv.ParseUint(tabularData[0], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid data line: %q (bad timestamp: %w)", line, err)
		}
		timestamp := data.startTime.Add(time.Duration(offsetNanos) * time.Nanosecond)
		for i, cell := range tabularData[1:] {
			timeseries := data.data[header[i]]
			value, err := strconv.ParseUint(cell, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid data line: %q (bad value in column %d: %q: %w)", line, i, cell, err)
			}
			timeseries.Data = append(timeseries.Data, Point{When: timestamp, Value: value})
		}
	}
	if !metricsLineFound {
		return nil, ErrNoMetricData
	}
	if data.startTime.IsZero() {
		return nil, fmt.Errorf("no start time found in logs")
	}
	if len(header) == 0 {
		return nil, fmt.Errorf("no header found in logs")
	}
	if hasPrefix && !checkedHash {
		gotErrs = append(gotErrs, fmt.Errorf("no hash data found in logs"))
	}
	switch len(gotErrs) {
	case 0:
		return data, nil
	case 1:
		return data, gotErrs[0]
	default:
		return data, fmt.Errorf("multiple errors found in logs: %v", gotErrs)
	}
}

var unsafeFileCharacters = regexp.MustCompile("[^-_a-zA-Z0-9., @:+=]+")

// slugify returns a slugified version of the given string, safe for use
// in a file path.
func slugify(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = unsafeFileCharacters.ReplaceAllString(s, "_")
	if s == "" {
		return "blank"
	}
	return s
}

// Container represents a container that can be stopped and from which we can
// get logs.
type Container interface {
	Stop(context.Context) error
	Status(context.Context) (types.ContainerState, error)
	Logs(context.Context) (string, error)
}

// FromContainerLogs parses a container's logs and reports metrics data
// found within.
// The container must be stopped or stoppable by the time this is called.
func FromContainerLogs(ctx context.Context, testLike testing.TB, container Container) {
	FromNamedContainerLogs(ctx, testLike, container, "")
}

// FromNamedContainerLogs parses a container's logs and reports metrics data
// found within, making note of the container's name on the results page.
// The container must be stopped or stoppable by the time this is called.
func FromNamedContainerLogs(ctx context.Context, testLike testing.TB, container Container, containerName string) {
	// If the container is not stopped, stop it.
	// This is necessary to flush the profiling metrics logs.
	st, err := container.Status(ctx)
	if err != nil {
		testLike.Fatalf("Failed to get container status: %v", err)
	}
	if st.Running {
		if err := container.Stop(ctx); err != nil {
			testLike.Fatalf("Failed to stop container: %v", err)
		}
	}
	// Get the logs.
	logs, err := container.Logs(ctx)
	if err != nil {
		testLike.Fatalf("Failed to get container logs: %v", err)
	}
	data, err := Parse(logs, true)
	if err != nil {
		if errors.Is(err, ErrNoMetricData) {
			return // No metric data in the logs, so stay quiet.
		}
		if data == nil {
			testLike.Fatalf("Failed to parse metrics data: %v", err)
		}
		testLike.Logf("Error while parsing metrics data (data may be incomplete): %v", err)
	}
	htmlOptions := HTMLOptions{
		Title:         testLike.Name(),
		ContainerName: containerName,
		When:          data.startTime,
	}
	html, err := data.ToHTML(htmlOptions)
	if err != nil {
		testLike.Fatalf("Failed to generate HTML: %v", err)
	}
	if err := publishHTMLFn(ctx, testLike.Logf, htmlOptions, html); err != nil {
		testLike.Fatalf("Failed to publish HTML: %v", err)
	}
}

// FromProfilingMetricsLogFile parses a profiling metrics log file
// (as created by --profiling-metrics-log) and reports metrics data within.
func FromProfilingMetricsLogFile(ctx context.Context, testLike testing.TB, logFile string) {
	contents, err := os.ReadFile(logFile)
	if err != nil {
		testLike.Fatalf("failed to read log file: %v", err)
	}
	if err := fromFile(ctx, testLike.Name(), logFile, contents, false, testLike.Logf); err != nil {
		testLike.Fatalf("Failed to process metrics logs file: %v", err)
	}
}

// FromFile reads a file and detects whether it is a profiling metrics log
// file or a file with GVISOR_METRICS-prefixed lines.
// Either way, it parses the metrics data and reports it.
func FromFile(ctx context.Context, logFile string, logFn func(string, ...any)) error {
	contents, err := os.ReadFile(logFile)
	if err != nil {
		return fmt.Errorf("failed to read log file: %w", err)
	}
	lines := strings.Split(string(contents), "\n")
	logName := strings.TrimSuffix(path.Base(logFile), ".log")
	foundRawHTMLPrefix := -1
	foundRawHTMLSuffix := -1
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == htmlRawLogsPrefix {
			foundRawHTMLPrefix = i
		} else if line == htmlRawLogsSuffix {
			foundRawHTMLSuffix = i
		}
	}
	if foundRawHTMLPrefix != -1 && foundRawHTMLSuffix != -1 {
		// Isolate the contents of the raw logs from inside the HTML file.
		lines = lines[foundRawHTMLPrefix+1 : foundRawHTMLSuffix]
		contents = []byte(strings.Join(lines, "\n"))
	}
	for _, line := range lines {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, metric.MetricsPrefix) {
			return fromFile(ctx, logName, logFile, contents, true, logFn)
		}
		if strings.HasPrefix(line, metric.TimeColumn) {
			return fromFile(ctx, logName, logFile, contents, false, logFn)
		}
	}
	return fmt.Errorf("could not recognize %q as a metrics log file", logFile)
}

func fromFile(ctx context.Context, name, logFile string, logContents []byte, hasPrefix bool, logFn func(string, ...any)) error {
	data, err := Parse(string(logContents), hasPrefix)
	if err != nil {
		if errors.Is(err, ErrNoMetricData) {
			return nil // No metric data in the logs, so stay quiet.
		}
		if data == nil {
			return fmt.Errorf("failed to parse metrics data: %w", err)
		}
		logFn("Error while parsing metrics data (data may be incomplete): %v", err)
	}
	htmlOptions := HTMLOptions{
		Title: name,
		When:  data.startTime,
	}
	html, err := data.ToHTML(htmlOptions)
	if err != nil {
		return fmt.Errorf("failed to generate HTML: %w", err)
	}
	if strings.HasSuffix(logFile, ".log") {
		// Best-effort conversion to HTML next to the .log file in the directory,
		// if permissions allow that. Ignore errors, what matters more is the
		// publishing step later on.
		_ = os.WriteFile(strings.TrimSuffix(logFile, ".log")+".html", []byte(html), 0644)
	}
	if err := publishHTMLFn(ctx, logFn, htmlOptions, html); err != nil {
		return fmt.Errorf("failed to publish HTML: %w", err)
	}
	return nil
}
