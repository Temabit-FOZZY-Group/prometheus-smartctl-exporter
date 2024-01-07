// Copyright 2022 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	kingpin "github.com/alecthomas/kingpin/v2"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
)

// SMARTctlManagerCollector implements the Collector interface.
type SMARTctlManagerCollector struct {
	CollectPeriod         string
	CollectPeriodDuration time.Duration
	Devices               []string

	logger log.Logger
	mutex  sync.Mutex
}

// Describe sends the super-set of all possible descriptors of metrics
func (i *SMARTctlManagerCollector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(i, ch)
}

// Collect is called by the Prometheus registry when collecting metrics.
func (i *SMARTctlManagerCollector) Collect(ch chan<- prometheus.Metric) {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	info := NewSMARTctlInfo(ch)
	for _, device := range i.Devices {
		json := readData(i.logger, device)
		if json.Exists() {
			info.SetJSON(json)
			smart := NewSMARTctl(i.logger, json, ch)
			smart.Collect()
		}
	}
	ch <- prometheus.MustNewConstMetric(
		metricDeviceCount,
		prometheus.GaugeValue,
		float64(len(i.Devices)),
	)
	info.Collect()
}

func (i *SMARTctlManagerCollector) RescanForDevices(ctx context.Context) error {
	timer := time.NewTimer(*smartctlRescanInterval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			err := ctx.Err()
			level.Info(i.logger).Log("msg", "Stop rescanning for devices because the context is end", "err", err)
			return err
		case <-timer.C:
			level.Info(i.logger).Log("msg", "Rescanning for devices")
			devices := scanDevices(i.logger)
			i.mutex.Lock()
			i.Devices = devices
			i.mutex.Unlock()
		}
	}
}

var (
	smartctlPath = kingpin.Flag("smartctl.path",
		"The path to the smartctl binary",
	).Default("/usr/sbin/smartctl").String()
	smartctlInterval = kingpin.Flag("smartctl.interval",
		"The interval between smartctl polls",
	).Default("60s").Duration()
	smartctlRescanInterval = kingpin.Flag("smartctl.rescan",
		"The interval between rescanning for new/disappeared devices. If the interval is smaller than 1s no rescanning takes place. If any devices are configured with smartctl.device also no rescanning takes place.",
	).Default("10m").Duration()
	smartctlDevices = kingpin.Flag("smartctl.device",
		"The device to monitor (repeatable)",
	).Strings()
	smartctlDeviceExclude = kingpin.Flag(
		"smartctl.device-exclude",
		"Regexp of devices to exclude from automatic scanning. (mutually exclusive to device-include)",
	).Default("").String()
	smartctlDeviceInclude = kingpin.Flag(
		"smartctl.device-include",
		"Regexp of devices to exclude from automatic scanning. (mutually exclusive to device-exclude)",
	).Default("").String()
	smartctlFakeData = kingpin.Flag("smartctl.fake-data",
		"The device to monitor (repeatable)",
	).Default("false").Hidden().Bool()
)

// scanDevices uses smartctl to gather the list of available devices.
func scanDevices(logger log.Logger) []string {
	filter := newDeviceFilter(*smartctlDeviceExclude, *smartctlDeviceInclude)

	json := readSMARTctlDevices(logger)
	devices := json.Get("devices").Array()
	var scanDeviceResult []string
	for _, d := range devices {
		deviceName := d.Get("name").String()
		if filter.ignored(deviceName) {
			level.Info(logger).Log("msg", "Ignoring device", "name", deviceName)
		} else {
			level.Info(logger).Log("msg", "Found device", "name", deviceName)
			scanDeviceResult = append(scanDeviceResult, deviceName)
		}
	}
	return scanDeviceResult
}

func main() {
	metricsPath := kingpin.Flag(
		"web.telemetry-path", "Path under which to expose metrics",
	).Default("/metrics").String()
	toolkitFlags := webflag.AddFlags(kingpin.CommandLine, ":9633")

	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("smartctl_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	level.Info(logger).Log("msg", "Starting smartctl_exporter", "version", version.Info())
	level.Info(logger).Log("msg", "Build context", "build_context", version.BuildContext())

	var devices []string
	if len(*smartctlDevices) > 0 {
		devices = *smartctlDevices
	} else {
		level.Info(logger).Log("msg", "No devices specified, trying to load them automatically")
		devices = scanDevices(logger)
		level.Info(logger).Log("msg", "Number of devices found", "count", len(devices))
	}

	collector := SMARTctlManagerCollector{
		Devices: devices,
		logger:  logger,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	defer cancel()

	if *smartctlRescanInterval >= 1*time.Second && len(*smartctlDevices) == 0 {
		level.Info(logger).Log("msg", "Start background scan process")
		level.Info(logger).Log("msg", "Rescanning for devices every", "rescanInterval", *smartctlRescanInterval)
		go func() {
			if err := collector.RescanForDevices(ctx); !noError(err) {
				level.Error(logger).Log("msg", "Rescanning for devices function exit with error", "err", err)
			}
		}()
	}

	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		collectors.NewGoCollector(),
	)

	prometheus.WrapRegistererWithPrefix("", reg).MustRegister(&collector)

	http.Handle(*metricsPath, promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))

	if *metricsPath != "/" && *metricsPath != "" {
		landingConfig := web.LandingConfig{
			Name:        "smartctl_exporter",
			Description: "Prometheus Exporter for S.M.A.R.T. devices",
			Version:     version.Info(),
			Links: []web.LandingLinks{
				{
					Address: *metricsPath,
					Text:    "Metrics",
				},
			},
		}
		landingPage, err := web.NewLandingPage(landingConfig)
		if err != nil {
			level.Error(logger).Log("err", err)
			os.Exit(1)
		}
		http.Handle("/", landingPage)
	}

	srv := &http.Server{}
	go func() {
		if err := web.ListenAndServe(srv, toolkitFlags, logger); !noError(err) {
			level.Error(logger).Log("msg", "ListenAndServe function exit with error", "err", err)
		}
	}()

	<-ctx.Done()

	srvShutdownCtx, srvShutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer srvShutdownCancel()
	err := srv.Shutdown(srvShutdownCtx)
	if err == nil {
		err = ctx.Err()
	}

	if !noError(err) {
		level.Error(logger).Log("err", err)
		os.Exit(1)
	}
}

func noError(err error) bool {
	return err == nil ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, http.ErrServerClosed)
}
