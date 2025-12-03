import { diag, DiagConsoleLogger, DiagLogLevel, metrics } from "@opentelemetry/api";
import { logs } from "@opentelemetry/api-logs";
diag.setLogger(new DiagConsoleLogger(), DiagLogLevel.INFO);

import { resourceFromAttributes } from '@opentelemetry/resources';
import { BatchSpanProcessor, NodeTracerProvider } from '@opentelemetry/sdk-trace-node';
import { PeriodicExportingMetricReader, MeterProvider } from '@opentelemetry/sdk-metrics';
import { HostMetrics } from '@opentelemetry/host-metrics';
import { LoggerProvider, BatchLogRecordProcessor } from '@opentelemetry/sdk-logs';
import { registerInstrumentations } from '@opentelemetry/instrumentation';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';

import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-http';
import { OTLPLogExporter } from '@opentelemetry/exporter-logs-otlp-http';

import { settings } from "./settings";
import * as os from 'os';

if (settings.enabled) {
  // Build resource from configured attributes
  const resource = resourceFromAttributes(settings.serverResourceAttributes ?? {});

  const metricsProvider = new MeterProvider({
    resource,
    readers: [
      new PeriodicExportingMetricReader({
        exporter: new OTLPMetricExporter({
          url: settings.otlpEndpoint ? `${settings.otlpEndpoint}/v1/metrics` : undefined,
        }),
        // Export metrics frequently so Grafana panels update in near real-time
        exportIntervalMillis: 2_000,
      }),
    ],
  });
  metrics.setGlobalMeterProvider(metricsProvider);

  const meter = metricsProvider.getMeter('meteor-server');

  // Start collecting host-level CPU and memory metrics (system.*)
  try {
    const hostMetrics = new HostMetrics({
      meterProvider: metricsProvider,
      // name: 'host-metrics', // optional
    });
    hostMetrics.start();
  } catch (err) {
    diag.warn('Failed to start HostMetrics instrumentation', err as any);
  }

  const processMemoryGauge = meter.createObservableGauge('meteorjs_memory_usage', {
    description: 'Node.js process memory usage reported by process.memoryUsage()',
    unit: 'By',
  });
  processMemoryGauge.addCallback((observableResult) => {
    const memory = process.memoryUsage();
    observableResult.observe(memory.rss, { memory_type: 'rss' });
    observableResult.observe(memory.heapTotal, { memory_type: 'heapTotal' });
    observableResult.observe(memory.heapUsed, { memory_type: 'heapUsed' });
    observableResult.observe(memory.external, { memory_type: 'external' });
    if (memory.arrayBuffers !== undefined) {
      observableResult.observe(memory.arrayBuffers, { memory_type: 'arrayBuffers' });
    }
  });

  const processCpuGauge = meter.createObservableGauge('meteorjs_cpu_utilization', {
    description: 'Average Node.js process CPU utilization between collections',
    unit: '1',
  });
  let lastCpuUsage = process.cpuUsage();
  let lastHrtime = process.hrtime.bigint();
  const cpuCount = Math.max(os.cpus().length, 1);
  processCpuGauge.addCallback((observableResult) => {
    const currentCpuUsage = process.cpuUsage();
    const currentHrtime = process.hrtime.bigint();

    const cpuUserDiff = currentCpuUsage.user - lastCpuUsage.user;
    const cpuSystemDiff = currentCpuUsage.system - lastCpuUsage.system;
    const cpuTotalDiffMicros = cpuUserDiff + cpuSystemDiff;
    const elapsedNs = Number(currentHrtime - lastHrtime);

    if (elapsedNs > 0 && cpuTotalDiffMicros >= 0) {
      const elapsedSeconds = elapsedNs / 1e9;
      const cpuSeconds = cpuTotalDiffMicros / 1e6;
      const utilization = cpuSeconds / elapsedSeconds / cpuCount;
      observableResult.observe(utilization);
    }

    lastCpuUsage = currentCpuUsage;
    lastHrtime = currentHrtime;
  });

  const tracer = new NodeTracerProvider({
    resource,
    spanProcessors: [
      new BatchSpanProcessor(new OTLPTraceExporter({
        url: settings.otlpEndpoint ? `${settings.otlpEndpoint}/v1/traces` : undefined,
      })),
    ],
  });
  // this also sets the global trace provider:
  tracer.register({});

  // Auto-instrument everything except HTTP and WebSocket. We also wire the meterProvider
  // so instrumentations that emit metrics can do so automatically.
  const autoInstrumentations = getNodeAutoInstrumentations({
    '@opentelemetry/instrumentation-http': { enabled: false },
    '@opentelemetry/instrumentation-undici': { enabled: false },
  }).filter((inst: any) => ![
    '@opentelemetry/instrumentation-ws',
    '@opentelemetry/instrumentation-http2',
    '@opentelemetry/instrumentation-socket.io',
  ].includes(inst.instrumentationName));

  registerInstrumentations({
    tracerProvider: tracer,
    meterProvider: metricsProvider,
    instrumentations: autoInstrumentations,
  });

  const logger = new LoggerProvider({
    resource,
    processors: [
      new BatchLogRecordProcessor(new OTLPLogExporter({
        url: settings.otlpEndpoint ? `${settings.otlpEndpoint}/v1/logs` : undefined,
      })),
    ],
  });
  logs.setGlobalLoggerProvider(logger);
}
