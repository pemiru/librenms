<?php

namespace App\Services\ZabbixTemplateExport\Builders;

use App\Models\Device;

class MacroBuilder
{
    /**
     * Build Zabbix user macros from device data.
     * These macros provide tunable thresholds and SNMP configuration.
     *
     * @return array<int, array{macro: string, value: string, description: string}>
     */
    public function build(Device $device): array
    {
        $macros = [];

        $macros[] = [
            'macro' => '{$SNMP_COMMUNITY}',
            'value' => '{$SNMP_COMMUNITY}',
            'description' => 'SNMP community string (override per host)',
        ];

        $macros[] = [
            'macro' => '{$SNMP_PORT}',
            'value' => '161',
            'description' => 'SNMP port',
        ];

        $macros[] = [
            'macro' => '{$SNMP_TIMEOUT}',
            'value' => '3s',
            'description' => 'SNMP timeout for requests',
        ];

        // Sensor threshold macros derived from actual device sensor limits
        $thresholds = $this->collectSensorThresholds($device);
        foreach ($thresholds as $macro) {
            $macros[] = $macro;
        }

        // Port utilization macro
        $macros[] = [
            'macro' => '{$IF_UTIL_MAX}',
            'value' => '90',
            'description' => 'Interface utilization threshold percentage',
        ];

        // Uptime reboot detection
        $macros[] = [
            'macro' => '{$UPTIME_LOW}',
            'value' => '600',
            'description' => 'Uptime threshold in seconds to detect a recent reboot',
        ];

        // ICMP loss/latency
        $macros[] = [
            'macro' => '{$ICMP_LOSS_WARN}',
            'value' => '20',
            'description' => 'ICMP packet loss warning threshold percentage',
        ];

        $macros[] = [
            'macro' => '{$ICMP_RESPONSE_TIME_WARN}',
            'value' => '0.15',
            'description' => 'ICMP response time warning threshold in seconds',
        ];

        return $macros;
    }

    /**
     * Derive threshold macros from the sensor types present on the device.
     *
     * @return array<int, array{macro: string, value: string, description: string}>
     */
    private function collectSensorThresholds(Device $device): array
    {
        $macros = [];
        $seenClasses = [];

        foreach ($device->sensors as $sensor) {
            $class = $sensor->sensor_class;
            if (isset($seenClasses[$class])) {
                continue;
            }
            $seenClasses[$class] = true;

            $classUpper = strtoupper($class);

            if ($sensor->sensor_limit !== null) {
                $macros[] = [
                    'macro' => '{$SENSOR_' . $classUpper . '_HIGH}',
                    'value' => (string) $sensor->sensor_limit,
                    'description' => ucfirst($class) . ' sensor high critical threshold',
                ];
            }

            if ($sensor->sensor_limit_warn !== null) {
                $macros[] = [
                    'macro' => '{$SENSOR_' . $classUpper . '_WARN_HIGH}',
                    'value' => (string) $sensor->sensor_limit_warn,
                    'description' => ucfirst($class) . ' sensor high warning threshold',
                ];
            }

            if ($sensor->sensor_limit_low !== null) {
                $macros[] = [
                    'macro' => '{$SENSOR_' . $classUpper . '_LOW}',
                    'value' => (string) $sensor->sensor_limit_low,
                    'description' => ucfirst($class) . ' sensor low critical threshold',
                ];
            }

            if ($sensor->sensor_limit_low_warn !== null) {
                $macros[] = [
                    'macro' => '{$SENSOR_' . $classUpper . '_WARN_LOW}',
                    'value' => (string) $sensor->sensor_limit_low_warn,
                    'description' => ucfirst($class) . ' sensor low warning threshold',
                ];
            }
        }

        return $macros;
    }
}
