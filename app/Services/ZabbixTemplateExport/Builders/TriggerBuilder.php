<?php

namespace App\Services\ZabbixTemplateExport\Builders;

use App\Models\Device;

class TriggerBuilder
{
    /**
     * Build static (non-prototype) triggers for the template.
     *
     * @return array<int, array<string, mixed>>
     */
    public function build(Device $device, string $templateName): array
    {
        $triggers = [];

        // ICMP availability trigger
        $triggers[] = [
            'expression' => 'max(/' . $templateName . '/icmpping,#3)=0',
            'name' => 'Unavailable by ICMP ping',
            'priority' => 'HIGH',
            'description' => 'Last three ICMP ping attempts failed',
        ];

        // High ICMP ping loss
        $triggers[] = [
            'expression' => 'min(/' . $templateName . '/icmppingloss,5m)>{$ICMP_LOSS_WARN}',
            'name' => 'High ICMP ping loss',
            'priority' => 'WARNING',
            'description' => 'ICMP packet loss exceeds {$ICMP_LOSS_WARN}%',
            'dependencies' => [
                ['name' => 'Unavailable by ICMP ping'],
            ],
        ];

        // High ICMP response time
        $triggers[] = [
            'expression' => 'avg(/' . $templateName . '/icmppingsec,5m)>{$ICMP_RESPONSE_TIME_WARN}',
            'name' => 'High ICMP ping response time',
            'priority' => 'WARNING',
            'description' => 'Average ICMP response time exceeds {$ICMP_RESPONSE_TIME_WARN}s',
            'dependencies' => [
                ['name' => 'Unavailable by ICMP ping'],
            ],
        ];

        // System uptime reboot detection
        $triggers[] = [
            'expression' => 'last(/' . $templateName . '/sysUpTime)<{$UPTIME_LOW}',
            'name' => 'Device has been restarted',
            'priority' => 'WARNING',
            'description' => 'System uptime is below {$UPTIME_LOW}s, indicating a recent reboot',
        ];

        // System name changed
        $triggers[] = [
            'expression' => 'change(/' . $templateName . '/sysName)<>0 and length(/' . $templateName . '/sysName)>0',
            'name' => 'System name has changed',
            'priority' => 'INFO',
            'description' => 'System name has changed. Ack to close.',
            'manual_close' => 'YES',
        ];

        // Add sensor-based static triggers
        $sensorTriggers = $this->buildSensorTriggers($device, $templateName);
        $triggers = array_merge($triggers, $sensorTriggers);

        return $triggers;
    }

    /**
     * Build triggers for singleton (non-discovered) sensors.
     *
     * @return array<int, array<string, mixed>>
     */
    private function buildSensorTriggers(Device $device, string $templateName): array
    {
        $triggers = [];

        $grouped = $device->sensors->groupBy('sensor_type');
        $singletons = $grouped->filter(fn ($sensors) => $sensors->count() === 1)->flatten();

        foreach ($singletons as $sensor) {
            $class = $sensor->sensor_class;
            if ($class === 'state') {
                continue; // State sensors use value maps, not numeric thresholds
            }

            $classLabel = ucfirst(str_replace('_', ' ', $class));
            $type = preg_replace('/[^a-zA-Z0-9_]/', '_', $sensor->sensor_type);
            $index = preg_replace('/[^a-zA-Z0-9_.]/', '_', (string) $sensor->sensor_index);
            $itemKey = "sensor.{$class}.{$type}.{$index}";
            $name = $sensor->sensor_descr ?: "{$classLabel} {$sensor->sensor_index}";

            if ($sensor->sensor_limit !== null) {
                $triggers[] = [
                    'expression' => 'last(/' . $templateName . '/' . $itemKey . ')>' . $sensor->sensor_limit,
                    'name' => $name . ': High critical value',
                    'priority' => 'HIGH',
                    'description' => "{$classLabel} sensor '{$name}' exceeds critical threshold ({$sensor->sensor_limit})",
                ];
            }

            if ($sensor->sensor_limit_warn !== null) {
                $trigger = [
                    'expression' => 'last(/' . $templateName . '/' . $itemKey . ')>' . $sensor->sensor_limit_warn,
                    'name' => $name . ': High warning value',
                    'priority' => 'WARNING',
                    'description' => "{$classLabel} sensor '{$name}' exceeds warning threshold ({$sensor->sensor_limit_warn})",
                ];
                if ($sensor->sensor_limit !== null) {
                    $trigger['dependencies'] = [
                        ['name' => $name . ': High critical value'],
                    ];
                }
                $triggers[] = $trigger;
            }

            if ($sensor->sensor_limit_low !== null) {
                $triggers[] = [
                    'expression' => 'last(/' . $templateName . '/' . $itemKey . ')<' . $sensor->sensor_limit_low,
                    'name' => $name . ': Low critical value',
                    'priority' => 'HIGH',
                    'description' => "{$classLabel} sensor '{$name}' is below critical threshold ({$sensor->sensor_limit_low})",
                ];
            }

            if ($sensor->sensor_limit_low_warn !== null) {
                $trigger = [
                    'expression' => 'last(/' . $templateName . '/' . $itemKey . ')<' . $sensor->sensor_limit_low_warn,
                    'name' => $name . ': Low warning value',
                    'priority' => 'WARNING',
                    'description' => "{$classLabel} sensor '{$name}' is below warning threshold ({$sensor->sensor_limit_low_warn})",
                ];
                if ($sensor->sensor_limit_low !== null) {
                    $trigger['dependencies'] = [
                        ['name' => $name . ': Low critical value'],
                    ];
                }
                $triggers[] = $trigger;
            }
        }

        return $triggers;
    }
}
