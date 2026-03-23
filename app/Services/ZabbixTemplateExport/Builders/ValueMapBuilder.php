<?php

namespace App\Services\ZabbixTemplateExport\Builders;

use App\Models\Device;

class ValueMapBuilder
{
    /**
     * Build Zabbix value maps from device state sensors.
     *
     * @return array<int, array{name: string, mappings: array<int, array{value: string, newvalue: string}>}>
     */
    public function build(Device $device): array
    {
        $valueMaps = [];

        // Standard IF-MIB interface value maps
        $valueMaps[] = [
            'name' => 'IF-MIB::ifOperStatus',
            'mappings' => [
                ['value' => '1', 'newvalue' => 'up'],
                ['value' => '2', 'newvalue' => 'down'],
                ['value' => '3', 'newvalue' => 'testing'],
                ['value' => '4', 'newvalue' => 'unknown'],
                ['value' => '5', 'newvalue' => 'dormant'],
                ['value' => '6', 'newvalue' => 'notPresent'],
                ['value' => '7', 'newvalue' => 'lowerLayerDown'],
            ],
        ];

        $valueMaps[] = [
            'name' => 'IF-MIB::ifAdminStatus',
            'mappings' => [
                ['value' => '1', 'newvalue' => 'up'],
                ['value' => '2', 'newvalue' => 'down'],
                ['value' => '3', 'newvalue' => 'testing'],
            ],
        ];

        $valueMaps[] = [
            'name' => 'IF-MIB::ifType',
            'mappings' => [
                ['value' => '1', 'newvalue' => 'other'],
                ['value' => '6', 'newvalue' => 'ethernetCsmacd'],
                ['value' => '24', 'newvalue' => 'softwareLoopback'],
                ['value' => '53', 'newvalue' => 'propVirtual'],
                ['value' => '131', 'newvalue' => 'tunnel'],
                ['value' => '135', 'newvalue' => 'l2vlan'],
                ['value' => '161', 'newvalue' => 'ieee8023adLag'],
            ],
        ];

        // Build value maps from state sensors
        $stateSensors = $device->sensors->where('sensor_class', 'state');
        $processedStates = [];

        foreach ($stateSensors as $sensor) {
            $stateIndex = $sensor->stateIndex;
            if (! $stateIndex) {
                continue;
            }

            $stateName = $stateIndex->state_name;
            if (isset($processedStates[$stateName])) {
                continue;
            }
            $processedStates[$stateName] = true;

            $translations = $stateIndex->translations;
            if ($translations->isEmpty()) {
                continue;
            }

            $mappings = [];
            foreach ($translations->sortBy('state_value') as $translation) {
                $mappings[] = [
                    'value' => (string) $translation->state_value,
                    'newvalue' => $translation->state_descr,
                ];
            }

            if (! empty($mappings)) {
                $valueMaps[] = [
                    'name' => $stateName,
                    'mappings' => $mappings,
                ];
            }
        }

        return $valueMaps;
    }
}
