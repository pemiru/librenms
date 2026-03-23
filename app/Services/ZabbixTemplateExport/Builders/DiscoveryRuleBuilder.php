<?php

namespace App\Services\ZabbixTemplateExport\Builders;

use App\Models\Device;
use App\Models\Sensor;

class DiscoveryRuleBuilder
{
    private ItemBuilder $itemBuilder;

    public function __construct(ItemBuilder $itemBuilder)
    {
        $this->itemBuilder = $itemBuilder;
    }

    /**
     * Build Zabbix discovery rules from device data.
     * Ports are always discovered via IF-MIB. Sensors with multiple instances
     * of the same type are grouped into discovery rules.
     *
     * @return array<int, array<string, mixed>>
     */
    public function build(Device $device, string $templateName): array
    {
        $rules = [];

        // Network interface discovery (IF-MIB)
        if ($device->ports->isNotEmpty()) {
            $rules[] = $this->buildInterfaceDiscovery($templateName);
        }

        // Sensor discovery rules - group sensors by type
        $sensorGroups = $this->itemBuilder->getDiscoverableSensorGroups($device);
        foreach ($sensorGroups as $sensorType => $sensors) {
            $rules[] = $this->buildSensorDiscovery($sensorType, $sensors, $templateName);
        }

        return $rules;
    }

    /**
     * Build the standard IF-MIB network interface discovery rule.
     */
    private function buildInterfaceDiscovery(string $templateName): array
    {
        return [
            'name' => 'Network interface discovery',
            'type' => 'SNMP_AGENT',
            'snmp_oid' => 'discovery[{#IFNAME},.1.3.6.1.2.1.2.2.1.2,{#IFALIAS},.1.3.6.1.2.1.31.1.1.1.18,{#IFTYPE},.1.3.6.1.2.1.2.2.1.3,{#IFADMINSTATUS},.1.3.6.1.2.1.2.2.1.7]',
            'key' => 'net.if.discovery',
            'delay' => '1h',
            'description' => 'Discovers network interfaces via IF-MIB::ifTable',
            'filter' => [
                'evaltype' => 'AND',
                'conditions' => [
                    [
                        'macro' => '{#IFADMINSTATUS}',
                        'value' => '1',
                        'formulaid' => 'A',
                    ],
                    [
                        'macro' => '{#IFTYPE}',
                        'value' => '(1|6|7|11|62|69|117|131|135|161)',
                        'operator' => 'MATCHES_REGEX',
                        'formulaid' => 'B',
                    ],
                ],
            ],
            'item_prototypes' => $this->buildInterfaceItemPrototypes($templateName),
            'trigger_prototypes' => $this->buildInterfaceTriggerPrototypes($templateName),
            'graph_prototypes' => $this->buildInterfaceGraphPrototypes($templateName),
        ];
    }

    /**
     * Build item prototypes for network interface discovery.
     */
    private function buildInterfaceItemPrototypes(string $templateName): array
    {
        return [
            [
                'name' => 'Interface {#IFNAME}: Inbound traffic',
                'type' => 'SNMP_AGENT',
                'snmp_oid' => '.1.3.6.1.2.1.31.1.1.1.6.{#SNMPINDEX}',
                'key' => 'net.if.in[ifHCInOctets.{#SNMPINDEX}]',
                'value_type' => 'UNSIGNED',
                'units' => 'bps',
                'delay' => '3m',
                'history' => '7d',
                'trends' => '365d',
                'description' => 'IF-MIB::ifHCInOctets counter for interface {#IFNAME}',
                'preprocessing' => [
                    ['type' => 'CHANGE_PER_SECOND', 'parameters' => []],
                    ['type' => 'MULTIPLIER', 'parameters' => ['8']],
                ],
            ],
            [
                'name' => 'Interface {#IFNAME}: Outbound traffic',
                'type' => 'SNMP_AGENT',
                'snmp_oid' => '.1.3.6.1.2.1.31.1.1.1.10.{#SNMPINDEX}',
                'key' => 'net.if.out[ifHCOutOctets.{#SNMPINDEX}]',
                'value_type' => 'UNSIGNED',
                'units' => 'bps',
                'delay' => '3m',
                'history' => '7d',
                'trends' => '365d',
                'description' => 'IF-MIB::ifHCOutOctets counter for interface {#IFNAME}',
                'preprocessing' => [
                    ['type' => 'CHANGE_PER_SECOND', 'parameters' => []],
                    ['type' => 'MULTIPLIER', 'parameters' => ['8']],
                ],
            ],
            [
                'name' => 'Interface {#IFNAME}: Inbound errors',
                'type' => 'SNMP_AGENT',
                'snmp_oid' => '.1.3.6.1.2.1.2.2.1.14.{#SNMPINDEX}',
                'key' => 'net.if.in.errors[ifInErrors.{#SNMPINDEX}]',
                'value_type' => 'UNSIGNED',
                'units' => '',
                'delay' => '3m',
                'history' => '7d',
                'trends' => '365d',
                'description' => 'IF-MIB::ifInErrors counter for interface {#IFNAME}',
                'preprocessing' => [
                    ['type' => 'CHANGE_PER_SECOND', 'parameters' => []],
                ],
            ],
            [
                'name' => 'Interface {#IFNAME}: Outbound errors',
                'type' => 'SNMP_AGENT',
                'snmp_oid' => '.1.3.6.1.2.1.2.2.1.20.{#SNMPINDEX}',
                'key' => 'net.if.out.errors[ifOutErrors.{#SNMPINDEX}]',
                'value_type' => 'UNSIGNED',
                'units' => '',
                'delay' => '3m',
                'history' => '7d',
                'trends' => '365d',
                'description' => 'IF-MIB::ifOutErrors counter for interface {#IFNAME}',
                'preprocessing' => [
                    ['type' => 'CHANGE_PER_SECOND', 'parameters' => []],
                ],
            ],
            [
                'name' => 'Interface {#IFNAME}: Operational status',
                'type' => 'SNMP_AGENT',
                'snmp_oid' => '.1.3.6.1.2.1.2.2.1.8.{#SNMPINDEX}',
                'key' => 'net.if.status[ifOperStatus.{#SNMPINDEX}]',
                'value_type' => 'UNSIGNED',
                'units' => '',
                'delay' => '3m',
                'history' => '7d',
                'trends' => '365d',
                'description' => 'IF-MIB::ifOperStatus for interface {#IFNAME}',
                'valuemap' => ['name' => 'IF-MIB::ifOperStatus'],
            ],
            [
                'name' => 'Interface {#IFNAME}: Admin status',
                'type' => 'SNMP_AGENT',
                'snmp_oid' => '.1.3.6.1.2.1.2.2.1.7.{#SNMPINDEX}',
                'key' => 'net.if.admin.status[ifAdminStatus.{#SNMPINDEX}]',
                'value_type' => 'UNSIGNED',
                'units' => '',
                'delay' => '3m',
                'history' => '7d',
                'trends' => '365d',
                'description' => 'IF-MIB::ifAdminStatus for interface {#IFNAME}',
                'valuemap' => ['name' => 'IF-MIB::ifAdminStatus'],
            ],
            [
                'name' => 'Interface {#IFNAME}: Speed',
                'type' => 'SNMP_AGENT',
                'snmp_oid' => '.1.3.6.1.2.1.31.1.1.1.15.{#SNMPINDEX}',
                'key' => 'net.if.speed[ifHighSpeed.{#SNMPINDEX}]',
                'value_type' => 'UNSIGNED',
                'units' => '',
                'delay' => '5m',
                'history' => '7d',
                'trends' => '365d',
                'description' => 'IF-MIB::ifHighSpeed for interface {#IFNAME} (in Mbps)',
                'preprocessing' => [
                    ['type' => 'MULTIPLIER', 'parameters' => ['1000000']],
                ],
            ],
            [
                'name' => 'Interface {#IFNAME}: Type',
                'type' => 'SNMP_AGENT',
                'snmp_oid' => '.1.3.6.1.2.1.2.2.1.3.{#SNMPINDEX}',
                'key' => 'net.if.type[ifType.{#SNMPINDEX}]',
                'value_type' => 'UNSIGNED',
                'units' => '',
                'delay' => '1h',
                'history' => '7d',
                'trends' => '365d',
                'description' => 'IF-MIB::ifType for interface {#IFNAME}',
                'valuemap' => ['name' => 'IF-MIB::ifType'],
            ],
        ];
    }

    /**
     * Build trigger prototypes for network interface discovery.
     */
    private function buildInterfaceTriggerPrototypes(string $templateName): array
    {
        return [
            [
                'expression' => 'last(/' . $templateName . '/net.if.status[ifOperStatus.{#SNMPINDEX}])=2 and last(/' . $templateName . '/net.if.admin.status[ifAdminStatus.{#SNMPINDEX}])=1',
                'name' => 'Interface {#IFNAME}: Link down',
                'priority' => 'AVERAGE',
                'description' => 'Interface {#IFNAME} is operationally down while administratively up',
            ],
            [
                'expression' => 'change(/' . $templateName . '/net.if.speed[ifHighSpeed.{#SNMPINDEX}])<>0 and last(/' . $templateName . '/net.if.speed[ifHighSpeed.{#SNMPINDEX}])>0',
                'name' => 'Interface {#IFNAME}: Speed changed',
                'priority' => 'INFO',
                'description' => 'Interface {#IFNAME} speed has changed',
            ],
        ];
    }

    /**
     * Build graph prototypes for network interface discovery.
     */
    private function buildInterfaceGraphPrototypes(string $templateName): array
    {
        return [
            [
                'name' => 'Interface {#IFNAME}: Traffic',
                'graph_items' => [
                    [
                        'color' => '1A7C11',
                        'item' => [
                            'host' => $templateName,
                            'key' => 'net.if.in[ifHCInOctets.{#SNMPINDEX}]',
                        ],
                    ],
                    [
                        'color' => 'F63100',
                        'drawtype' => 'GRADIENT_LINE',
                        'item' => [
                            'host' => $templateName,
                            'key' => 'net.if.out[ifHCOutOctets.{#SNMPINDEX}]',
                        ],
                    ],
                ],
            ],
            [
                'name' => 'Interface {#IFNAME}: Errors',
                'graph_items' => [
                    [
                        'color' => '1A7C11',
                        'item' => [
                            'host' => $templateName,
                            'key' => 'net.if.in.errors[ifInErrors.{#SNMPINDEX}]',
                        ],
                    ],
                    [
                        'color' => 'F63100',
                        'drawtype' => 'GRADIENT_LINE',
                        'item' => [
                            'host' => $templateName,
                            'key' => 'net.if.out.errors[ifOutErrors.{#SNMPINDEX}]',
                        ],
                    ],
                ],
            ],
        ];
    }

    /**
     * Build a discovery rule from a group of same-type sensors.
     *
     * @param  \Illuminate\Support\Collection<int, Sensor>  $sensors
     */
    private function buildSensorDiscovery(string $sensorType, \Illuminate\Support\Collection $sensors, string $templateName): array
    {
        $firstSensor = $sensors->first();
        $class = $firstSensor->sensor_class;
        $classLabel = ucfirst(str_replace('_', ' ', $class));

        // Determine the base OID by finding the common prefix among sensor OIDs
        $baseOid = $this->findCommonOidPrefix($sensors->pluck('sensor_oid')->toArray());

        $sanitizedType = preg_replace('/[^a-zA-Z0-9_]/', '_', $sensorType);
        $key = "sensor.{$class}.{$sanitizedType}.discovery";

        $rule = [
            'name' => "{$classLabel} discovery: {$sensorType}",
            'type' => 'SNMP_AGENT',
            'snmp_oid' => "discovery[{#SENSOR_INDEX},$baseOid]",
            'key' => $key,
            'delay' => '1h',
            'description' => "Discovers {$classLabel} sensors of type {$sensorType}",
            'item_prototypes' => $this->buildSensorItemPrototypes($firstSensor, $templateName),
            'trigger_prototypes' => $this->buildSensorTriggerPrototypes($firstSensor, $templateName),
            'graph_prototypes' => [],
        ];

        // Add graph prototype for non-state sensors
        if ($class !== 'state') {
            $rule['graph_prototypes'][] = $this->buildSensorGraphPrototype($firstSensor, $templateName);
        }

        return $rule;
    }

    /**
     * Build item prototypes for sensor discovery.
     */
    private function buildSensorItemPrototypes(Sensor $sensor, string $templateName): array
    {
        $class = $sensor->sensor_class;
        $type = preg_replace('/[^a-zA-Z0-9_]/', '_', $sensor->sensor_type);
        $classLabel = ucfirst(str_replace('_', ' ', $class));

        $unitMap = ItemBuilder::UNIT_MAP ?? [];
        $units = $unitMap[$class] ?? '';
        $valueTypeMap = ItemBuilder::VALUE_TYPE_MAP ?? [];
        $valueType = $valueTypeMap[$class] ?? 'FLOAT';

        $prototype = [
            'name' => "{$classLabel} {#SENSOR_INDEX}",
            'type' => 'SNMP_AGENT',
            'snmp_oid' => $sensor->sensor_oid,
            'key' => "sensor.{$class}.{$type}[{#SENSOR_INDEX}]",
            'value_type' => $valueType,
            'units' => $units,
            'delay' => '5m',
            'history' => '7d',
            'trends' => '365d',
            'description' => "Discovered {$classLabel} sensor",
        ];

        if ($sensor->sensor_divisor > 1) {
            $prototype['preprocessing'] = [[
                'type' => 'MULTIPLIER',
                'parameters' => [(string) (1 / $sensor->sensor_divisor)],
            ]];
        } elseif ($sensor->sensor_multiplier > 1) {
            $prototype['preprocessing'] = [[
                'type' => 'MULTIPLIER',
                'parameters' => [(string) $sensor->sensor_multiplier],
            ]];
        }

        if ($class === 'state') {
            $stateIndex = $sensor->stateIndex;
            if ($stateIndex) {
                $prototype['valuemap'] = ['name' => $stateIndex->state_name];
            }
        }

        return [$prototype];
    }

    /**
     * Build trigger prototypes for sensor discovery.
     */
    private function buildSensorTriggerPrototypes(Sensor $sensor, string $templateName): array
    {
        $triggers = [];
        $class = $sensor->sensor_class;
        $type = preg_replace('/[^a-zA-Z0-9_]/', '_', $sensor->sensor_type);
        $classLabel = ucfirst(str_replace('_', ' ', $class));
        $itemKey = "sensor.{$class}.{$type}[{#SENSOR_INDEX}]";

        if ($class === 'state') {
            // For state sensors, trigger on generic critical value (2)
            $triggers[] = [
                'expression' => 'last(/' . $templateName . '/' . $itemKey . ')=2',
                'name' => "{$classLabel} {#SENSOR_INDEX}: Critical state",
                'priority' => 'HIGH',
                'description' => "{$classLabel} sensor {#SENSOR_INDEX} is in critical state",
            ];

            return $triggers;
        }

        // For numeric sensors, use macro-based thresholds when available
        $classUpper = strtoupper($class);

        if ($sensor->sensor_limit !== null) {
            $triggers[] = [
                'expression' => 'last(/' . $templateName . '/' . $itemKey . ')>{$SENSOR_' . $classUpper . '_HIGH}',
                'name' => "{$classLabel} {#SENSOR_INDEX}: High critical value",
                'priority' => 'HIGH',
                'description' => "{$classLabel} sensor value exceeds critical threshold",
            ];
        }

        if ($sensor->sensor_limit_warn !== null) {
            $triggers[] = [
                'expression' => 'last(/' . $templateName . '/' . $itemKey . ')>{$SENSOR_' . $classUpper . '_WARN_HIGH}',
                'name' => "{$classLabel} {#SENSOR_INDEX}: High warning value",
                'priority' => 'WARNING',
                'description' => "{$classLabel} sensor value exceeds warning threshold",
                'dependencies' => [
                    ['name' => "{$classLabel} {#SENSOR_INDEX}: High critical value"],
                ],
            ];
        }

        if ($sensor->sensor_limit_low !== null) {
            $triggers[] = [
                'expression' => 'last(/' . $templateName . '/' . $itemKey . ')<{$SENSOR_' . $classUpper . '_LOW}',
                'name' => "{$classLabel} {#SENSOR_INDEX}: Low critical value",
                'priority' => 'HIGH',
                'description' => "{$classLabel} sensor value is below critical threshold",
            ];
        }

        if ($sensor->sensor_limit_low_warn !== null) {
            $triggers[] = [
                'expression' => 'last(/' . $templateName . '/' . $itemKey . ')<{$SENSOR_' . $classUpper . '_WARN_LOW}',
                'name' => "{$classLabel} {#SENSOR_INDEX}: Low warning value",
                'priority' => 'WARNING',
                'description' => "{$classLabel} sensor value is below warning threshold",
                'dependencies' => [
                    ['name' => "{$classLabel} {#SENSOR_INDEX}: Low critical value"],
                ],
            ];
        }

        return $triggers;
    }

    /**
     * Build a graph prototype for a sensor discovery.
     */
    private function buildSensorGraphPrototype(Sensor $sensor, string $templateName): array
    {
        $class = $sensor->sensor_class;
        $type = preg_replace('/[^a-zA-Z0-9_]/', '_', $sensor->sensor_type);
        $classLabel = ucfirst(str_replace('_', ' ', $class));

        return [
            'name' => "{$classLabel} {#SENSOR_INDEX}",
            'graph_items' => [
                [
                    'color' => '1A7C11',
                    'item' => [
                        'host' => $templateName,
                        'key' => "sensor.{$class}.{$type}[{#SENSOR_INDEX}]",
                    ],
                ],
            ],
        ];
    }

    /**
     * Find the longest common OID prefix among a set of OIDs.
     */
    private function findCommonOidPrefix(array $oids): string
    {
        if (empty($oids)) {
            return '';
        }

        if (count($oids) === 1) {
            // Remove the last segment (instance index)
            return preg_replace('/\.\d+$/', '', $oids[0]) ?: $oids[0];
        }

        $parts = array_map(fn ($oid) => explode('.', ltrim($oid, '.')), $oids);
        $prefix = [];

        $minLen = min(array_map('count', $parts));
        for ($i = 0; $i < $minLen; $i++) {
            $segment = $parts[0][$i];
            foreach ($parts as $p) {
                if ($p[$i] !== $segment) {
                    break 2;
                }
            }
            $prefix[] = $segment;
        }

        return '.' . implode('.', $prefix);
    }
}
