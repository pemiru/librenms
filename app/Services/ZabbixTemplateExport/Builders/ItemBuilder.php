<?php

namespace App\Services\ZabbixTemplateExport\Builders;

use App\Models\Device;
use App\Models\Sensor;

class ItemBuilder
{
    /** Map LibreNMS sensor classes to Zabbix value types */
    public const VALUE_TYPE_MAP = [
        'temperature' => 'FLOAT',
        'humidity' => 'FLOAT',
        'voltage' => 'FLOAT',
        'current' => 'FLOAT',
        'power' => 'FLOAT',
        'power_consumed' => 'FLOAT',
        'power_factor' => 'FLOAT',
        'frequency' => 'FLOAT',
        'fanspeed' => 'UNSIGNED',
        'airflow' => 'FLOAT',
        'pressure' => 'FLOAT',
        'cooling' => 'FLOAT',
        'delay' => 'FLOAT',
        'dbm' => 'FLOAT',
        'signal' => 'FLOAT',
        'signal_loss' => 'FLOAT',
        'snr' => 'FLOAT',
        'bitrate' => 'FLOAT',
        'load' => 'FLOAT',
        'charge' => 'FLOAT',
        'runtime' => 'FLOAT',
        'count' => 'UNSIGNED',
        'percent' => 'FLOAT',
        'loss' => 'FLOAT',
        'ber' => 'FLOAT',
        'eer' => 'FLOAT',
        'chromatic_dispersion' => 'FLOAT',
        'quality_factor' => 'FLOAT',
        'tv_signal' => 'FLOAT',
        'waterflow' => 'FLOAT',
        'state' => 'UNSIGNED',
    ];

    /** Map LibreNMS sensor classes to Zabbix units */
    public const UNIT_MAP = [
        'temperature' => '°C',
        'humidity' => '%',
        'voltage' => 'V',
        'current' => 'A',
        'power' => 'W',
        'power_consumed' => 'kWh',
        'power_factor' => '',
        'frequency' => 'Hz',
        'fanspeed' => 'RPM',
        'airflow' => 'cfm',
        'pressure' => 'kPa',
        'cooling' => 'W',
        'delay' => 's',
        'dbm' => 'dBm',
        'signal' => 'dBm',
        'signal_loss' => 'dB',
        'snr' => 'dB',
        'bitrate' => 'bps',
        'load' => '%',
        'charge' => '%',
        'runtime' => 'Min',
        'count' => '',
        'percent' => '%',
        'loss' => '%',
        'ber' => '',
        'eer' => '',
        'chromatic_dispersion' => 'ps/nm',
        'quality_factor' => '',
        'tv_signal' => 'dBmV',
        'waterflow' => 'l/m',
        'state' => '',
    ];

    /**
     * Build static (non-discovered) SNMP items for the device.
     * These are system-level OIDs and singleton sensors.
     *
     * @return array<int, array<string, mixed>>
     */
    public function buildStaticItems(Device $device, string $templateName): array
    {
        $items = [];

        // Core system items from SNMPv2-MIB
        $items[] = $this->makeItem(
            'System name',
            'SNMP_AGENT',
            '.1.3.6.1.2.1.1.5.0',
            'sysName',
            'TEXT',
            '',
            '1h',
            '0',
            'The administratively-assigned name for this managed node (SNMPv2-MIB::sysName.0)'
        );

        $items[] = $this->makeItem(
            'System description',
            'SNMP_AGENT',
            '.1.3.6.1.2.1.1.1.0',
            'sysDescr',
            'TEXT',
            '',
            '12h',
            '0',
            'A textual description of the entity (SNMPv2-MIB::sysDescr.0)'
        );

        $sysUpTimeItem = $this->makeItem(
            'System uptime',
            'SNMP_AGENT',
            '.1.3.6.1.2.1.1.3.0',
            'sysUpTime',
            'FLOAT',
            'uptime',
            '5m',
            '365d',
            'Time since the network management portion of the system was last re-initialized (SNMPv2-MIB::sysUpTime.0)'
        );
        $sysUpTimeItem['preprocessing'] = [
            ['type' => 'MULTIPLIER', 'parameters' => ['0.01']],
        ];
        $items[] = $sysUpTimeItem;

        $items[] = $this->makeItem(
            'System object ID',
            'SNMP_AGENT',
            '.1.3.6.1.2.1.1.2.0',
            'sysObjectID',
            'TEXT',
            '',
            '12h',
            '0',
            'The vendor\'s authoritative identification (SNMPv2-MIB::sysObjectID.0)'
        );

        $items[] = $this->makeItem(
            'System contact',
            'SNMP_AGENT',
            '.1.3.6.1.2.1.1.4.0',
            'sysContact',
            'TEXT',
            '',
            '12h',
            '0',
            'The contact person for this managed node (SNMPv2-MIB::sysContact.0)'
        );

        $items[] = $this->makeItem(
            'System location',
            'SNMP_AGENT',
            '.1.3.6.1.2.1.1.6.0',
            'sysLocation',
            'TEXT',
            '',
            '12h',
            '0',
            'The physical location of this node (SNMPv2-MIB::sysLocation.0)'
        );

        // ICMP availability items
        $items[] = $this->makeItem(
            'ICMP ping',
            'SIMPLE',
            '',
            'icmpping',
            'UNSIGNED',
            '',
            '1m',
            '365d',
            'Host availability via ICMP ping'
        );

        $items[] = $this->makeItem(
            'ICMP loss',
            'SIMPLE',
            '',
            'icmppingloss',
            'FLOAT',
            '%',
            '1m',
            '365d',
            'ICMP packet loss percentage'
        );

        $items[] = $this->makeItem(
            'ICMP response time',
            'SIMPLE',
            '',
            'icmppingsec',
            'FLOAT',
            's',
            '1m',
            '365d',
            'ICMP response time in seconds'
        );

        // Add singleton sensors (those not suitable for discovery)
        $singletonSensors = $this->getSingletonSensors($device);
        foreach ($singletonSensors as $sensor) {
            $items[] = $this->sensorToItem($sensor);
        }

        return $items;
    }

    /**
     * Convert a Sensor model instance to a Zabbix item definition.
     */
    public function sensorToItem(Sensor $sensor): array
    {
        $class = $sensor->sensor_class;
        $valueType = self::VALUE_TYPE_MAP[$class] ?? 'FLOAT';
        $units = self::UNIT_MAP[$class] ?? '';
        $valueMapName = $class === 'state' ? $this->getStateValueMapName($sensor) : '';

        $item = $this->makeItem(
            $sensor->sensor_descr ?: ucfirst($class) . ' sensor ' . $sensor->sensor_index,
            'SNMP_AGENT',
            $sensor->sensor_oid,
            $this->sensorKey($sensor),
            $valueType,
            $units,
            '5m',
            '365d',
            ucfirst($class) . ' sensor: ' . ($sensor->sensor_descr ?: $sensor->sensor_type)
        );

        if ($sensor->sensor_divisor > 1) {
            $item['preprocessing'] = [[
                'type' => 'MULTIPLIER',
                'parameters' => [(string) (1 / $sensor->sensor_divisor)],
            ]];
        } elseif ($sensor->sensor_multiplier > 1) {
            $item['preprocessing'] = [[
                'type' => 'MULTIPLIER',
                'parameters' => [(string) $sensor->sensor_multiplier],
            ]];
        }

        if ($valueMapName) {
            $item['valuemap'] = ['name' => $valueMapName];
        }

        return $item;
    }

    /**
     * Get sensors that should be static items (not part of a discovery rule).
     * A sensor is "singleton" if there is only one sensor of its type on the device.
     *
     * @return \Illuminate\Support\Collection<int, Sensor>
     */
    public function getSingletonSensors(Device $device): \Illuminate\Support\Collection
    {
        $grouped = $device->sensors->groupBy('sensor_type');

        return $grouped->filter(fn ($sensors) => $sensors->count() === 1)
            ->flatten();
    }

    /**
     * Get sensors that should be part of a discovery rule (multiple instances of same type).
     *
     * @return \Illuminate\Support\Collection<string, \Illuminate\Support\Collection<int, Sensor>>
     */
    public function getDiscoverableSensorGroups(Device $device): \Illuminate\Support\Collection
    {
        return $device->sensors->groupBy('sensor_type')
            ->filter(fn ($sensors) => $sensors->count() > 1);
    }

    /**
     * Create a unique item key for a sensor.
     */
    public function sensorKey(Sensor $sensor): string
    {
        $class = preg_replace('/[^a-zA-Z0-9_]/', '_', $sensor->sensor_class);
        $type = preg_replace('/[^a-zA-Z0-9_]/', '_', $sensor->sensor_type);
        $index = preg_replace('/[^a-zA-Z0-9_.]/', '_', (string) $sensor->sensor_index);

        return "sensor.{$class}.{$type}.{$index}";
    }

    /**
     * Build a standard Zabbix item array.
     */
    private function makeItem(
        string $name,
        string $type,
        string $snmpOid,
        string $key,
        string $valueType,
        string $units,
        string $delay,
        string $trends,
        string $description,
    ): array {
        return [
            'name' => $name,
            'type' => $type,
            'snmp_oid' => $snmpOid,
            'key' => $key,
            'value_type' => $valueType,
            'units' => $units,
            'delay' => $delay,
            'history' => '7d',
            'trends' => $trends,
            'description' => $description,
        ];
    }

    /**
     * Get the value map name for a state sensor.
     */
    private function getStateValueMapName(Sensor $sensor): string
    {
        $stateIndex = $sensor->stateIndex;

        return $stateIndex ? $stateIndex->state_name : '';
    }
}
