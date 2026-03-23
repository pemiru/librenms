<?php

namespace LibreNMS\Tests\Feature\Commands;

use App\Models\Device;
use App\Models\Port;
use App\Models\Sensor;
use App\Services\ZabbixTemplateExport\Builders\DiscoveryRuleBuilder;
use App\Services\ZabbixTemplateExport\Builders\GraphBuilder;
use App\Services\ZabbixTemplateExport\Builders\ItemBuilder;
use App\Services\ZabbixTemplateExport\Builders\MacroBuilder;
use App\Services\ZabbixTemplateExport\Builders\TriggerBuilder;
use App\Services\ZabbixTemplateExport\Builders\ValueMapBuilder;
use App\Services\ZabbixTemplateExport\ZabbixTemplateExporter;
use LibreNMS\Tests\InMemoryDbTestCase;

class ExportZabbixTemplateTest extends InMemoryDbTestCase
{

    private function createDeviceWithSensors(): Device
    {
        $device = Device::factory()->create([
            'hostname' => 'test-switch.example.com',
            'os' => 'linux',
            'hardware' => 'TestHW',
            'sysObjectID' => '.1.3.6.1.4.1.8072.3.2.10',
        ]);

        // Create multiple temperature sensors (same type -> discoverable)
        $device->sensors()->create([
            'sensor_class' => 'temperature',
            'sensor_type' => 'linux-temp',
            'sensor_index' => '0',
            'sensor_oid' => '.1.3.6.1.4.1.2021.13.16.2.1.3.1',
            'sensor_descr' => 'CPU Temperature',
            'sensor_current' => 45,
            'sensor_limit' => 85,
            'sensor_limit_warn' => 70,
            'sensor_limit_low' => 5,
            'sensor_limit_low_warn' => 10,
            'sensor_divisor' => 1000,
            'sensor_multiplier' => 1,
        ]);

        $device->sensors()->create([
            'sensor_class' => 'temperature',
            'sensor_type' => 'linux-temp',
            'sensor_index' => '1',
            'sensor_oid' => '.1.3.6.1.4.1.2021.13.16.2.1.3.2',
            'sensor_descr' => 'Board Temperature',
            'sensor_current' => 35,
            'sensor_limit' => 80,
            'sensor_limit_warn' => 65,
            'sensor_limit_low' => 0,
            'sensor_limit_low_warn' => 5,
            'sensor_divisor' => 1000,
            'sensor_multiplier' => 1,
        ]);

        // Create a singleton voltage sensor
        $device->sensors()->create([
            'sensor_class' => 'voltage',
            'sensor_type' => 'ups-voltage',
            'sensor_index' => '0',
            'sensor_oid' => '.1.3.6.1.4.1.318.1.1.1.3.2.1.0',
            'sensor_descr' => 'Input Voltage',
            'sensor_current' => 230,
            'sensor_limit' => 260,
            'sensor_limit_warn' => 250,
            'sensor_limit_low' => 180,
            'sensor_limit_low_warn' => 190,
            'sensor_divisor' => 1,
            'sensor_multiplier' => 1,
        ]);

        // Create a port
        $device->ports()->save(Port::factory()->make([
            'ifIndex' => 1,
            'ifName' => 'eth0',
            'ifDescr' => 'Ethernet0',
            'ifSpeed' => 1000000000,
            'ifAdminStatus' => 'up',
            'ifOperStatus' => 'up',
        ]));

        $device->load(['sensors.stateIndex.translations', 'ports']);

        return $device;
    }

    public function testExportProducesValidXml(): void
    {
        $device = $this->createDeviceWithSensors();
        $exporter = new ZabbixTemplateExporter;
        $xml = $exporter->export($device);

        $this->assertNotEmpty($xml);

        // Validate well-formed XML
        $dom = new \DOMDocument;
        $result = $dom->loadXML($xml);
        $this->assertTrue($result, 'Generated XML is not well-formed');
    }

    public function testExportContainsTemplateStructure(): void
    {
        $device = $this->createDeviceWithSensors();
        $exporter = new ZabbixTemplateExporter;
        $xml = $exporter->export($device);

        $this->assertStringContainsString('<zabbix_export>', $xml);
        $this->assertStringContainsString('<version>7.0</version>', $xml);
        $this->assertStringContainsString('<templates>', $xml);
        $this->assertStringContainsString('<template>', $xml);
        $this->assertStringContainsString('LibreNMS Export: Linux TestHW', $xml);
    }

    public function testExportContainsCoreSnmpItems(): void
    {
        $device = $this->createDeviceWithSensors();
        $exporter = new ZabbixTemplateExporter;
        $xml = $exporter->export($device);

        // Verify system OIDs are numeric (not MIB strings)
        $this->assertStringContainsString('.1.3.6.1.2.1.1.5.0', $xml); // sysName
        $this->assertStringContainsString('.1.3.6.1.2.1.1.1.0', $xml); // sysDescr
        $this->assertStringContainsString('.1.3.6.1.2.1.1.3.0', $xml); // sysUpTime
        $this->assertStringContainsString('.1.3.6.1.2.1.1.2.0', $xml); // sysObjectID
        $this->assertStringContainsString('<key>sysName</key>', $xml);
        $this->assertStringContainsString('<key>sysUpTime</key>', $xml);
    }

    public function testExportContainsIcmpItems(): void
    {
        $device = $this->createDeviceWithSensors();
        $exporter = new ZabbixTemplateExporter;
        $xml = $exporter->export($device);

        $this->assertStringContainsString('<key>icmpping</key>', $xml);
        $this->assertStringContainsString('<key>icmppingloss</key>', $xml);
        $this->assertStringContainsString('<key>icmppingsec</key>', $xml);
    }

    public function testExportContainsInterfaceDiscovery(): void
    {
        $device = $this->createDeviceWithSensors();
        $exporter = new ZabbixTemplateExporter;
        $xml = $exporter->export($device);

        $this->assertStringContainsString('<discovery_rules>', $xml);
        $this->assertStringContainsString('Network interface discovery', $xml);
        $this->assertStringContainsString('net.if.discovery', $xml);
        $this->assertStringContainsString('{#IFNAME}', $xml);
        $this->assertStringContainsString('{#SNMPINDEX}', $xml);
        // Interface item prototypes with numeric OIDs
        $this->assertStringContainsString('.1.3.6.1.2.1.31.1.1.1.6.{#SNMPINDEX}', $xml); // ifHCInOctets
        $this->assertStringContainsString('.1.3.6.1.2.1.31.1.1.1.10.{#SNMPINDEX}', $xml); // ifHCOutOctets
    }

    public function testExportContainsSensorDiscoveryRules(): void
    {
        $device = $this->createDeviceWithSensors();
        $exporter = new ZabbixTemplateExporter;
        $xml = $exporter->export($device);

        // Temperature sensors (2 of same type) should create a discovery rule
        $this->assertStringContainsString('Temperature discovery: linux-temp', $xml);
        $this->assertStringContainsString('{#SENSOR_INDEX}', $xml);
    }

    public function testExportContainsSingletonSensorAsStaticItem(): void
    {
        $device = $this->createDeviceWithSensors();
        $exporter = new ZabbixTemplateExporter;
        $xml = $exporter->export($device);

        // The voltage sensor (only 1 of its type) should be a static item
        $this->assertStringContainsString('Input Voltage', $xml);
        $this->assertStringContainsString('.1.3.6.1.4.1.318.1.1.1.3.2.1.0', $xml);
    }

    public function testExportContainsMacros(): void
    {
        $device = $this->createDeviceWithSensors();
        $exporter = new ZabbixTemplateExporter;
        $xml = $exporter->export($device);

        $this->assertStringContainsString('<macros>', $xml);
        $this->assertStringContainsString('{$SNMP_COMMUNITY}', $xml);
        $this->assertStringContainsString('{$SNMP_PORT}', $xml);
        $this->assertStringContainsString('{$SNMP_TIMEOUT}', $xml);
        $this->assertStringContainsString('{$IF_UTIL_MAX}', $xml);
        $this->assertStringContainsString('{$UPTIME_LOW}', $xml);
        // Sensor threshold macros
        $this->assertStringContainsString('{$SENSOR_TEMPERATURE_HIGH}', $xml);
        $this->assertStringContainsString('{$SENSOR_TEMPERATURE_LOW}', $xml);
    }

    public function testExportContainsTriggers(): void
    {
        $device = $this->createDeviceWithSensors();
        $exporter = new ZabbixTemplateExporter;
        $xml = $exporter->export($device);

        $this->assertStringContainsString('<triggers>', $xml);
        $this->assertStringContainsString('Unavailable by ICMP ping', $xml);
        $this->assertStringContainsString('Device has been restarted', $xml);
        $this->assertStringContainsString('System name has changed', $xml);
    }

    public function testExportContainsGraphs(): void
    {
        $device = $this->createDeviceWithSensors();
        $exporter = new ZabbixTemplateExporter;
        $xml = $exporter->export($device);

        $this->assertStringContainsString('<graphs>', $xml);
        $this->assertStringContainsString('ICMP response time', $xml);
        $this->assertStringContainsString('ICMP packet loss', $xml);
    }

    public function testExportContainsValueMaps(): void
    {
        $device = $this->createDeviceWithSensors();
        $exporter = new ZabbixTemplateExporter;
        $xml = $exporter->export($device);

        $this->assertStringContainsString('<valuemaps>', $xml);
        $this->assertStringContainsString('IF-MIB::ifOperStatus', $xml);
        $this->assertStringContainsString('IF-MIB::ifAdminStatus', $xml);
        $this->assertStringContainsString('<newvalue>up</newvalue>', $xml);
        $this->assertStringContainsString('<newvalue>down</newvalue>', $xml);
    }

    public function testExportContainsInterfaceTriggerPrototypes(): void
    {
        $device = $this->createDeviceWithSensors();
        $exporter = new ZabbixTemplateExporter;
        $xml = $exporter->export($device);

        $this->assertStringContainsString('<trigger_prototypes>', $xml);
        $this->assertStringContainsString('Interface {#IFNAME}: Link down', $xml);
    }

    public function testExportContainsInterfaceGraphPrototypes(): void
    {
        $device = $this->createDeviceWithSensors();
        $exporter = new ZabbixTemplateExporter;
        $xml = $exporter->export($device);

        $this->assertStringContainsString('<graph_prototypes>', $xml);
        $this->assertStringContainsString('Interface {#IFNAME}: Traffic', $xml);
        $this->assertStringContainsString('Interface {#IFNAME}: Errors', $xml);
    }

    public function testExportContainsPreprocessing(): void
    {
        $device = $this->createDeviceWithSensors();
        $exporter = new ZabbixTemplateExporter;
        $xml = $exporter->export($device);

        $this->assertStringContainsString('<preprocessing>', $xml);
        $this->assertStringContainsString('CHANGE_PER_SECOND', $xml);
        $this->assertStringContainsString('MULTIPLIER', $xml);
    }

    public function testCommandWritesToFile(): void
    {
        $device = $this->createDeviceWithSensors();
        $outputPath = sys_get_temp_dir() . '/zabbix_template_test_' . uniqid() . '.xml';

        try {
            $this->artisan('export:zabbix-template', [
                'device spec' => $device->hostname,
                '--output' => $outputPath,
            ])->assertExitCode(0);

            $this->assertFileExists($outputPath);
            $content = file_get_contents($outputPath);
            $this->assertStringContainsString('<zabbix_export>', $content);
        } finally {
            @unlink($outputPath);
        }
    }

    public function testCommandFailsForNonexistentDevice(): void
    {
        $this->artisan('export:zabbix-template', [
            'device spec' => 'nonexistent-device-xyz.example.com',
        ])->assertExitCode(1);
    }

    public function testItemBuilderSingletonDetection(): void
    {
        $device = $this->createDeviceWithSensors();
        $builder = new ItemBuilder;

        $singletons = $builder->getSingletonSensors($device);
        $this->assertCount(1, $singletons);
        $this->assertEquals('voltage', $singletons->first()->sensor_class);

        $groups = $builder->getDiscoverableSensorGroups($device);
        $this->assertCount(1, $groups);
        $this->assertTrue($groups->has('linux-temp'));
        $this->assertCount(2, $groups['linux-temp']);
    }

    public function testMacroBuilderGeneratesThresholdMacros(): void
    {
        $device = $this->createDeviceWithSensors();
        $builder = new MacroBuilder;
        $macros = $builder->build($device);

        $macroNames = array_column($macros, 'macro');

        $this->assertContains('{$SNMP_COMMUNITY}', $macroNames);
        $this->assertContains('{$IF_UTIL_MAX}', $macroNames);
        $this->assertContains('{$SENSOR_TEMPERATURE_HIGH}', $macroNames);
        $this->assertContains('{$SENSOR_VOLTAGE_HIGH}', $macroNames);
    }

    public function testValueMapBuilderIncludesIfMibMaps(): void
    {
        $device = $this->createDeviceWithSensors();
        $builder = new ValueMapBuilder;
        $maps = $builder->build($device);

        $mapNames = array_column($maps, 'name');
        $this->assertContains('IF-MIB::ifOperStatus', $mapNames);
        $this->assertContains('IF-MIB::ifAdminStatus', $mapNames);
        $this->assertContains('IF-MIB::ifType', $mapNames);
    }

    public function testDiscoveryRuleBuilderCreatesInterfaceDiscovery(): void
    {
        $device = $this->createDeviceWithSensors();
        $itemBuilder = new ItemBuilder;
        $builder = new DiscoveryRuleBuilder($itemBuilder);
        $templateName = 'Test Template';
        $rules = $builder->build($device, $templateName);

        $ruleNames = array_column($rules, 'name');
        $this->assertContains('Network interface discovery', $ruleNames);

        // Find the interface rule
        $ifRule = collect($rules)->firstWhere('name', 'Network interface discovery');
        $this->assertNotNull($ifRule);
        $this->assertEquals('net.if.discovery', $ifRule['key']);
        $this->assertNotEmpty($ifRule['item_prototypes']);
        $this->assertNotEmpty($ifRule['trigger_prototypes']);
        $this->assertNotEmpty($ifRule['graph_prototypes']);
    }

    public function testTriggerBuilderCreatesCoreTriggers(): void
    {
        $device = $this->createDeviceWithSensors();
        $builder = new TriggerBuilder;
        $templateName = 'Test Template';
        $triggers = $builder->build($device, $templateName);

        $triggerNames = array_column($triggers, 'name');
        $this->assertContains('Unavailable by ICMP ping', $triggerNames);
        $this->assertContains('Device has been restarted', $triggerNames);
        $this->assertContains('System name has changed', $triggerNames);
    }

    public function testGraphBuilderCreatesIcmpGraphs(): void
    {
        $device = $this->createDeviceWithSensors();
        $builder = new GraphBuilder;
        $templateName = 'Test Template';
        $graphs = $builder->build($device, $templateName);

        $graphNames = array_column($graphs, 'name');
        $this->assertContains('ICMP response time', $graphNames);
        $this->assertContains('ICMP packet loss', $graphNames);
    }

    public function testTemplateNameSanitization(): void
    {
        $device = Device::factory()->create([
            'os' => 'test/os<>',
            'hardware' => 'some"hardware',
        ]);

        $exporter = new ZabbixTemplateExporter;
        $name = $exporter->templateName($device);

        // Should not contain invalid XML characters
        $this->assertStringNotContainsString('<', $name);
        $this->assertStringNotContainsString('>', $name);
        $this->assertStringNotContainsString('"', $name);
        $this->assertStringNotContainsString('/', $name);
    }

    public function testExportDeviceWithNoSensorsOrPorts(): void
    {
        $device = Device::factory()->create([
            'os' => 'generic',
            'hardware' => '',
        ]);
        $device->load(['sensors.stateIndex.translations', 'ports']);

        $exporter = new ZabbixTemplateExporter;
        $xml = $exporter->export($device);

        // Should still produce valid XML with core items
        $dom = new \DOMDocument;
        $result = $dom->loadXML($xml);
        $this->assertTrue($result, 'Generated XML for empty device is not well-formed');
        $this->assertStringContainsString('<items>', $xml);
        $this->assertStringContainsString('sysName', $xml);
    }

    public function testSensorDivisorCreatesPreprocessing(): void
    {
        $device = $this->createDeviceWithSensors();
        $builder = new ItemBuilder;

        // Get temperature sensor with divisor of 1000
        $sensor = $device->sensors->first(fn ($s) => $s->sensor_class === 'temperature');
        $item = $builder->sensorToItem($sensor);

        $this->assertArrayHasKey('preprocessing', $item);
        $this->assertEquals('MULTIPLIER', $item['preprocessing'][0]['type']);
        $this->assertEquals('0.001', $item['preprocessing'][0]['parameters'][0]);
    }
}
