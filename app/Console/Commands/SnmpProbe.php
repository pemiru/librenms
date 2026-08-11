<?php

/**
 * SnmpProbe.php
 *
 * Standalone SNMP discovery probe – no database required.
 * Runs all discovery modules against a target host and prints a human-readable
 * report of everything LibreNMS would discover: device identity, OS, MIBs,
 * sensors, mempools, processors, ports and physical inventory with numeric OIDs.
 *
 * Usage examples:
 *   # SNMPv2c
 *   ./lnms snmp:probe router.example.com --v2c -c public
 *
 *   # SNMPv3
 *   ./lnms snmp:probe router.example.com --v3 \
 *       -u admin -a SHA -A authpass -x AES -X privpass
 *
 *   # Passwords with special shell characters (& $ ! etc.):
 *   #   Option 1 — single-quote the value so the shell treats it literally:
 *   ./lnms snmp:probe router.example.com --v3 \
 *       -u admin -a SHA -A 'p@ss&word' -x AES -X 'pr1v&pass'
 *
 *   #   Option 2 — pass via environment variables (immune to all shell quoting):
 *   SNMP_AUTH_PASS='p@ss&word' SNMP_PRIV_PASS='pr1v&pass' \
 *   ./lnms snmp:probe router.example.com --v3 -u admin -a SHA -x AES
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * @link       https://www.librenms.org
 *
 * @copyright  2025 LibreNMS Contributors
 */

namespace App\Console\Commands;

use App\Console\LnmsCommand;
use App\Events\SnmpQueryExecuted;
use App\Facades\LibrenmsConfig;
use App\Models\Device;
use DeviceCache;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Event;
use LibreNMS\OS;
use LibreNMS\Polling\ConnectivityHelper;
use LibreNMS\Polling\ModuleStatus;
use LibreNMS\Util\Module;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputOption;

class SnmpProbe extends LnmsCommand
{
    protected $name = 'snmp:probe';

    /** @var array<string, array{oids: string[], mib: string}> Recorded SNMP queries */
    private array $snmpQueries = [];

    public function __construct()
    {
        parent::__construct();

        $this->addArgument('hostname', InputArgument::REQUIRED, 'Target hostname or IP address');

        $this->addOption('v1', '1', InputOption::VALUE_NONE, 'Use SNMPv1');
        $this->addOption('v2c', '2', InputOption::VALUE_NONE, 'Use SNMPv2c (default)');
        $this->addOption('v3', '3', InputOption::VALUE_NONE, 'Use SNMPv3');

        $this->addOption('community', 'c', InputOption::VALUE_REQUIRED, 'SNMPv1/v2c community string', 'public');
        $this->addOption('port', 'r', InputOption::VALUE_REQUIRED, 'SNMP UDP port', '161');
        $this->addOption('transport', 't', InputOption::VALUE_REQUIRED, 'Transport (udp, udp6, tcp, tcp6)', 'udp');

        // SNMPv3 options
        $this->addOption('security-name', 'u', InputOption::VALUE_REQUIRED, 'SNMPv3 security/user name', 'root');
        $this->addOption('auth-password', 'A', InputOption::VALUE_REQUIRED, 'SNMPv3 authentication password (or set SNMP_AUTH_PASS env var)');
        $this->addOption('auth-protocol', 'a', InputOption::VALUE_REQUIRED, 'SNMPv3 auth protocol (MD5, SHA, SHA-256, SHA-512)', 'MD5');
        $this->addOption('privacy-password', 'X', InputOption::VALUE_REQUIRED, 'SNMPv3 privacy/encryption password (or set SNMP_PRIV_PASS env var)');
        $this->addOption('privacy-protocol', 'x', InputOption::VALUE_REQUIRED, 'SNMPv3 privacy protocol (AES, DES, AES-256)', 'AES');
    }

    public function handle(): int
    {
        // ----------------------------------------------------------------
        // 1. Switch to an ephemeral in-memory SQLite database so no MySQL
        //    (or any other persistent DB) is required.
        // ----------------------------------------------------------------
        if (! in_array('sqlite', \PDO::getAvailableDrivers())) {
            $this->error(
                'The PHP SQLite extension (pdo_sqlite) is not installed. ' .
                'snmp:probe uses an in-memory SQLite database and requires it. ' .
                'Install it with: apt install php' . PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION . '-sqlite3  (or the equivalent for your OS/PHP version)'
            );

            return 1;
        }

        config(['database.default' => 'testing_memory']);
        $this->line('<fg=yellow>Setting up in-memory database …</>');
        Artisan::call('migrate', ['--force' => true, '--quiet' => true]);
        $this->line('<fg=green>Done.</>');
        $this->newLine();

        // ----------------------------------------------------------------
        // 2. Build the Device model (in-memory only).
        // ----------------------------------------------------------------
        // Environment-variable fallback lets users pass credentials with
        // special characters (& $ ! ' etc.) without any shell-quoting issues:
        //   SNMP_AUTH_PASS='p@ss&word' SNMP_PRIV_PASS='pr1v&pass' ./lnms snmp:probe …
        $auth = $this->option('auth-password') ?? getenv('SNMP_AUTH_PASS') ?: null;
        $priv = $this->option('privacy-password') ?? getenv('SNMP_PRIV_PASS') ?: null;

        $snmpver = 'v2c';
        if ($this->option('v3')) {
            $snmpver = 'v3';
        } elseif ($this->option('v1')) {
            $snmpver = 'v1';
        }

        $authlevel = 'noAuthNoPriv';
        if ($snmpver === 'v3') {
            if ($auth && $priv) {
                $authlevel = 'authPriv';
            } elseif ($auth) {
                $authlevel = 'authNoPriv';
            }
        }

        $device = Device::create([
            'hostname'     => $this->argument('hostname'),
            'snmpver'      => $snmpver,
            'port'         => (int) $this->option('port'),
            'transport'    => $this->option('transport'),
            'community'    => $this->option('community'),
            'authlevel'    => $authlevel,
            'authname'     => $this->option('security-name'),
            'authpass'     => $auth,
            'authalgo'     => $this->option('auth-protocol'),
            'cryptopass'   => $priv,
            'cryptoalgo'   => $this->option('privacy-protocol') ?: '',
            'status'       => 1,
            'status_reason' => '',
            'snmp_disable' => false,
            'disabled'     => false,
        ]);

        // Put the device in the cache directly so DeviceCache::getPrimary() and
        // SnmpQuery can find it without an extra DB round-trip.
        DeviceCache::fake($device);
        DeviceCache::setPrimary($device->device_id);

        // ----------------------------------------------------------------
        // 3. Wire up SNMP query recording so we can list queried OIDs.
        // ----------------------------------------------------------------
        Event::listen(SnmpQueryExecuted::class, function (SnmpQueryExecuted $event): void {
            $this->snmpQueries[] = [
                'oids'   => $event->oids,
                'method' => $event->method,
                'mibs'   => $event->mibs,
                'mibDir' => $event->mibDir,
            ];
        });

        // ----------------------------------------------------------------
        // 4. Run legacy discovery bootstrapping (functions, constants …).
        // ----------------------------------------------------------------
        include_once base_path('includes/functions.php');
        include_once base_path('includes/common.php');
        include_once base_path('includes/discovery/functions.inc.php');
        include_once base_path('includes/snmp.inc.php');

        // ----------------------------------------------------------------
        // 5. Run discovery modules.
        // ----------------------------------------------------------------
        $this->line('<fg=yellow>Running discovery modules …</>');

        $deviceArray = $device->toArray();
        // 'os' is null until the core module runs; default to 'generic' so
        // OS::make() does not trigger an "Undefined array key" PHP warning.
        $deviceArray['os'] ??= 'generic';
        // 'port_association_mode' must be present (falsy = use default) so that
        // the ports discovery module does not throw an "Undefined array key" warning.
        $deviceArray['port_association_mode'] ??= 0;
        $os           = OS::make($deviceArray);
        $connectivity = new ConnectivityHelper($device);

        $snmpFailed = false;

        $modules = [
            'core',
            'os',
            'sensors',
            'mempools',
            'processors',
            'ports',
            'entity-physical',
            'hr-device',
            'ipv4-addresses',
            'ipv6-addresses',
            'discovery-protocols',
        ];

        foreach ($modules as $moduleName) {
            try {
                $instance = Module::fromName($moduleName);
                $status   = new ModuleStatus(true);

                if (! $instance->shouldDiscover($os, $status, $connectivity)) {
                    continue;
                }

                $this->line("  <fg=cyan>[$moduleName]</> discovering …");
                $instance->discover($os);

                // After core/os the OS may have changed; rebuild deviceArray from the
                // in-memory DeviceCache model so we don't lose unsaved Core fields
                // (Core fills sysObjectID/sysDescr/sysName in-memory but does not save
                // them to the DB during discover, so $device->refresh() would wipe them).
                if (in_array($moduleName, ['core', 'os'])) {
                    $device    = DeviceCache::getPrimary();
                    $deviceArray = $device->toArray();
                    $deviceArray['os'] ??= 'generic';
                    $deviceArray['port_association_mode'] ??= 0;
                    if ($osGroup = LibrenmsConfig::get("os.{$device->os}.group")) {
                        $deviceArray['os_group'] = $osGroup;
                    }
                    $os = OS::make($deviceArray);

                    // Check SNMP availability after core module.
                    if ($moduleName === 'core' && $device->sysObjectID === null && $device->sysDescr === null) {
                        $snmpFailed = true;
                        $this->warn('SNMP query returned no data. Check that the host is reachable and that the community / credentials are correct.');
                    }
                }
            } catch (\Throwable $e) {
                $this->line("  <fg=red>[$moduleName] error:</> " . $e->getMessage());
            }
        }

        if ($snmpFailed) {
            $this->newLine();
            $this->error('Discovery completed with no SNMP data. The report below will be empty.');
        }

        $this->newLine();

        // ----------------------------------------------------------------
        // 6. Use the in-memory DeviceCache model for the report so that
        //    fields populated by Core (but not yet persisted) are visible.
        // ----------------------------------------------------------------
        $device = DeviceCache::getPrimary();
        $this->printReport($device);

        return 0;
    }

    // ====================================================================
    // Report rendering
    // ====================================================================

    private function printReport(Device $device): void
    {
        $sep = str_repeat('─', 72);
        $this->line("<fg=bright-white>$sep</>");

        $this->sectionHeader('SNMP Discovery Report — ' . $device->hostname);
        $this->line("<fg=bright-white>$sep</>");
        $this->newLine();

        $this->printDeviceIdentity($device);
        $this->printOsInfo($device);
        $this->printMibInfo($device);
        $this->printSensors($device);
        $this->printMempools($device);
        $this->printProcessors($device);
        $this->printPorts($device);
        $this->printEntityPhysical($device);
        $this->printQueriedOids();

        $this->line("<fg=bright-white>$sep</>");
        $this->line('<fg=green>Discovery complete.</>');
    }

    private function printDeviceIdentity(Device $device): void
    {
        $this->sectionHeader('Device Identity');

        $rows = [
            ['Hostname',      $device->hostname],
            ['sysName',       $device->sysName       ?: '(not set)'],
            ['sysObjectID',   $device->sysObjectID    ?: '(unknown)'],
            ['sysDescr',      $this->truncate((string) $device->sysDescr, 120)],
            ['sysContact',    $this->truncate((string) $device->sysContact, 80)],
            ['SNMP Engine ID', $device->snmpEngineID  ?: '(not retrieved)'],
            ['IP',            $device->ip             ?: '(not resolved)'],
        ];

        $this->printKeyValueTable($rows);
    }

    private function printOsInfo(Device $device): void
    {
        $this->sectionHeader('Detected OS / Device Classification');

        $os     = $device->os    ?: 'generic';
        $osText = LibrenmsConfig::getOsSetting($os, 'text', $os);
        $group  = LibrenmsConfig::getOsSetting($os, 'group', '');

        $rows = [
            ['OS key',     $os],
            ['OS name',    $osText],
            ['OS group',   $group ?: '(none)'],
            ['Type',       $device->type       ?: '(unknown)'],
            ['Hardware',   $device->hardware   ?: '(not detected)'],
            ['Version',    $device->version    ?: '(not detected)'],
            ['Features',   $this->truncate((string) $device->features, 80)],
            ['Serial',     $device->serial     ?: '(not detected)'],
            ['Icon',       $device->icon       ?: '(default)'],
        ];

        $this->printKeyValueTable($rows);
    }

    private function printMibInfo(Device $device): void
    {
        $this->sectionHeader('MIBs & Extends');

        $os      = $device->os ?: 'generic';
        $mibDir  = LibrenmsConfig::getOsSetting($os, 'mib_dir', '');
        $extends = LibrenmsConfig::getOsSetting($os, 'extends', []);
        $poller  = LibrenmsConfig::getOsSetting($os, 'poller_modules', []);
        $disc    = LibrenmsConfig::getOsSetting($os, 'discovery_modules', []);

        $rows = [
            ['MIB directory', $mibDir ?: '(default only)'],
            ['Extends',
                $extends ? implode(', ', (array) $extends) : '(none)'],
            ['Custom discovery modules',
                $disc   ? implode(', ', array_keys(array_filter((array) $disc))) : '(none)'],
            ['Custom poller modules',
                $poller ? implode(', ', array_keys(array_filter((array) $poller))) : '(none)'],
        ];

        $this->printKeyValueTable($rows);
    }

    private function printSensors(Device $device): void
    {
        $sensors = $device->sensors()->get();
        if ($sensors->isEmpty()) {
            return;
        }

        $this->sectionHeader("Sensors ({$sensors->count()})");

        $byClass = $sensors->groupBy('sensor_class');

        foreach ($byClass as $class => $items) {
            $this->line("  <fg=cyan;options=bold>$class</>:");
            foreach ($items as $sensor) {
                $this->line(sprintf(
                    '    <fg=bright-blue>%-50s</> oid: <fg=yellow>%s</>  type: %s  current: %s',
                    $sensor->sensor_descr,
                    $sensor->sensor_oid,
                    $sensor->sensor_type,
                    $sensor->sensor_current !== null ? $sensor->sensor_current : 'n/a'
                ));
            }
        }

        $this->newLine();
    }

    private function printMempools(Device $device): void
    {
        $pools = $device->mempools()->get();
        if ($pools->isEmpty()) {
            return;
        }

        $this->sectionHeader("Memory Pools ({$pools->count()})");

        foreach ($pools as $pool) {
            $this->line(sprintf(
                '  <fg=bright-blue>%-40s</>  type: %-20s  class: %s',
                $pool->mempool_descr,
                $pool->mempool_type,
                $pool->mempool_class
            ));
        }

        $this->newLine();
    }

    private function printProcessors(Device $device): void
    {
        $procs = $device->processors()->get();
        if ($procs->isEmpty()) {
            return;
        }

        $this->sectionHeader("Processors ({$procs->count()})");

        foreach ($procs as $proc) {
            $this->line(sprintf(
                '  <fg=bright-blue>%-50s</>  oid: <fg=yellow>%s</>  type: %s',
                $proc->processor_descr,
                $proc->processor_oid ?? '(no OID)',
                $proc->processor_type ?? 'unknown'
            ));
        }

        $this->newLine();
    }

    private function printPorts(Device $device): void
    {
        $ports = $device->ports()->get();
        if ($ports->isEmpty()) {
            return;
        }

        $this->sectionHeader("Ports / Interfaces ({$ports->count()})");

        $headers = ['ifIndex', 'ifName', 'ifDescr', 'ifType', 'Speed (bps)', 'Admin', 'Oper'];
        $rows    = [];

        foreach ($ports as $port) {
            $rows[] = [
                $port->ifIndex,
                $port->ifName      ?? '',
                $this->truncate((string) $port->ifDescr, 30),
                $port->ifType      ?? '',
                $port->ifSpeed     ? number_format($port->ifSpeed) : '',
                $port->ifAdminStatus?->value ?? '',
                $port->ifOperStatus?->value  ?? '',
            ];
        }

        $this->table($headers, $rows);
        $this->newLine();
    }

    private function printEntityPhysical(Device $device): void
    {
        $entities = $device->entityPhysical()->get();
        if ($entities->isEmpty()) {
            return;
        }

        $this->sectionHeader("Physical Inventory ({$entities->count()} entries)");

        $headers = ['Index', 'Class', 'Name', 'Description', 'Model', 'Serial', 'Firmware'];
        $rows    = [];

        foreach ($entities as $ent) {
            $rows[] = [
                $ent->entPhysicalIndex,
                $ent->entPhysicalClass     ?? '',
                $this->truncate((string) $ent->entPhysicalName, 30),
                $this->truncate((string) $ent->entPhysicalDescr, 30),
                $ent->entPhysicalModelName  ?? '',
                $ent->entPhysicalSerialNum  ?? '',
                $ent->entPhysicalFirmwareRev ?? '',
            ];
        }

        $this->table($headers, $rows);
        $this->newLine();
    }

    private function printQueriedOids(): void
    {
        if (empty($this->snmpQueries)) {
            return;
        }

        $this->sectionHeader('SNMP Queries Executed During Discovery');

        $seen = [];
        foreach ($this->snmpQueries as $q) {
            foreach ((array) $q['oids'] as $oid) {
                $oidStr = (string) $oid;
                if (isset($seen[$oidStr])) {
                    continue;
                }
                $seen[$oidStr] = true;
                $this->line(sprintf(
                    '  [<fg=cyan>%s</>] <fg=yellow>%s</>',
                    $q['method'] ?? 'snmp',
                    $oidStr
                ));
            }
        }

        $this->newLine();
    }

    // ====================================================================
    // Helpers
    // ====================================================================

    private function sectionHeader(string $title): void
    {
        $this->newLine();
        $this->line("<fg=bright-white;options=bold>## $title</>");
        $this->line(str_repeat('─', min(strlen($title) + 3, 72)));
    }

    /** @param array<array{0:string, 1:string}> $rows */
    private function printKeyValueTable(array $rows): void
    {
        $maxKey = max(array_map(fn ($r) => strlen($r[0]), $rows));

        foreach ($rows as [$key, $value]) {
            $pad = str_repeat(' ', $maxKey - strlen($key));
            $this->line("  <fg=cyan>$key</>$pad  $value");
        }

        $this->newLine();
    }

    private function truncate(string $str, int $max): string
    {
        $str = trim(preg_replace('/\s+/', ' ', $str));

        return strlen($str) > $max ? substr($str, 0, $max - 1) . '…' : $str;
    }
}
