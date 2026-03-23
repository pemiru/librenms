<?php

namespace App\Console\Commands;

use App\Console\LnmsCommand;
use App\Models\Device;
use App\Services\ZabbixTemplateExport\ZabbixTemplateExporter;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputOption;

class ExportZabbixTemplate extends LnmsCommand
{
    protected $name = 'export:zabbix-template';

    public function __construct()
    {
        parent::__construct();

        $this->addArgument('device spec', InputArgument::REQUIRED, trans('commands.export:zabbix-template.arguments.device spec'));
        $this->addOption('output', 'o', InputOption::VALUE_REQUIRED, trans('commands.export:zabbix-template.options.output'));
    }

    public function handle(ZabbixTemplateExporter $exporter): int
    {
        $deviceSpec = $this->argument('device spec');
        $device = Device::whereDeviceSpec($deviceSpec)->first();

        if (! $device) {
            $this->error(trans('commands.export:zabbix-template.messages.not_found', ['spec' => $deviceSpec]));

            return 1;
        }

        $xml = $exporter->export($device);

        $outputPath = $this->option('output');
        if ($outputPath) {
            $bytes = file_put_contents($outputPath, $xml);
            if ($bytes === false) {
                $this->error(trans('commands.export:zabbix-template.messages.write_failed', ['file' => $outputPath]));

                return 2;
            }
            $this->info(trans('commands.export:zabbix-template.messages.exported', [
                'hostname' => $device->displayName(),
                'file' => $outputPath,
            ]));
        } else {
            $this->line($xml);
        }

        return 0;
    }
}
