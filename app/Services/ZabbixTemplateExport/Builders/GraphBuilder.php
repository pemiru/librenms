<?php

namespace App\Services\ZabbixTemplateExport\Builders;

use App\Models\Device;

class GraphBuilder
{
    /**
     * Build static (non-prototype) graphs for the template.
     *
     * @return array<int, array<string, mixed>>
     */
    public function build(Device $device, string $templateName): array
    {
        $graphs = [];

        // ICMP response time graph
        $graphs[] = [
            'name' => 'ICMP response time',
            'graph_items' => [
                [
                    'color' => '1A7C11',
                    'item' => [
                        'host' => $templateName,
                        'key' => 'icmppingsec',
                    ],
                ],
            ],
        ];

        // ICMP packet loss graph
        $graphs[] = [
            'name' => 'ICMP packet loss',
            'graph_items' => [
                [
                    'color' => 'F63100',
                    'item' => [
                        'host' => $templateName,
                        'key' => 'icmppingloss',
                    ],
                ],
            ],
        ];

        return $graphs;
    }
}
