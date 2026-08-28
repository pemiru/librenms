<?php

namespace App\Services\ZabbixTemplateExport;

use App\Models\Device;
use App\Services\ZabbixTemplateExport\Builders\DiscoveryRuleBuilder;
use App\Services\ZabbixTemplateExport\Builders\GraphBuilder;
use App\Services\ZabbixTemplateExport\Builders\ItemBuilder;
use App\Services\ZabbixTemplateExport\Builders\MacroBuilder;
use App\Services\ZabbixTemplateExport\Builders\TriggerBuilder;
use App\Services\ZabbixTemplateExport\Builders\ValueMapBuilder;
use DOMDocument;
use DOMElement;

class ZabbixTemplateExporter
{
    private ItemBuilder $itemBuilder;

    private DiscoveryRuleBuilder $discoveryRuleBuilder;

    private GraphBuilder $graphBuilder;

    private TriggerBuilder $triggerBuilder;

    private ValueMapBuilder $valueMapBuilder;

    private MacroBuilder $macroBuilder;

    public function __construct(
        ?ItemBuilder $itemBuilder = null,
        ?DiscoveryRuleBuilder $discoveryRuleBuilder = null,
        ?GraphBuilder $graphBuilder = null,
        ?TriggerBuilder $triggerBuilder = null,
        ?ValueMapBuilder $valueMapBuilder = null,
        ?MacroBuilder $macroBuilder = null,
    ) {
        $this->itemBuilder = $itemBuilder ?? new ItemBuilder;
        $this->discoveryRuleBuilder = $discoveryRuleBuilder ?? new DiscoveryRuleBuilder($this->itemBuilder);
        $this->graphBuilder = $graphBuilder ?? new GraphBuilder;
        $this->triggerBuilder = $triggerBuilder ?? new TriggerBuilder;
        $this->valueMapBuilder = $valueMapBuilder ?? new ValueMapBuilder;
        $this->macroBuilder = $macroBuilder ?? new MacroBuilder;
    }

    /**
     * Export a device as a Zabbix XML template.
     */
    public function export(Device $device): string
    {
        $templateName = $this->templateName($device);

        // Eagerly load relationships we'll need
        $device->load(['sensors.stateIndex.translations', 'ports']);

        $dom = new DOMDocument('1.0', 'UTF-8');
        $dom->formatOutput = true;

        $root = $dom->createElement('zabbix_export');
        $dom->appendChild($root);

        $this->addTextElement($dom, $root, 'version', '7.0');
        $this->addTextElement($dom, $root, 'date', gmdate('Y-m-d\TH:i:s\Z'));

        // Template groups
        $groups = $dom->createElement('template_groups');
        $root->appendChild($groups);
        $group = $dom->createElement('group');
        $groups->appendChild($group);
        $this->addTextElement($dom, $group, 'name', 'Templates/Network devices');

        // Templates section
        $templates = $dom->createElement('templates');
        $root->appendChild($templates);
        $template = $dom->createElement('template');
        $templates->appendChild($template);

        $this->addTextElement($dom, $template, 'template', $templateName);
        $this->addTextElement($dom, $template, 'name', $templateName);
        $this->addTextElement($dom, $template, 'description', $this->templateDescription($device));

        // Groups reference inside template
        $tGroups = $dom->createElement('groups');
        $template->appendChild($tGroups);
        $tGroup = $dom->createElement('group');
        $tGroups->appendChild($tGroup);
        $this->addTextElement($dom, $tGroup, 'name', 'Templates/Network devices');

        // Macros
        $macroData = $this->macroBuilder->build($device);
        $this->addMacros($dom, $template, $macroData);

        // Items
        $itemData = $this->itemBuilder->buildStaticItems($device, $templateName);
        $this->addItems($dom, $template, $itemData);

        // Discovery rules
        $discoveryData = $this->discoveryRuleBuilder->build($device, $templateName);
        $this->addDiscoveryRules($dom, $template, $discoveryData);

        // Graphs
        $graphData = $this->graphBuilder->build($device, $templateName);
        $this->addGraphs($dom, $template, $graphData);

        // Triggers
        $triggerData = $this->triggerBuilder->build($device, $templateName);
        $this->addTriggers($dom, $template, $triggerData);

        // Value maps
        $valueMapData = $this->valueMapBuilder->build($device);
        $this->addValueMaps($dom, $template, $valueMapData);

        return $dom->saveXML() ?: '';
    }

    /**
     * Generate a template name from the device.
     */
    public function templateName(Device $device): string
    {
        $os = $device->os ?: 'generic';
        $hardware = $device->hardware ?: '';

        $name = 'LibreNMS Export: ' . ucfirst($os);
        if ($hardware) {
            $name .= ' ' . $hardware;
        }

        // Sanitize for Zabbix template naming
        return preg_replace('/[^a-zA-Z0-9 :_\-.]/', '', $name) ?: 'LibreNMS Export';
    }

    /**
     * Generate a template description.
     */
    private function templateDescription(Device $device): string
    {
        $lines = [
            'Auto-generated Zabbix template exported from LibreNMS.',
            '',
            'Source device: ' . $device->displayName(),
            'OS: ' . ($device->os ?: 'unknown'),
            'Hardware: ' . ($device->hardware ?: 'unknown'),
            'sysObjectID: ' . ($device->sysObjectID ?: 'unknown'),
            '',
            'This template contains SNMP items, discovery rules, graphs,',
            'triggers, and value maps translated from LibreNMS sensor and',
            'port monitoring data. Review and adjust macros for your environment.',
        ];

        return implode("\n", $lines);
    }

    private function addTextElement(DOMDocument $dom, DOMElement $parent, string $tag, string $value): void
    {
        $el = $dom->createElement($tag);
        $el->appendChild($dom->createTextNode($value));
        $parent->appendChild($el);
    }

    private function addMacros(DOMDocument $dom, DOMElement $parent, array $macros): void
    {
        $macrosEl = $dom->createElement('macros');
        $parent->appendChild($macrosEl);

        foreach ($macros as $macro) {
            $macroEl = $dom->createElement('macro');
            $macrosEl->appendChild($macroEl);
            $this->addTextElement($dom, $macroEl, 'macro', $macro['macro']);
            $this->addTextElement($dom, $macroEl, 'value', $macro['value']);
            $this->addTextElement($dom, $macroEl, 'description', $macro['description']);
        }
    }

    private function addItems(DOMDocument $dom, DOMElement $parent, array $items): void
    {
        $itemsEl = $dom->createElement('items');
        $parent->appendChild($itemsEl);

        foreach ($items as $item) {
            $this->addItem($dom, $itemsEl, $item);
        }
    }

    private function addItem(DOMDocument $dom, DOMElement $parent, array $item): void
    {
        $itemEl = $dom->createElement('item');
        $parent->appendChild($itemEl);

        $this->addTextElement($dom, $itemEl, 'name', $item['name']);
        $this->addTextElement($dom, $itemEl, 'type', $item['type']);

        if (! empty($item['snmp_oid'])) {
            $this->addTextElement($dom, $itemEl, 'snmp_oid', $item['snmp_oid']);
        }

        $this->addTextElement($dom, $itemEl, 'key', $item['key']);
        $this->addTextElement($dom, $itemEl, 'delay', $item['delay'] ?? '5m');
        $this->addTextElement($dom, $itemEl, 'history', $item['history'] ?? '7d');
        $this->addTextElement($dom, $itemEl, 'trends', $item['trends'] ?? '365d');
        $this->addTextElement($dom, $itemEl, 'value_type', $item['value_type']);

        if (! empty($item['units'])) {
            $this->addTextElement($dom, $itemEl, 'units', $item['units']);
        }

        if (! empty($item['description'])) {
            $this->addTextElement($dom, $itemEl, 'description', $item['description']);
        }

        if (! empty($item['valuemap'])) {
            $vmEl = $dom->createElement('valuemap');
            $itemEl->appendChild($vmEl);
            $this->addTextElement($dom, $vmEl, 'name', $item['valuemap']['name']);
        }

        if (! empty($item['preprocessing'])) {
            $this->addPreprocessing($dom, $itemEl, $item['preprocessing']);
        }
    }

    private function addPreprocessing(DOMDocument $dom, DOMElement $parent, array $steps): void
    {
        $prepEl = $dom->createElement('preprocessing');
        $parent->appendChild($prepEl);

        foreach ($steps as $step) {
            $stepEl = $dom->createElement('step');
            $prepEl->appendChild($stepEl);
            $this->addTextElement($dom, $stepEl, 'type', $step['type']);

            if (! empty($step['parameters'])) {
                $paramsEl = $dom->createElement('parameters');
                $stepEl->appendChild($paramsEl);
                foreach ($step['parameters'] as $param) {
                    $this->addTextElement($dom, $paramsEl, 'parameter', (string) $param);
                }
            }
        }
    }

    private function addDiscoveryRules(DOMDocument $dom, DOMElement $parent, array $rules): void
    {
        $rulesEl = $dom->createElement('discovery_rules');
        $parent->appendChild($rulesEl);

        foreach ($rules as $rule) {
            $ruleEl = $dom->createElement('discovery_rule');
            $rulesEl->appendChild($ruleEl);

            $this->addTextElement($dom, $ruleEl, 'name', $rule['name']);
            $this->addTextElement($dom, $ruleEl, 'type', $rule['type']);
            $this->addTextElement($dom, $ruleEl, 'snmp_oid', $rule['snmp_oid']);
            $this->addTextElement($dom, $ruleEl, 'key', $rule['key']);
            $this->addTextElement($dom, $ruleEl, 'delay', $rule['delay'] ?? '1h');

            if (! empty($rule['description'])) {
                $this->addTextElement($dom, $ruleEl, 'description', $rule['description']);
            }

            // Filter
            if (! empty($rule['filter'])) {
                $this->addFilter($dom, $ruleEl, $rule['filter']);
            }

            // Item prototypes
            if (! empty($rule['item_prototypes'])) {
                $protosEl = $dom->createElement('item_prototypes');
                $ruleEl->appendChild($protosEl);
                foreach ($rule['item_prototypes'] as $proto) {
                    $this->addItemPrototype($dom, $protosEl, $proto);
                }
            }

            // Trigger prototypes
            if (! empty($rule['trigger_prototypes'])) {
                $triggersEl = $dom->createElement('trigger_prototypes');
                $ruleEl->appendChild($triggersEl);
                foreach ($rule['trigger_prototypes'] as $trigger) {
                    $this->addTrigger($dom, $triggersEl, $trigger, 'trigger_prototype');
                }
            }

            // Graph prototypes
            if (! empty($rule['graph_prototypes'])) {
                $graphsEl = $dom->createElement('graph_prototypes');
                $ruleEl->appendChild($graphsEl);
                foreach ($rule['graph_prototypes'] as $graph) {
                    $this->addGraph($dom, $graphsEl, $graph, 'graph_prototype');
                }
            }
        }
    }

    private function addFilter(DOMDocument $dom, DOMElement $parent, array $filter): void
    {
        $filterEl = $dom->createElement('filter');
        $parent->appendChild($filterEl);

        $this->addTextElement($dom, $filterEl, 'evaltype', $filter['evaltype'] ?? 'AND');

        if (! empty($filter['conditions'])) {
            $condsEl = $dom->createElement('conditions');
            $filterEl->appendChild($condsEl);
            foreach ($filter['conditions'] as $cond) {
                $condEl = $dom->createElement('condition');
                $condsEl->appendChild($condEl);
                $this->addTextElement($dom, $condEl, 'macro', $cond['macro']);
                $this->addTextElement($dom, $condEl, 'value', $cond['value']);
                if (! empty($cond['operator'])) {
                    $this->addTextElement($dom, $condEl, 'operator', $cond['operator']);
                }
                $this->addTextElement($dom, $condEl, 'formulaid', $cond['formulaid']);
            }
        }
    }

    private function addItemPrototype(DOMDocument $dom, DOMElement $parent, array $proto): void
    {
        $protoEl = $dom->createElement('item_prototype');
        $parent->appendChild($protoEl);

        $this->addTextElement($dom, $protoEl, 'name', $proto['name']);
        $this->addTextElement($dom, $protoEl, 'type', $proto['type']);
        $this->addTextElement($dom, $protoEl, 'snmp_oid', $proto['snmp_oid']);
        $this->addTextElement($dom, $protoEl, 'key', $proto['key']);
        $this->addTextElement($dom, $protoEl, 'delay', $proto['delay'] ?? '5m');
        $this->addTextElement($dom, $protoEl, 'history', $proto['history'] ?? '7d');
        $this->addTextElement($dom, $protoEl, 'trends', $proto['trends'] ?? '365d');
        $this->addTextElement($dom, $protoEl, 'value_type', $proto['value_type']);

        if (! empty($proto['units'])) {
            $this->addTextElement($dom, $protoEl, 'units', $proto['units']);
        }

        if (! empty($proto['description'])) {
            $this->addTextElement($dom, $protoEl, 'description', $proto['description']);
        }

        if (! empty($proto['valuemap'])) {
            $vmEl = $dom->createElement('valuemap');
            $protoEl->appendChild($vmEl);
            $this->addTextElement($dom, $vmEl, 'name', $proto['valuemap']['name']);
        }

        if (! empty($proto['preprocessing'])) {
            $this->addPreprocessing($dom, $protoEl, $proto['preprocessing']);
        }
    }

    private function addGraphs(DOMDocument $dom, DOMElement $parent, array $graphs): void
    {
        $graphsEl = $dom->createElement('graphs');
        $parent->appendChild($graphsEl);

        foreach ($graphs as $graph) {
            $this->addGraph($dom, $graphsEl, $graph);
        }
    }

    private function addGraph(DOMDocument $dom, DOMElement $parent, array $graph, string $elementName = 'graph'): void
    {
        $graphEl = $dom->createElement($elementName);
        $parent->appendChild($graphEl);

        $this->addTextElement($dom, $graphEl, 'name', $graph['name']);
        $this->addTextElement($dom, $graphEl, 'width', (string) ($graph['width'] ?? 900));
        $this->addTextElement($dom, $graphEl, 'height', (string) ($graph['height'] ?? 200));

        $itemsEl = $dom->createElement('graph_items');
        $graphEl->appendChild($itemsEl);

        foreach ($graph['graph_items'] as $gi) {
            $giEl = $dom->createElement('graph_item');
            $itemsEl->appendChild($giEl);

            $this->addTextElement($dom, $giEl, 'color', $gi['color']);

            if (! empty($gi['drawtype'])) {
                $this->addTextElement($dom, $giEl, 'drawtype', $gi['drawtype']);
            }

            $itemRefEl = $dom->createElement('item');
            $giEl->appendChild($itemRefEl);
            $this->addTextElement($dom, $itemRefEl, 'host', $gi['item']['host']);
            $this->addTextElement($dom, $itemRefEl, 'key', $gi['item']['key']);
        }
    }

    private function addTriggers(DOMDocument $dom, DOMElement $parent, array $triggers): void
    {
        $triggersEl = $dom->createElement('triggers');
        $parent->appendChild($triggersEl);

        foreach ($triggers as $trigger) {
            $this->addTrigger($dom, $triggersEl, $trigger);
        }
    }

    private function addTrigger(DOMDocument $dom, DOMElement $parent, array $trigger, string $elementName = 'trigger'): void
    {
        $triggerEl = $dom->createElement($elementName);
        $parent->appendChild($triggerEl);

        $this->addTextElement($dom, $triggerEl, 'expression', $trigger['expression']);
        $this->addTextElement($dom, $triggerEl, 'name', $trigger['name']);
        $this->addTextElement($dom, $triggerEl, 'priority', $trigger['priority'] ?? 'NOT_CLASSIFIED');

        if (! empty($trigger['description'])) {
            $this->addTextElement($dom, $triggerEl, 'description', $trigger['description']);
        }

        if (! empty($trigger['manual_close'])) {
            $this->addTextElement($dom, $triggerEl, 'manual_close', $trigger['manual_close']);
        }

        if (! empty($trigger['dependencies'])) {
            $depsEl = $dom->createElement('dependencies');
            $triggerEl->appendChild($depsEl);
            foreach ($trigger['dependencies'] as $dep) {
                $depEl = $dom->createElement('dependency');
                $depsEl->appendChild($depEl);
                $this->addTextElement($dom, $depEl, 'name', $dep['name']);
                if (! empty($dep['expression'])) {
                    $this->addTextElement($dom, $depEl, 'expression', $dep['expression']);
                }
            }
        }
    }

    private function addValueMaps(DOMDocument $dom, DOMElement $parent, array $valueMaps): void
    {
        $vmEl = $dom->createElement('valuemaps');
        $parent->appendChild($vmEl);

        foreach ($valueMaps as $vm) {
            $mapEl = $dom->createElement('valuemap');
            $vmEl->appendChild($mapEl);
            $this->addTextElement($dom, $mapEl, 'name', $vm['name']);

            $mappingsEl = $dom->createElement('mappings');
            $mapEl->appendChild($mappingsEl);

            foreach ($vm['mappings'] as $mapping) {
                $mappingEl = $dom->createElement('mapping');
                $mappingsEl->appendChild($mappingEl);
                $this->addTextElement($dom, $mappingEl, 'value', $mapping['value']);
                $this->addTextElement($dom, $mappingEl, 'newvalue', $mapping['newvalue']);
            }
        }
    }
}
