<?php

// Real pre-fix shape: a JSON-decoded POST arg's nested key is concatenated
// onto an existing filter string, then handed to whereRaw() with no
// allow-list check anywhere in the function.
class ChartAjaxHandlerTest1
{
    public static function ajax_fetch_chart_data()
    {
        $args = json_decode(stripslashes($_POST['args']), true);
        $filterWhere = self::buildFilterWhere();

        if (!empty($args['chart_data']['where'])) {
            $chartWhere = $args['chart_data']['where'];
            $filterWhere = !empty($filterWhere) ? $filterWhere . ' AND ' . $chartWhere : $chartWhere;
        }

        $query = Query::select('*')->from('wp_stats');
        if (!empty($filterWhere)) {
            // ruleid: claude.php.wordpress.sqli.raw-where-fragment-unprepared-query-builder
            $query->whereRaw($filterWhere);
        }
    }

    private static function buildFilterWhere()
    {
        return '';
    }
}

// Different sink method name (snake_case) and direct GET-sourced fragment,
// no allow-list gate anywhere in the function.
class ReportBuilderTest2
{
    public function get_rows()
    {
        $filter = $_GET['filter'] ?? '';
        $extra = 'status = 1 AND ' . $filter;
        $query = new Query();
        // ruleid: claude.php.wordpress.sqli.raw-where-fragment-unprepared-query-builder
        $query->where_raw($extra, []);
        return $query->getAll();
    }
}

// The actual fix shape: the fragment is normalized and checked against an
// allow-list harvested from trusted, plugin-defined report definitions;
// only the matched canonical string (not the tainted one) reaches the sink.
class ChartAjaxHandlerTest3
{
    private static function getAllowedWhereClauses(): array
    {
        return ['status = 1' => 'status = 1'];
    }

    public static function ajax_fetch_chart_data_fixed()
    {
        $args = json_decode(stripslashes($_POST['args']), true);
        $filterWhere = '';

        if (!empty($args['chart_data']['where'])) {
            if (!is_string($args['chart_data']['where'])) {
                throw new \Exception('Invalid filter expression.');
            }
            $normalized = trim(preg_replace('/\s+/', ' ', $args['chart_data']['where']));
            $allowed = self::getAllowedWhereClauses();
            if (!isset($allowed[$normalized])) {
                throw new \Exception('Invalid filter expression.');
            }
            $canonical = $allowed[$normalized];
            $filterWhere = '(' . $canonical . ')';
        }

        $query = Query::select('*')->from('wp_stats');
        if (!empty($filterWhere)) {
            // ok: claude.php.wordpress.sqli.raw-where-fragment-unprepared-query-builder
            $query->whereRaw($filterWhere);
        }
    }
}

// Sink reached, but only a bound VALUE is tainted — the template/fragment
// argument itself is a fixed literal, never touched by request data.
class ReportBuilderTest4
{
    public function get_rows()
    {
        $status = isset($_GET['status']) ? absint($_GET['status']) : 0;
        $query = new Query();
        // ok: claude.php.wordpress.sqli.raw-where-fragment-unprepared-query-builder
        $query->whereRaw('status = %d', [$status]);
        return $query->getAll();
    }
}
