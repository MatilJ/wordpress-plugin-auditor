<?php
// Test cases for claude.php.wordpress.sqli.csv-explode-uncast-tax-query-terms

function relevanssi_compile_search_args_cat_vuln( $query ) {
	$cat = $query->query_vars['cats'];
	// ruleid: claude.php.wordpress.sqli.csv-explode-uncast-tax-query-terms
	$cat         = explode( ',', $cat );
	$tax_query[] = array(
		'taxonomy' => 'category',
		'field'    => 'term_id',
		'terms'    => $cat,
		'operator' => 'IN',
	);
	return $tax_query;
}

function relevanssi_compile_search_args_tag_vuln( $query ) {
	$tag = $query->query_vars['tags'];
	// ruleid: claude.php.wordpress.sqli.csv-explode-uncast-tax-query-terms
	$tag      = explode( '+', $tag );
	$operator = 'AND';
	$tax_query[] = array(
		'taxonomy' => 'post_tag',
		'field'    => 'id',
		'terms'    => $tag,
		'operator' => $operator,
	);
	return $tax_query;
}

function custom_search_filter_ids_vuln( $ids_csv ) {
	// ruleid: claude.php.wordpress.sqli.csv-explode-uncast-tax-query-terms
	$ids = explode( ',', $ids_csv );
	$row = [
		'taxonomy' => 'product_cat',
		'field'    => 'term_id',
		'terms'    => $ids,
	];
	return $row;
}

function relevanssi_compile_search_args_tag_vuln_ifelse( $query ) {
	$tag = $query->query_vars['tags'];
	// ruleid: claude.php.wordpress.sqli.csv-explode-uncast-tax-query-terms
	if ( false !== strpos( $tag, '+' ) ) {
		$tag      = explode( '+', $tag );
		$operator = 'AND';
	} else {
		$tag      = explode( ',', $tag );
		$operator = 'OR';
	}
	$tax_query[] = array(
		'taxonomy' => 'post_tag',
		'field'    => 'id',
		'terms'    => $tag,
		'operator' => $operator,
	);
	return $tax_query;
}

function relevanssi_compile_search_args_cat_fixed( $query ) {
	$cat = $query->query_vars['cats'];
	// ok: claude.php.wordpress.sqli.csv-explode-uncast-tax-query-terms
	$cat         = array_map( 'absint', explode( ',', $cat ) );
	$tax_query[] = array(
		'taxonomy' => 'category',
		'field'    => 'term_id',
		'terms'    => $cat,
		'operator' => 'IN',
	);
	return $tax_query;
}

function relevanssi_compile_search_args_tag_fixed( $query ) {
	$tag = $query->query_vars['tags'];
	// ok: claude.php.wordpress.sqli.csv-explode-uncast-tax-query-terms
	$tag      = explode( '+', $tag );
	$tag      = array_map( 'intval', $tag );
	$operator = 'AND';
	$tax_query[] = array(
		'taxonomy' => 'post_tag',
		'field'    => 'id',
		'terms'    => $tag,
		'operator' => $operator,
	);
	return $tax_query;
}

function real_wp_query_tax_query_read_only( $csv ) {
	// ok: claude.php.wordpress.sqli.csv-explode-uncast-tax-query-terms
	$ids = wp_parse_id_list( $csv );
	$args = array(
		'tax_query' => array(
			array(
				'taxonomy' => 'category',
				'field'    => 'term_id',
				'terms'    => $ids,
			),
		),
	);
	return new WP_Query( $args );
}
