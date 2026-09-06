<?php
/**
 * Test cases for: claude.php.wordpress.xss.list-table-column-unescaped-return
 */

class Some_List_Table extends WP_List_Table {

	public function column_default( $item, $column_name ) {
		// ruleid: claude.php.wordpress.xss.list-table-column-unescaped-return
		return $item[ $column_name ];
	}

	public function column_ip_address( $item ) {
		if ( is_blocked( $item['ip_address'] ) ) {
			// ruleid: claude.php.wordpress.xss.list-table-column-unescaped-return
			return $item['ip_address'] . '<br /><span>blocked</span>';
		}
		return '';
	}

	public function column_default_fixed( $item, $column_name ) {
		// ok: claude.php.wordpress.xss.list-table-column-unescaped-return
		echo esc_html( $item[ $column_name ] );
	}

	public function column_status_fixed( $item ) {
		$status = $item['status'];
		// ok: claude.php.wordpress.xss.list-table-column-unescaped-return
		return esc_html( $status );
	}

	public function get_columns() {
		global $wpdb;
		$rows = $wpdb->get_results( "SELECT * FROM some_table" );
		// ok: claude.php.wordpress.xss.list-table-column-unescaped-return
		return $rows;
	}
}

abstract class Column_Base_Type {
	public function get_value( array $record = array() ) {
		return $record[ $this->column ] ?? false;
	}
}

class User_Journey_Query_Column extends Column_Base_Type {

	public function get_value( array $record = array() ) {
		$journey_query = $record['journey_query'] ?? '';
		// ruleid: claude.php.wordpress.xss.list-table-column-unescaped-return
		return $journey_query;
	}
}

class Form_Action_Result_Column extends Column_Base_Type {

	public function get_value( array $record = array() ) {
		// ruleid: claude.php.wordpress.xss.list-table-column-unescaped-return
		return $record['action_name'];
	}
}

class User_Journey_Query_Column_Fixed extends Column_Base_Type {

	public function get_value( array $record = array() ) {
		$journey_query = $record['journey_query'] ?? '';
		// ok: claude.php.wordpress.xss.list-table-column-unescaped-return
		return esc_html( $journey_query );
	}
}

class Form_Action_Result_Column_Fixed extends Column_Base_Type {

	public function get_value( array $record = array() ) {
		// ok: claude.php.wordpress.xss.list-table-column-unescaped-return
		return esc_html( $record['action_name'] );
	}
}

class Row_Identifier_Column_Table extends WP_List_Table {

	// $item['id'] is the row's own auto-increment primary key — never
	// attacker-supplied HTML content, even though it comes from the same row
	// array as every other (escaped-or-not) column value.
	public function column_default( $item, $column_name ) {
		switch ( $column_name ) {
			case 'id':
				// ok: claude.php.wordpress.xss.list-table-column-unescaped-return
				return $item['id'];

			case 'label':
				// A different, non-'id' literal key must still be flagged.
				// ruleid: claude.php.wordpress.xss.list-table-column-unescaped-return
				return $item['label'];
		}
		return '';
	}

	// WP_List_Table checkbox-column boilerplate: sprintf() with only a %d
	// conversion specifier can never emit attacker-controlled string content.
	public function column_cb( $item ) {
		// ok: claude.php.wordpress.xss.list-table-column-unescaped-return
		return sprintf( '<input type="checkbox" name="ids[]" value="%d" />', $item['id'] );
	}

	// A %s specifier in the same sprintf() call passes the argument through
	// as a raw string — must still be flagged.
	public function column_name( $item ) {
		// ruleid: claude.php.wordpress.xss.list-table-column-unescaped-return
		return sprintf( '<span title="%s">%d</span>', $item['label'], $item['id'] );
	}
}
