<?php
// Tests for claude.php.wordpress.access-control.child-id-getter-no-parent-containment-check
// TP cases: child id used in a getter with no call combining it with the parent id
// FP cases: a combining call verifies the child belongs to the parent before use

// ruleid: claude.php.wordpress.access-control.child-id-getter-no-parent-containment-check
function rest_check_answer( $request ) {
    $question_id = $request['question_id'] ?? 0;
    $answered    = $request['answered'] ?? '';
    $quiz_id     = $request['quiz_id'] ?? 0;
    $question = get_question( $question_id );
    $response['explanation'] = $question->get_explanation();
    return $response;
}

// ruleid: claude.php.wordpress.access-control.child-id-getter-no-parent-containment-check
function ajax_get_line_item() {
    $order_id = $_REQUEST['order_id'];
    $item_id  = $_REQUEST['item_id'];
    $line_item = get_order_line_item( $item_id );
    echo $line_item->get_total();
}

// ok: claude.php.wordpress.access-control.child-id-getter-no-parent-containment-check
function rest_check_answer_fixed( $request ) {
    $question_id = $request['question_id'] ?? 0;
    $answered    = $request['answered'] ?? '';
    $quiz_id     = $request['quiz_id'] ?? 0;
    $link = QuizQuestionModel::find( $quiz_id, $question_id );
    if ( ! $link ) {
        return new WP_Error( 'invalid_id', '', [ 'status' => 400 ] );
    }
    $question = get_question( $question_id );
    $response['explanation'] = $question->get_explanation();
    return $response;
}

// ok: claude.php.wordpress.access-control.child-id-getter-no-parent-containment-check
function get_single_faq( $request ) {
    $faq_id = $request['faq_id'] ?? 0;
    $faq    = get_post( $faq_id );
    echo $faq->post_title;
}
