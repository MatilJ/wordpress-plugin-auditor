// Test cases for claude.js.wordpress.xss.jquery-dom-insertion-ajax-response

// --- TRUE POSITIVES ---

// ruleid: claude.js.wordpress.xss.jquery-dom-insertion-ajax-response
jQuery('#list').append('<li>' + response.data.name + '</li>');

// ruleid: claude.js.wordpress.xss.jquery-dom-insertion-ajax-response
$('#container').prepend('<div class="item">' + item.title + '</div>');

// ruleid: claude.js.wordpress.xss.jquery-dom-insertion-ajax-response
$(row).after('<tr><td>' + data.value + '</td></tr>');

// ruleid: claude.js.wordpress.xss.jquery-dom-insertion-ajax-response
$element.before('<span>' + userData.label + '</span>');

// ruleid: claude.js.wordpress.xss.jquery-dom-insertion-ajax-response
$('#target').replaceWith('<div>' + res.html + '</div>');

// ruleid: claude.js.wordpress.xss.jquery-dom-insertion-ajax-response
$('#items').append(items.join(''));

// ruleid: claude.js.wordpress.xss.jquery-dom-insertion-ajax-response
$el.prepend(rows.join('<br>'));

// Pre-built variable idiom: markup accumulated via += across an AJAX
// response's fields, then passed as a bare variable into .before().
var file_html = '';
// ruleid: claude.js.wordpress.xss.jquery-dom-insertion-ajax-response
file_html += '<img src="' + file['url'] + '" alt="' + file['author'] + '">';
jQuery('#container .clear').before(file_html);

var list_html = '';
// ruleid: claude.js.wordpress.xss.jquery-dom-insertion-ajax-response
list_html += '<li>' + item.title + '</li>';
$('#list').append(list_html);

// --- FALSE POSITIVES ---

// ok: claude.js.wordpress.xss.jquery-dom-insertion-ajax-response
$('#list').text(response.data.name);

// ok: claude.js.wordpress.xss.jquery-dom-insertion-ajax-response
$('#list').append(DOMPurify.sanitize('<li>' + response.data.name + '</li>'));
