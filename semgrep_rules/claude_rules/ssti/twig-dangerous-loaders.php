<?php
// ruleid: claude.php.wordpress.ssti.twig-loader-string
$loader = new Twig_Loader_String();
$twig = new Twig_Environment($loader);

// ruleid: claude.php.wordpress.ssti.twig-loader-string
$loader = new \Twig_Loader_String();

// ruleid: claude.php.wordpress.ssti.twig-createtemplate-user-input
$tpl = $twig->createTemplate($_POST['template']);

$src = $_GET['src'];
// ruleid: claude.php.wordpress.ssti.twig-createtemplate-user-input
$tpl = $twig->createTemplate($src);

// ok: claude.php.wordpress.ssti.twig-loader-string
$loader = new \Twig\Loader\FilesystemLoader('/path/to/templates');
$twig = new \Twig\Environment($loader);

// ok: claude.php.wordpress.ssti.twig-createtemplate-user-input
$tpl = $twig->createTemplate('Hello {{ name }}');
$tpl->render(['name' => $_POST['name']]);

// ->parse() is no longer a sink: Twig's parse() takes a TokenStream (not a raw string),
// and many non-Twig libraries (LESS, XML, Markdown) expose ->parse() — causing FPs.
// Confirmed FP: coming-soon 6.20.0 lpage.php:1066 — $less->parse('.sp-html {' . $css . '}')
// uses the seedprod_lessc CSS compiler, which does not execute PHP code.
$css = $_POST['css'];
// ok: claude.php.wordpress.ssti.twig-createtemplate-user-input
$style = $less->parse('.sp-html {' . $css . '}');

// ok: claude.php.wordpress.ssti.twig-createtemplate-user-input
$xml_parser->parse($_POST['xml_data']);

class FormRendererLoaderInline
{
    private $_twig;
    public function showForm()
    {
        $field = [];
        $fieldValue = isset($_GET['cfs_x']) ? sanitize_text_field($_GET['cfs_x']) : false;
        if ($fieldValue !== false) {
            // ruleid: claude.php.wordpress.ssti.twig-string-loader-tainted-field-value
            $field['value'] = $fieldValue;
        }
    }
    protected function _initTwig()
    {
        // ruleid: claude.php.wordpress.ssti.twig-loader-string
        $this->_twig = new Twig_Environment(new Twig_Loader_String(), ['debug' => 0]);
    }
}

class FormRendererLoaderVar
{
    private $_twig;
    public function showForm()
    {
        $field = [];
        $val = $_POST['prefill'];
        // ruleid: claude.php.wordpress.ssti.twig-string-loader-tainted-field-value
        $field['value'] = $val;
    }
    protected function _initTwig()
    {
        // ruleid: claude.php.wordpress.ssti.twig-loader-string
        $loader = new Twig_Loader_String();
        $this->_twig = new Twig_Environment($loader, ['debug' => 0]);
    }
}

class FormRendererPatched
{
    private $_twig;
    public function showForm()
    {
        $field = [];
        $fieldValue = isset($_GET['cfs_x']) ? sanitize_text_field($_GET['cfs_x']) : false;
        if ($fieldValue !== false) {
            // Escape Twig delimiters before assignment — the real fix (CVE-2026-4257).
            $fieldValue = str_replace(['{', '}'], ['&#123;', '&#125;'], $fieldValue);
            // ok: claude.php.wordpress.ssti.twig-string-loader-tainted-field-value
            $field['value'] = $fieldValue;
        }
    }
    protected function _initTwig()
    {
        // ruleid: claude.php.wordpress.ssti.twig-loader-string
        $this->_twig = new Twig_Environment(new Twig_Loader_String(), ['debug' => 0]);
    }
}

class FormRendererNoTwig
{
    public function showForm()
    {
        $field = [];
        $val = $_GET['prefill'];
        // ok: claude.php.wordpress.ssti.twig-string-loader-tainted-field-value
        // No Twig string loader anywhere in this class — plain prefill into an
        // array key, safe as long as the eventual HTML output is esc_attr()'d
        // (a different, non-SSTI concern for the XSS category to catch).
        $field['value'] = $val;
    }
}
