<?php

class Comment_Attachment_Upload_1 {
    private $mimeTypes = [
        "jpg" => "image/jpeg",
        "png" => "image/png",
        "pdf" => "application/pdf",
    ];

    private function isAllowedFileType($mimeType) {
        $isAllowed = false;
        // ruleid: claude.php.wordpress.file-upload.mime-allowlist-extension-unbound
        foreach ($this->mimeTypes as $ext => $mimes) {
            $isAllowed = in_array($mimeType, explode("|", $mimes));
            if ($isAllowed) {
                break;
            }
        }
        return $isAllowed;
    }
}

class Generic_Upload_Handler_2 {
    private $allowedMimes = [
        "gif" => "image/gif,image/x-gif",
        "doc" => "application/msword",
    ];

    public function validateType($mimeType) {
        $ok = false;
        // ruleid: claude.php.wordpress.file-upload.mime-allowlist-extension-unbound
        foreach ($this->allowedMimes as $ext => $mimes) {
            if (in_array($mimeType, explode(",", $mimes))) {
                $ok = true;
                break;
            }
        }
        return $ok;
    }
}

class Comment_Attachment_Upload_Fixed {
    private $mimeTypes = [
        "jpg" => "image/jpeg",
        "png" => "image/png",
        "pdf" => "application/pdf",
    ];

    private function isAllowedFileType($mimeType, $extension) {
        $isAllowed = false;
        // ok: claude.php.wordpress.file-upload.mime-allowlist-extension-unbound
        foreach ($this->mimeTypes as $ext => $mimes) {
            if ($ext === $extension) {
                if ($isAllowed = in_array($mimeType, explode("|", $mimes))) {
                    break;
                }
            }
        }
        return $isAllowed;
    }
}

class Generic_Upload_Handler_Fixed_2 {
    private $allowedMimes = [
        "gif" => "image/gif,image/x-gif",
        "doc" => "application/msword",
    ];

    public function validateType($mimeType, $extension) {
        $ok = false;
        // ok: claude.php.wordpress.file-upload.mime-allowlist-extension-unbound
        foreach ($this->allowedMimes as $ext => $mimes) {
            if ($extension == $ext) {
                $ok = in_array($mimeType, explode(",", $mimes));
            }
        }
        return $ok;
    }
}
