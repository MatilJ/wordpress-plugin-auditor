<?php
// Test cases for color-setting-getter-unsanitized-return
// Rule id: claude.php.wordpress.xss.color-setting-getter-unsanitized-return

namespace Vendor\ViewModels;

class FormViewModel {
    private $formSettings;

    // ruleid: claude.php.wordpress.xss.color-setting-getter-unsanitized-return
    public function primaryColor(): string
    {
        if ($this->formSettings->inheritCampaignColors) {
            $campaignColors = $this->getCampaignColors($this->donationFormId);

            if ($campaignColors['primaryColor']) {
                return $campaignColors['primaryColor'];
            }
        }

        return $this->formSettings->primaryColor ?? '';
    }

    // ruleid: claude.php.wordpress.xss.color-setting-getter-unsanitized-return
    public function get_background_color(): string
    {
        return $this->settings['backgroundColor'] ?? '#ffffff';
    }

    // ok: claude.php.wordpress.xss.color-setting-getter-unsanitized-return
    // Fixed shape (mirrors the real patch): value is validated with
    // sanitize_hex_color() before being returned.
    public function secondaryColor(): string
    {
        $color = $this->formSettings->secondaryColor ?? '';

        if ($this->formSettings->inheritCampaignColors) {
            $campaignColors = $this->getCampaignColors($this->donationFormId);

            if ($campaignColors['secondaryColor']) {
                $color = $campaignColors['secondaryColor'];
            }
        }

        return sanitize_hex_color($color) ?? '';
    }

    // ok: claude.php.wordpress.xss.color-setting-getter-unsanitized-return
    public function getAccentColor(): string
    {
        return sanitize_hex_color_no_hash($this->settings['accentColor'] ?? '');
    }

    // ok: claude.php.wordpress.xss.color-setting-getter-unsanitized-return
    // Not a color-named getter — must not fire on ordinary DB-read passthrough getters.
    public function getDonorName(): string
    {
        return $this->donor->name ?? '';
    }
}
