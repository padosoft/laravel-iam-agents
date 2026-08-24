<?php

declare(strict_types=1);

use Padosoft\Iam\Agents\Tests\RebelTestCase;
use Padosoft\Iam\Agents\Tests\TestCase;

uses(TestCase::class)->in('Feature');

// L'adapter rebel-step-up vive in una suite separata: il suo TestCase boota ANCHE
// i provider rebel (core + email-otp + step-up) accanto a server IAM + modulo.
uses(RebelTestCase::class)->in('Rebel');
