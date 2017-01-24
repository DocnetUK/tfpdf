<?php

use PHPUnit\Framework\TestCase;

define('FPDF_FONT_WRITE_PATH', __DIR__ . '/../build/');

class PDFGeneratedTest extends TestCase
{
    public function testFileIsGenerated()
    {
        $pdfLibrary = new tFPDF\PDF();

        $pdfLibrary->AddPage();

        $pdfLibrary->AddFont('DejaVuSansCondensed', '', 'DejaVuSansCondensed.ttf', true);
        $pdfLibrary->SetFont('DejaVuSansCondensed', '', 14);

        $txt = file_get_contents(__DIR__ . '/test_data/HelloWorld.txt');
        $pdfLibrary->Write(8, $txt);

        $pdfLibrary->SetFont('Arial', '', 14);
        $pdfLibrary->Ln(10);
        $pdfLibrary->Write(5, "La taille de ce PDF n'est que de 12 ko.");

        $file = $pdfLibrary->output();

        file_put_contents(__DIR__ . '/test_data/output.pdf', $file);

        if (!file_exists(__DIR__ . '/test_data/output.pdf')) {
            static::fail();
        }
    }
}
