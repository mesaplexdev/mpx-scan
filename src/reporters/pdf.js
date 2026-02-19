/**
 * PDF Report Generator for mpx-scan
 * 
 * Generates professional security scan reports using PDFKit
 */

const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');
const pkg = require('../../package.json');

// Color palette
const COLORS = {
  primary: '#1a56db',
  dark: '#1f2937',
  gray: '#6b7280',
  lightGray: '#e5e7eb',
  white: '#ffffff',
  pass: '#16a34a',
  warn: '#ea580c',
  fail: '#dc2626',
  info: '#2563eb',
  error: '#dc2626',
  headerBg: '#1e3a5f',
  sectionBg: '#f3f4f6',
};

const STATUS_LABELS = {
  pass: '✓ PASS',
  warn: '⚠ WARNING',
  fail: '✗ FAIL',
  info: 'ℹ INFO',
  error: '✗ ERROR',
};

const SECTION_NAMES = {
  headers: 'Security Headers',
  ssl: 'SSL/TLS',
  cookies: 'Cookies',
  server: 'Server Configuration',
  exposedFiles: 'Exposed Files',
  dns: 'DNS Security',
  sri: 'Subresource Integrity',
  mixedContent: 'Mixed Content',
  redirects: 'Redirects',
};

/**
 * Generate a PDF report from scan results
 * @param {object} results - Scan results object
 * @param {string} outputPath - Path to write the PDF
 * @returns {Promise<string>} - Resolved path of the generated PDF
 */
function generatePDF(results, outputPath) {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({
        size: 'A4',
        margins: { top: 50, bottom: 50, left: 50, right: 50 },
        info: {
          Title: `mpx-scan Security Report — ${results.hostname}`,
          Author: 'mpx-scan',
          Subject: 'Website Security Scan Report',
          Creator: `mpx-scan v${pkg.version}`,
        },
        bufferPages: true,
      });

      const stream = fs.createWriteStream(outputPath);
      doc.pipe(stream);

      const pageWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
      const now = new Date().toLocaleDateString('en-US', {
        year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit',
      });

      // ─── Header ───
      doc.rect(0, 0, doc.page.width, 100).fill(COLORS.headerBg);
      doc.fontSize(22).fillColor(COLORS.white).font('Helvetica-Bold')
        .text('mpx-scan Security Report', 50, 30);
      doc.fontSize(10).fillColor('#a0b4cc').font('Helvetica')
        .text(`v${pkg.version}  •  ${now}  •  ${results.url}`, 50, 60);

      doc.y = 120;

      // ─── Summary Box ───
      const scorePercent = results.maxScore > 0 ? Math.round((results.score / results.maxScore) * 100) : 0;
      const gradeColor = scorePercent >= 85 ? COLORS.pass : scorePercent >= 55 ? COLORS.warn : COLORS.fail;

      doc.roundedRect(50, doc.y, pageWidth, 90, 6).fill(COLORS.sectionBg);
      const summaryTop = doc.y + 15;

      // Grade circle
      doc.circle(100, summaryTop + 30, 28).fill(gradeColor);
      doc.fontSize(26).fillColor(COLORS.white).font('Helvetica-Bold')
        .text(results.grade, 100 - 18, summaryTop + 16, { width: 36, align: 'center' });

      // Score text
      doc.fontSize(16).fillColor(COLORS.dark).font('Helvetica-Bold')
        .text(`${scorePercent}/100`, 150, summaryTop + 5);
      doc.fontSize(10).fillColor(COLORS.gray).font('Helvetica')
        .text(`${results.score}/${results.maxScore} points  •  ${results.scanDuration}ms scan`, 150, summaryTop + 28);

      // Counts
      const countsX = 360;
      const counts = [
        { label: 'Passed', count: results.summary.passed, color: COLORS.pass },
        { label: 'Warnings', count: results.summary.warnings, color: COLORS.warn },
        { label: 'Failed', count: results.summary.failed, color: COLORS.fail },
        { label: 'Info', count: results.summary.info, color: COLORS.info },
      ];
      counts.forEach((c, i) => {
        const cx = countsX + i * 55;
        doc.fontSize(18).fillColor(c.color).font('Helvetica-Bold')
          .text(String(c.count), cx, summaryTop + 5, { width: 50, align: 'center' });
        doc.fontSize(7).fillColor(COLORS.gray).font('Helvetica')
          .text(c.label, cx, summaryTop + 28, { width: 50, align: 'center' });
      });

      doc.y = summaryTop + 75;

      // ─── Detailed Findings ───
      for (const [sectionKey, section] of Object.entries(results.sections)) {
        const sectionName = SECTION_NAMES[sectionKey] || sectionKey;
        const sectionPercent = section.maxScore > 0 ? Math.round((section.score / section.maxScore) * 100) : 0;

        // Check if we need a new page (need at least 100px for header + 1 check)
        if (doc.y > doc.page.height - 150) {
          doc.addPage();
          doc.y = 50;
        }

        // Section header
        doc.y += 10;
        doc.roundedRect(50, doc.y, pageWidth, 28, 4).fill(COLORS.primary);
        doc.fontSize(11).fillColor(COLORS.white).font('Helvetica-Bold')
          .text(`${sectionName}`, 60, doc.y + 7);
        doc.fontSize(9).fillColor('#c0d4f0').font('Helvetica')
          .text(`${section.grade}  •  ${sectionPercent}%  (${section.score}/${section.maxScore})`, 60, doc.y + 7, {
            width: pageWidth - 20, align: 'right'
          });
        doc.y += 35;

        // Checks
        for (const check of section.checks) {
          if (doc.y > doc.page.height - 100) {
            doc.addPage();
            doc.y = 50;
          }

          const statusColor = COLORS[check.status] || COLORS.gray;
          const statusLabel = STATUS_LABELS[check.status] || check.status.toUpperCase();

          // Status badge
          doc.fontSize(7).fillColor(statusColor).font('Helvetica-Bold')
            .text(statusLabel, 60, doc.y);

          // Check name
          doc.fontSize(10).fillColor(COLORS.dark).font('Helvetica-Bold')
            .text(check.name, 130, doc.y);
          doc.y += 15;

          // Message
          if (check.message) {
            doc.fontSize(9).fillColor(COLORS.gray).font('Helvetica')
              .text(check.message, 130, doc.y, { width: pageWidth - 90 });
            doc.y += doc.heightOfString(check.message, { width: pageWidth - 90, fontSize: 9 }) + 3;
          }

          // Recommendation
          if (check.recommendation) {
            doc.fontSize(8).fillColor(COLORS.primary).font('Helvetica-Oblique')
              .text(`→ ${check.recommendation}`, 130, doc.y, { width: pageWidth - 90 });
            doc.y += doc.heightOfString(`→ ${check.recommendation}`, { width: pageWidth - 90, fontSize: 8 }) + 3;
          }

          doc.y += 8;
        }
      }

      // ─── Footer on every page ───
      const range = doc.bufferedPageRange();
      for (let i = range.start; i < range.start + range.count; i++) {
        doc.switchToPage(i);
        const footerY = doc.page.height - 35;
        doc.fontSize(7).fillColor(COLORS.gray).font('Helvetica')
          .text(
            `Generated by mpx-scan v${pkg.version} on ${now}`,
            50, footerY, { width: pageWidth, align: 'center' }
          );
        doc.text(
          `Page ${i + 1} of ${range.count}`,
          50, footerY + 12, { width: pageWidth, align: 'center' }
        );
      }

      doc.end();

      stream.on('finish', () => resolve(outputPath));
      stream.on('error', reject);
    } catch (err) {
      reject(err);
    }
  });
}

/**
 * Get default PDF filename for a scan
 * @param {string} hostname - Target hostname
 * @returns {string} Default filename
 */
function getDefaultPDFFilename(hostname) {
  const date = new Date().toISOString().slice(0, 10);
  const safeName = hostname.replace(/[^a-zA-Z0-9.-]/g, '_');
  return `mpx-scan-report-${safeName}-${date}.pdf`;
}

module.exports = { generatePDF, getDefaultPDFFilename };
