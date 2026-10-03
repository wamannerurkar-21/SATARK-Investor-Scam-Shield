
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from PIL import Image, ImageDraw, ImageFont

from ocr.extractor import extract_text_from_image


class ExtractTextFromImageTests(unittest.TestCase):
    def _make_screenshot(self, path: Path) -> None:
        image = Image.new("RGB", (1_200, 240), "white")
        draw = ImageDraw.Draw(image)
        try:
            font = ImageFont.truetype("DejaVuSans.ttf", 72)
        except OSError:
            try:
                font = ImageFont.load_default(size=72)
            except TypeError:
                font = ImageFont.load_default()
        draw.text((48, 62), "SATARK TEST MESSAGE", fill="black", font=font)
        image.save(path, format="PNG")

    @unittest.skipUnless(shutil.which("tesseract"), "Tesseract binary is not installed")
    def test_extracts_text_from_valid_screenshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            image_path = Path(directory) / "sample.png"
            self._make_screenshot(image_path)

            result = extract_text_from_image(image_path)

        self.assertTrue(result["success"], result)
        self.assertIn("SATARK", result["text"].upper())
        self.assertGreaterEqual(result["confidence"], 0.0)
        self.assertLessEqual(result["confidence"], 1.0)
        self.assertNotIn("error", result)

    def test_invalid_image_returns_clean_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            image_path = Path(directory) / "invalid.png"
            image_path.write_bytes(b"not an image")

            result = extract_text_from_image(image_path)

        self.assertFalse(result["success"])
        self.assertEqual(result["text"], "")
        self.assertIn("error", result)

    def test_ocr_failure_returns_manual_input_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            image_path = Path(directory) / "sample.png"
            self._make_screenshot(image_path)
            with patch("ocr.extractor._run_tesseract", side_effect=RuntimeError("private engine detail")):
                result = extract_text_from_image(image_path)

        self.assertFalse(result["success"])
        self.assertIn("manually", result["error"])
        self.assertNotIn("private engine detail", result["error"])

    def test_temporary_upload_can_be_deleted_after_processing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            image_path = Path(directory) / "temporary.png"
            self._make_screenshot(image_path)
            with patch("ocr.extractor._run_tesseract", return_value=("SATARK TEST", 0.9)):
                result = extract_text_from_image(image_path, delete_after=True)

        self.assertTrue(result["success"])
        self.assertFalse(image_path.exists())

    def test_rejects_unsupported_file_extension(self) -> None:
        result = extract_text_from_image("screenshot.pdf")
        self.assertFalse(result["success"])
        self.assertIn("Unsupported", result["error"])


if __name__ == "__main__":
    unittest.main()
