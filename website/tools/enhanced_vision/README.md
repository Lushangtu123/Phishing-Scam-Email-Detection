# Optional local image recognition

This service runs separately from the Vercel website. It listens only on
`127.0.0.1`, accepts bounded PNG/JPEG/single-frame WebP bytes, and returns a
second literal OCR reading. The default browser Tesseract/jsQR flow stays
enabled. Additional output does not change a phishing verdict or certify an
address as safe. No submitted image is written to disk by this service.

Install the **optional** pinned dependencies into an isolated Python 3.12
environment (the repository's serving requirements do not include them):

```sh
python -m pip install -r website/tools/enhanced_vision/requirements.txt
python -m unittest website.tools.enhanced_vision.test_provider -v
python -m website.tools.enhanced_vision.provider --port 8765
```

The pinned `rapidocr-onnxruntime==1.4.4` package includes three PP-OCRv4
ONNX models; it does not fetch a model when an image is submitted. The service
computes their SHA-256 digests and the installed engine source digest. Image
formats, dimensions (at most 4,096 pixels per side and 8 million pixels), size
(at most 2 MiB), concurrent work, output length and deadlines are bounded.
The OCR package reads mixed Chinese/English with one bundled model, so the
requested language is a hint, not a claim that separate English and Chinese
weights were selected. Neither OCR nor model-generated URL strings are
corrected or followed.

For a **local development** website, start its backend with:

```sh
APP_ENV=development ENHANCED_VISION_ENABLED=true \
  ENHANCED_VISION_URL=http://127.0.0.1:8765/recognize \
  python -m uvicorn app:app --app-dir website --host 127.0.0.1 --port 8000
```

For a non-loopback deployment, the website configuration requires an HTTPS
`/recognize` URL and `ENHANCED_VISION_TOKEN`. The loopback process itself is
not remotely reachable. A separately administered private HTTPS gateway is
needed to expose it to a production backend. Keep the service and token
private; the API sends the original image only after the user selects the
enhanced recognition checkbox. The website never includes the token in
`/api/config` or browser code. You may also set the **same** token in the
local service environment to require a Bearer header. Do not enable this
feature publicly until the gateway, privacy notice, and data path are reviewed.

Optional screenshot understanding uses a separately installed, local Ollama
model. Set `ENHANCED_VISION_MODEL` to the exact admin-approved model name on
the service and `ENHANCED_VISION_SEMANTICS_ENABLED=true` on the website. The
provider sends only to Ollama on `127.0.0.1:11434` using fixed JSON output,
bounded image resolution, tokens, response bytes and time. It never downloads
models or follows links from an image. Neither MiniCPM-V nor Qwen2.5-VL was
installed or evaluated in this change. If testing Qwen2.5-VL, use the 7B
Apache-2.0 checkpoint for a possible deployed candidate; the 3B model has a
research-only license. Model output is unverified text, not a risk score.

Relevant upstream projects and licenses: [RapidOCR](https://github.com/RapidAI/RapidOCR),
[PP-OCR](https://github.com/PaddlePaddle/PaddleOCR),
[MiniCPM-V-4.6](https://huggingface.co/openbmb/MiniCPM-V-4.6),
[Qwen2.5-VL-7B](https://huggingface.co/Qwen/Qwen2.5-VL-7B-Instruct), and
[Qwen2.5-VL-3B license](https://huggingface.co/Qwen/Qwen2.5-VL-3B-Instruct/raw/main/LICENSE).
