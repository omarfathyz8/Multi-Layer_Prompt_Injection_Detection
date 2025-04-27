# 🛡️ Prompt Injection Detector

This Streamlit app helps detect prompt injection attacks using:

- Heuristic keyword matching
- BERT-based semantic similarity
- GPT-4 audit layer

🚀 **Live Demo:** https://prompt-injection-detection.streamlit.app/

---

## How it works
- Paste a prompt you want to analyze.
- It checks using multiple strategies if the prompt is potentially malicious.
- Built with `streamlit`, `sentence-transformers`, and `OpenAI GPT-4`.

---

## Setup (Local Run)

```bash
git clone https://github.com/omarfathyz8/prompt-injection-detector.git
cd prompt-injection-detector
pip install -r requirements.txt
streamlit run app.py
