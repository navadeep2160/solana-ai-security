import os
import re
import time
import json
import requests
from pathlib import Path
from bs4 import BeautifulSoup
import html2text
from tqdm import tqdm

RAW_DIR = Path(__file__).parent.parent / "raw_sources"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
}

def clean_text(text):
    text = re.sub(r'\n{3,}', '\n\n', text)
    text = re.sub(r'[ \t]+', ' ', text)
    text = re.sub(r'[^\x00-\x7F]+', ' ', text)
    return text.strip()

def scrape_web(source):
    try:
        resp = requests.get(source["url"], headers=HEADERS, timeout=20)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "lxml")
        for tag in soup(["script", "style", "nav", "footer", "header"]):
            tag.decompose()
        converter = html2text.HTML2Text()
        converter.ignore_links = True
        converter.ignore_images = True
        text = converter.handle(str(soup))
        return clean_text(text)
    except Exception as e:
        return f"ERROR: {e}"

def scrape_pdf(source):
    try:
        resp = requests.get(source["url"], headers=HEADERS, timeout=30, stream=True)
        resp.raise_for_status()
        pdf_path = RAW_DIR / f"{source['id']}.pdf"
        with open(pdf_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
        # Extract text from PDF
        import PyPDF2
        text = ""
        with open(pdf_path, "rb") as f:
            reader = PyPDF2.PdfReader(f)
            for page in reader.pages:
                text += page.extract_text() or ""
        return clean_text(text)
    except Exception as e:
        return f"ERROR: {e}"

def scrape_github(source):
    try:
        url = source["url"]
        # Convert github.com URL to API or raw content
        if "/blob/" in url:
            raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
            resp = requests.get(raw_url, headers=HEADERS, timeout=20)
            return clean_text(resp.text)
        elif "/tree/" in url:
            # Get directory listing via API
            api_url = url.replace("https://github.com/", "https://api.github.com/repos/")
            api_url = api_url.replace("/tree/main/", "/contents/").replace("/tree/master/", "/contents/")
            resp = requests.get(api_url, headers={"Accept": "application/vnd.github.v3+json"}, timeout=20)
            items = resp.json()
            if isinstance(items, list):
                text = f"Repository contents of {url}:\n"
                for item in items[:30]:
                    text += f"- {item.get('name','')}: {item.get('path','')}\n"
                return clean_text(text)
        else:
            # Regular github page - scrape readme
            resp = requests.get(source["url"], headers=HEADERS, timeout=20)
            soup = BeautifulSoup(resp.text, "lxml")
            readme = soup.find("article")
            if readme:
                converter = html2text.HTML2Text()
                converter.ignore_links = True
                return clean_text(converter.handle(str(readme)))
            return scrape_web(source)
    except Exception as e:
        return f"ERROR: {e}"

def scrape_all(sources_dict):
    results = {}
    total = sum(len(v) for v in sources_dict.values())
    print(f"\nScraping {total} sources...\n")

    for collection, sources in sources_dict.items():
        print(f"\n--- Collection: {collection} ---")
        results[collection] = []

        for source in tqdm(sources, desc=collection):
            print(f"\n  Scraping: {source['title']}")
            stype = source["type"]

            if stype == "pdf":
                text = scrape_pdf(source)
            elif stype == "github":
                text = scrape_github(source)
            else:
                text = scrape_web(source)

            status = "ERROR" if text.startswith("ERROR") else "OK"
            char_count = len(text)

            result = {
                "id": source["id"],
                "title": source["title"],
                "url": source["url"],
                "type": stype,
                "collection": collection,
                "status": status,
                "char_count": char_count,
                "text": text if status == "OK" else "",
                "error": text if status == "ERROR" else ""
            }
            results[collection].append(result)

            # Save raw text
            out_path = RAW_DIR / f"{source['id']}.json"
            with open(out_path, "w") as f:
                json.dump(result, f, indent=2)

            print(f"  Status: {status} | Chars: {char_count:,}")
            time.sleep(1)  # be polite to servers

    # Save summary
    summary = {
        col: [{"id": r["id"], "status": r["status"], "chars": r["char_count"]} for r in recs]
        for col, recs in results.items()
    }
    with open(RAW_DIR / "scrape_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    print("\n\n=== SCRAPE SUMMARY ===")
    for col, recs in results.items():
        ok = sum(1 for r in recs if r["status"] == "OK")
        print(f"{col}: {ok}/{len(recs)} succeeded")

    return results

if __name__ == "__main__":
    from sources import SOURCES
    scrape_all(SOURCES)
