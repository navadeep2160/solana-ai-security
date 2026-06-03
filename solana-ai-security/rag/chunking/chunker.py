import re

def chunk_rust(content):

    pattern = r"(pub fn|fn)\s+\w+"

    matches = list(re.finditer(pattern, content))

    chunks = []

    for i in range(len(matches)):

        start = matches[i].start()

        end = (
            matches[i + 1].start()
            if i + 1 < len(matches)
            else len(content)
        )

        chunk = content[start:end]

        chunks.append(chunk)

    return chunks


def chunk_markdown(content):

    sections = re.split(r"\n# ", content)

    return sections


def chunk_file(path, content):

    if path.endswith(".rs"):
        return chunk_rust(content)

    return chunk_markdown(content)