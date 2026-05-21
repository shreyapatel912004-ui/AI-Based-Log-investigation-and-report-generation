from pathlib import Path


class LogFileReader:
    BLOCKED_BINARY_EXTENSIONS = {".evtx"}
    SUPPORTED_EXTENSIONS = {".log", ".txt", ".csv", ".json", ".jsonl", ".xml", ".out"}
    DECODINGS = ("utf-8-sig", "utf-16", "cp1252", "latin-1")

    def read(self, filename: str, payload: bytes) -> str:
        extension = Path(filename or "").suffix.lower()

        if extension in self.BLOCKED_BINARY_EXTENSIONS:
            raise ValueError(
                "Windows .evtx files are binary. Export them from Event Viewer as XML, CSV, or TXT, then upload here."
            )

        if extension and extension not in self.SUPPORTED_EXTENSIONS:
            raise ValueError("Unsupported file type. Upload .log, .txt, .csv, .json, .jsonl, .xml, or .out files.")

        for encoding in self.DECODINGS:
            try:
                text = payload.decode(encoding)
                if text.strip():
                    return text
            except UnicodeDecodeError:
                continue

        raise ValueError("Could not decode this log file as text.")
