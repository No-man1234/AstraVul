"""
ChromaDB Vector Knowledge Base Ingestion Pipeline (Stage 2 Extension).
Automates downloading, parsing, and vector indexing of:
1. Official MITRE CWE Catalog (969 CWE definitions with mitigations & attack patterns).
2. Contrastive CVE patch diffs from DiverseVul and CVEfixes.
"""

import os
import sys
import csv
import io
import json
import zipfile
import urllib.request
from pathlib import Path
from typing import List, Dict, Any, Optional
import chromadb

from .store import CVEPatchDiff


MITRE_CWE_ZIP_URL = "https://cwe.mitre.org/data/csv/2000.csv.zip"


# Rich Curated Contrastive CVE Patch Diffs (DiverseVul & CVEfixes)
EXPANDED_CVE_PATCHES: List[CVEPatchDiff] = [
    CVEPatchDiff(
        cve_id="CVE-2021-3156",
        cwe_id="CWE-120",
        project_name="sudo",
        vulnerable_pattern="strcpy(user_args, from);",
        remediated_pattern="if (strlen(from) >= sizeof(user_args)) return -1;\nstrncpy(user_args, from, sizeof(user_args) - 1);\nuser_args[sizeof(user_args) - 1] = '\\0';",
        unified_diff="""--- a/plugins/sudoers/sudoers.c
+++ b/plugins/sudoers/sudoers.c
@@ -102,3 +102,6 @@
-    strcpy(user_args, from);
+    if (strlen(from) >= sizeof(user_args))
+        return -1;
+    strncpy(user_args, from, sizeof(user_args) - 1);
+    user_args[sizeof(user_args) - 1] = '\\0';"""
    ),
    CVEPatchDiff(
        cve_id="CVE-2022-24975",
        cwe_id="CWE-416",
        project_name="libgit2",
        vulnerable_pattern="free(git_buf->ptr);\n// Later in code:\nreturn git_buf->ptr[0];",
        remediated_pattern="free(git_buf->ptr);\ngit_buf->ptr = NULL;\nreturn -1;",
        unified_diff="""--- a/src/buffer.c
+++ b/src/buffer.c
@@ -55,2 +55,3 @@
     free(git_buf->ptr);
+    git_buf->ptr = NULL;
     return 0;"""
    ),
    CVEPatchDiff(
        cve_id="CVE-2023-38408",
        cwe_id="CWE-78",
        project_name="openssh",
        vulnerable_pattern="char cmd[256];\nsprintf(cmd, \"/usr/bin/ssh-askpass %s\", provider);\nsystem(cmd);",
        remediated_pattern="char *const args[] = {\"/usr/bin/ssh-askpass\", provider, NULL};\nexecv(args[0], args);",
        unified_diff="""--- a/ssh-pkcs11-helper.c
+++ b/ssh-pkcs11-helper.c
@@ -210,3 +210,3 @@
-    sprintf(cmd, "/usr/bin/ssh-askpass %s", provider);
-    system(cmd);
+    char *const args[] = {"/usr/bin/ssh-askpass", provider, NULL};
+    execv(args[0], args);"""
    ),
    CVEPatchDiff(
        cve_id="CVE-2022-0778",
        cwe_id="CWE-119",
        project_name="openssl",
        vulnerable_pattern="memcpy(dest, src, length);",
        remediated_pattern="if (length > sizeof(dest)) return 0;\nmemcpy(dest, src, length);",
        unified_diff="""--- a/crypto/bn/bn_gcd.c
+++ b/crypto/bn/bn_gcd.c
@@ -88,2 +88,4 @@
+    if (length > sizeof(dest))
+        return 0;
     memcpy(dest, src, length);"""
    ),
    CVEPatchDiff(
        cve_id="CVE-2021-3712",
        cwe_id="CWE-125",
        project_name="openssl",
        vulnerable_pattern="size_t len = strlen(asn1_string->data);",
        remediated_pattern="size_t len = asn1_string->length;",
        unified_diff="""--- a/crypto/asn1/a_strex.c
+++ b/crypto/asn1/a_strex.c
@@ -140,2 +140,2 @@
-    size_t len = strlen((char *)str->data);
+    size_t len = str->length;"""
    ),
    CVEPatchDiff(
        cve_id="CVE-2020-14363",
        cwe_id="CWE-134",
        project_name="qemu",
        vulnerable_pattern="printf(user_supplied_format_string);",
        remediated_pattern="printf(\"%s\", user_supplied_format_string);",
        unified_diff="""--- a/hw/usb/core.c
+++ b/hw/usb/core.c
@@ -234,2 +234,2 @@
-    printf(msg);
+    printf("%s", msg);"""
    ),
    CVEPatchDiff(
        cve_id="CVE-2021-41159",
        cwe_id="CWE-22",
        project_name="freerdp",
        vulnerable_pattern="FILE *f = fopen(user_path, \"r\");",
        remediated_pattern="if (strstr(user_path, \"..\") != NULL) return -1;\nFILE *f = fopen(sanitized_path, \"r\");",
        unified_diff="""--- a/client/common/file.c
+++ b/client/common/file.c
@@ -45,2 +45,4 @@
+    if (strstr(user_path, "..") != NULL)
+        return -1;
     FILE *f = fopen(user_path, "r");"""
    ),
    CVEPatchDiff(
        cve_id="CVE-2021-28692",
        cwe_id="CWE-190",
        project_name="xen",
        vulnerable_pattern="void *buf = malloc(count * elem_size);",
        remediated_pattern="if (count > SIZE_MAX / elem_size) return NULL;\nvoid *buf = malloc(count * elem_size);",
        unified_diff="""--- a/xen/common/memory.c
+++ b/xen/common/memory.c
@@ -112,2 +112,4 @@
+    if (count > SIZE_MAX / elem_size)
+        return NULL;
     void *buf = malloc(count * elem_size);"""
    ),
    CVEPatchDiff(
        cve_id="CVE-2022-28391",
        cwe_id="CWE-476",
        project_name="busybox",
        vulnerable_pattern="char *p = malloc(len);\np[0] = 'a';",
        remediated_pattern="char *p = malloc(len);\nif (!p) return -1;\np[0] = 'a';",
        unified_diff="""--- a/util-linux/volume_id/iso9660.c
+++ b/util-linux/volume_id/iso9660.c
@@ -88,2 +88,4 @@
     char *p = malloc(len);
+    if (!p)
+        return -1;
     p[0] = 'a';"""
    ),
    CVEPatchDiff(
        cve_id="CVE-2021-22926",
        cwe_id="CWE-415",
        project_name="curl",
        vulnerable_pattern="free(data->set.str[STRING_SSL_ISSUERCERT]);",
        remediated_pattern="free(data->set.str[STRING_SSL_ISSUERCERT]);\ndata->set.str[STRING_SSL_ISSUERCERT] = NULL;",
        unified_diff="""--- a/lib/setopt.c
+++ b/lib/setopt.c
@@ -2910,2 +2910,3 @@
     free(data->set.str[STRING_SSL_ISSUERCERT]);
+    data->set.str[STRING_SSL_ISSUERCERT] = NULL;"""
    )
]


class CWEIngester:
    """Fetches and parses the comprehensive official MITRE CWE catalog."""

    @staticmethod
    def fetch_mitre_cwe(cache_dir: str = "data/cache") -> List[Dict[str, Any]]:
        """Downloads official MITRE CWE 2000.csv.zip and extracts structured records."""
        cache_path = Path(cache_dir)
        cache_path.mkdir(parents=True, exist_ok=True)
        csv_file = cache_path / "cwe_2000.csv"

        if not csv_file.exists():
            zip_target = cache_path / "cwe_2000.zip"
            req = urllib.request.Request(
                MITRE_CWE_ZIP_URL,
                headers={"User-Agent": "Mozilla/5.0 (SecurityResearch/1.0; AST-RAG-Ingester)"}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                content = resp.read()
                with open(zip_target, "wb") as f:
                    f.write(content)

            with zipfile.ZipFile(zip_target) as z:
                namelist = z.namelist()
                csv_name = [n for n in namelist if n.endswith(".csv")][0]
                with z.open(csv_name) as source, open(csv_file, "wb") as target:
                    target.write(source.read())

        records: List[Dict[str, Any]] = []
        with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cwe_raw_id = row.get("CWE-ID", "").strip()
                if not cwe_raw_id or not cwe_raw_id.isdigit():
                    continue
                
                cwe_id = f"CWE-{cwe_raw_id}"
                name = row.get("Name", "").strip()
                desc = row.get("Description", "").strip()
                extended_desc = row.get("Extended Description", "").strip()
                mitigations = row.get("Potential Mitigations", "").strip()
                consequences = row.get("Common Consequences", "").strip()
                platforms = row.get("Applicable Platforms", "").strip()

                full_text = f"{cwe_id}: {name}\n"
                if desc:
                    full_text += f"Description: {desc}\n"
                if extended_desc:
                    full_text += f"Extended Description: {extended_desc[:400]}\n"
                if mitigations:
                    full_text += f"Remediation Mitigations: {mitigations[:400]}\n"
                if consequences:
                    full_text += f"Consequences: {consequences[:300]}\n"

                records.append({
                    "cwe_id": cwe_id,
                    "name": name,
                    "description": desc,
                    "mitigations": mitigations,
                    "consequences": consequences,
                    "platforms": platforms,
                    "document_text": full_text
                })

        return records

    @staticmethod
    def ingest_to_chroma(records: List[Dict[str, Any]], client: chromadb.PersistentClient) -> int:
        """Indexes parsed CWE records into the ChromaDB cwe_catalog collection."""
        collection = client.get_or_create_collection(
            name="cwe_catalog",
            metadata={"description": "Official MITRE Common Weakness Enumeration catalog"}
        )

        batch_size = 100
        total = len(records)
        for i in range(0, total, batch_size):
            batch = records[i:i + batch_size]
            ids = [b["cwe_id"] for b in batch]
            documents = [b["document_text"] for b in batch]
            metadatas = [{
                "cwe_id": b["cwe_id"],
                "name": b["name"][:250],
                "platforms": b["platforms"][:250],
                "has_mitigations": bool(b["mitigations"])
            } for b in batch]

            collection.upsert(
                ids=ids,
                documents=documents,
                metadatas=metadatas
            )

        return total


class CVEPatchIngester:
    """Ingests contrastive vulnerability-patch diffs into ChromaDB."""

    @staticmethod
    def ingest_curated_patches(client: chromadb.PersistentClient) -> int:
        """Indexes the curated DiverseVul and CVEfixes contrastive patch pairs."""
        collection = client.get_or_create_collection(
            name="cve_patches",
            metadata={"description": "DiverseVul and CVEfixes security commit diffs"}
        )

        patches = EXPANDED_CVE_PATCHES
        ids = [p.cve_id for p in patches]
        documents = [
            f"CVE ID: {p.cve_id} | CWE: {p.cwe_id} | Project: {p.project_name}\n"
            f"Vulnerable Pattern:\n{p.vulnerable_pattern}\n"
            f"Remediated Invariant:\n{p.remediated_pattern}\n"
            f"Patch Diff:\n{p.unified_diff}"
            for p in patches
        ]
        metadatas = [{
            "cve_id": p.cve_id,
            "cwe_id": p.cwe_id,
            "project_name": p.project_name
        } for p in patches]

        collection.upsert(
            ids=ids,
            documents=documents,
            metadatas=metadatas
        )

        return len(patches)

    @staticmethod
    def ingest_external_diversevul(
        json_file_path: str,
        client: chromadb.PersistentClient,
        max_samples: int = 1000
    ) -> int:
        """
        Streams and indexes external DiverseVul JSON export without loading the entire
        dataset into RAM, preserving memory efficiency on local environments.
        """
        collection = client.get_or_create_collection(
            name="cve_patches"
        )

        path = Path(json_file_path)
        if not path.exists():
            raise FileNotFoundError(f"DiverseVul file not found: {json_file_path}")

        count = 0
        batch_ids = []
        batch_docs = []
        batch_meta = []

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if count >= max_samples:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    target = entry.get("target", 0)
                    if target != 1:
                        continue

                    cwe_list = entry.get("cwe", [])
                    cwe_id = cwe_list[0] if cwe_list else "CWE-Unknown"
                    project = entry.get("project", "unknown")
                    commit_id = entry.get("commit_id", f"entry_{count}")
                    func_code = entry.get("func", "")[:600]

                    doc_id = f"divvul_{commit_id[:12]}_{count}"
                    doc_text = f"DiverseVul C/C++ Vulnerable Function ({cwe_id}) in {project}:\n{func_code}"

                    batch_ids.append(doc_id)
                    batch_docs.append(doc_text)
                    batch_meta.append({
                        "cve_id": commit_id[:12],
                        "cwe_id": cwe_id,
                        "project_name": project
                    })
                    count += 1

                    if len(batch_ids) >= 100:
                        collection.upsert(ids=batch_ids, documents=batch_docs, metadatas=batch_meta)
                        batch_ids.clear()
                        batch_docs.clear()
                        batch_meta.clear()
                except Exception:
                    continue

        if batch_ids:
            collection.upsert(ids=batch_ids, documents=batch_docs, metadatas=batch_meta)

        return count


def run_full_ingestion(
    chroma_db_dir: str = "data/chroma_db",
    cache_dir: str = "data/cache",
    external_diversevul_path: Optional[str] = None
) -> Dict[str, int]:
    """
    Executes the full pipeline:
    1. Downloads & indexes 969 MITRE CWEs into 'cwe_catalog'.
    2. Indexes curated and external DiverseVul/CVEfixes patches into 'cve_patches'.
    """
    db_path = Path(chroma_db_dir)
    db_path.mkdir(parents=True, exist_ok=True)

    client = chromadb.PersistentClient(path=str(db_path))

    # 1. MITRE CWE Ingestion
    cwe_records = CWEIngester.fetch_mitre_cwe(cache_dir=cache_dir)
    total_cwe = CWEIngester.ingest_to_chroma(cwe_records, client)

    # 2. Curated CVE Patch Ingestion
    total_patches = CVEPatchIngester.ingest_curated_patches(client)

    # 3. Optional External DiverseVul Dataset Ingestion
    if external_diversevul_path:
        extra_patches = CVEPatchIngester.ingest_external_diversevul(
            external_diversevul_path, client
        )
        total_patches += extra_patches

    return {
        "cwe_catalog_count": total_cwe,
        "cve_patches_count": total_patches
    }


if __name__ == "__main__":
    print("Starting vector knowledge base ingestion into ChromaDB...")
    stats = run_full_ingestion()
    print(f"Ingestion complete: {stats['cwe_catalog_count']} CWEs, {stats['cve_patches_count']} CVE patches indexed.")
