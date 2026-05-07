"""Diagnostics endpoint — verify the full Deshifro pipeline is working."""

from __future__ import annotations

import time

from fastapi import APIRouter

router = APIRouter(tags=["diagnostics"])


@router.get("/diagnostics")
def diagnostics():
    """Run a full health check: tools, AI, dependencies. Returns what works and what doesn't."""
    results = {
        "version": "0.2.0",
        "checks": [],
    }

    # 1. Python deps
    deps = {}
    for mod in ["fastapi", "uvicorn", "sqlalchemy", "pydantic", "numpy",
                "r2pipe", "pefile", "yara", "frida"]:
        try:
            __import__(mod)
            deps[mod] = "ok"
        except ImportError:
            deps[mod] = "missing"
    results["checks"].append({"name": "python_deps", "result": deps})

    # 2. RE tools
    from core.tools.binwalk_tool import BinwalkTool
    from core.tools.die_tool import DieTool
    from core.tools.diff_tool import DiffTool
    from core.tools.entropy_tool import EntropyTool
    from core.tools.frida_tool import FridaTool
    from core.tools.ghidra import GhidraTool
    from core.tools.radare2 import Radare2Tool
    from core.tools.shellcode_tool import ShellcodeTool
    from core.tools.strings_tool import StringsTool
    from core.tools.virustotal import VirusTotalTool
    from core.tools.yara_tool import YaraTool
    from core.tools.archive_tool import ArchiveTool

    tools = [
        StringsTool(), EntropyTool(), YaraTool(), DieTool(),
        Radare2Tool(), GhidraTool(), FridaTool(), BinwalkTool(),
        VirusTotalTool(), DiffTool(), ShellcodeTool(), ArchiveTool(),
    ]
    tool_status = {t.name: t.is_available() for t in tools}
    results["checks"].append({"name": "tools", "result": tool_status})

    # 3. AI / Ollama
    from core.ai.interpreter import is_ai_available, get_available_models, OLLAMA_HOST, OLLAMA_MODEL
    ai_check = {
        "ollama_host": OLLAMA_HOST,
        "ollama_reachable": is_ai_available(),
        "configured_model": OLLAMA_MODEL,
        "installed_models": get_available_models(),
    }
    results["checks"].append({"name": "ai", "result": ai_check})

    # 4. Live AI test (small request)
    if ai_check["ollama_reachable"]:
        try:
            from core.ai.interpreter import _call_ollama
            start = time.time()
            response = _call_ollama("", "Reply with just: OK", max_tokens=10)
            ai_test = {
                "success": True,
                "duration_seconds": round(time.time() - start, 2),
                "response_preview": response[:100],
            }
        except Exception as e:
            ai_test = {"success": False, "error": str(e)[:300]}
        results["checks"].append({"name": "ai_live_test", "result": ai_test})

    # 5. DB
    try:
        from api.database.engine import SessionLocal
        from api.database.orm_models import Upload, AnalysisJob
        db = SessionLocal()
        upload_count = db.query(Upload).count()
        job_count = db.query(AnalysisJob).count()
        db.close()
        db_check = {"upload_count": upload_count, "job_count": job_count, "ok": True}
    except Exception as e:
        db_check = {"ok": False, "error": str(e)}
    results["checks"].append({"name": "database", "result": db_check})

    # Summary
    all_tools_count = sum(1 for v in tool_status.values() if v)
    summary = {
        "tools_working": f"{all_tools_count}/{len(tool_status)}",
        "ai_working": ai_check["ollama_reachable"],
        "ready_for_analysis": all_tools_count >= 3 and ai_check["ollama_reachable"],
    }
    results["summary"] = summary

    return results
