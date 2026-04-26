from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel, Field

from .detector import analyze_lines


class AnalyzeRequest(BaseModel):
    lines: list[str] = Field(..., min_length=1)
    threshold: int = Field(default=5, ge=1)
    year: int = Field(default=2026, ge=1970)


app = FastAPI(
    title="LogGuard API",
    version="0.1.0",
    description="Analyze SSH authentication logs and report suspicious IPs.",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze")
def analyze(request: AnalyzeRequest) -> dict:
    return analyze_lines(request.lines, threshold=request.threshold, year=request.year)

