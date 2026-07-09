"""
Retrieval-Augmented Generation module.

Retrieval: TF-IDF + cosine similarity over the local knowledge base.
  (Swap-in note: for a stronger version, replace TfidfVectorizer with
  sentence-transformers embeddings + FAISS/Chroma. TF-IDF is used here
  so the project runs instantly with no model downloads.)

Generation: if ANTHROPIC_API_KEY is set, the retrieved chunks are passed
  to Claude to produce a grounded, conversational answer. If no key is
  set, we fall back to a clean extractive answer built directly from the
  retrieved documents, so the assistant still works out of the box.
"""

import json
import os
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

DATA_PATH = Path(__file__).parent / "data" / "knowledge_base.json"


class SafetyRAG:
    def __init__(self):
        with open(DATA_PATH, "r") as f:
            self.docs = json.load(f)

        corpus = [f"{d['title']}. {d['content']}" for d in self.docs]
        self.vectorizer = TfidfVectorizer(stop_words="english")
        self.doc_matrix = self.vectorizer.fit_transform(corpus)

        self.client = None
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if api_key:
            try:
                import anthropic
                self.client = anthropic.Anthropic(api_key=api_key)
            except Exception:
                self.client = None

    def retrieve(self, query: str, top_k: int = 3):
        query_vec = self.vectorizer.transform([query])
        sims = cosine_similarity(query_vec, self.doc_matrix)[0]
        top_idx = np.argsort(sims)[::-1][:top_k]
        results = []
        for i in top_idx:
            if sims[i] > 0:
                results.append({**self.docs[i], "score": float(sims[i])})
        return results

    def answer(self, query: str, incident_category: str | None = None) -> dict:
        retrieved = self.retrieve(query, top_k=3)

        if not retrieved:
            return {
                "answer": (
                    "I don't have specific guidance for that in my knowledge base yet. "
                    "Stay on the line, keep moving toward a populated, well-lit area, "
                    "and help is being routed to you."
                ),
                "sources": [],
                "generated_by": "fallback",
            }

        if self.client:
            context = "\n\n".join(
                f"[{d['title']}]\n{d['content']}" for d in retrieved
            )
            system = (
                "You are a calm, concise safety assistant inside an emergency response app. "
                "A user is in a potentially distressing real-world situation and help is already "
                "being dispatched to them in parallel. Answer ONLY using the provided context. "
                "Keep the tone steady and reassuring, use short direct sentences, and give clear "
                "action steps. Do not diagnose, do not give legal advice beyond what is provided, "
                "and remind them help is on the way. Keep the answer under 120 words."
            )
            try:
                resp = self.client.messages.create(
                    model="claude-sonnet-4-6",
                    max_tokens=400,
                    system=system,
                    messages=[
                        {
                            "role": "user",
                            "content": f"Context:\n{context}\n\nUser situation: {query}",
                        }
                    ],
                )
                text = "".join(
                    block.text for block in resp.content if block.type == "text"
                )
                return {
                    "answer": text.strip(),
                    "sources": [d["title"] for d in retrieved],
                    "generated_by": "claude-sonnet-4-6",
                }
            except Exception:
                pass  # fall through to extractive fallback

        # Extractive fallback: no LLM available, build a clean answer from docs directly
        lead = retrieved[0]
        steps = lead["content"]
        answer = f"{lead['title']}: {steps}"
        if len(retrieved) > 1:
            answer += f"\n\nAlso relevant: {retrieved[1]['title']} — {retrieved[1]['content']}"
        answer += "\n\nHelp is being routed to your location."
        return {
            "answer": answer,
            "sources": [d["title"] for d in retrieved],
            "generated_by": "extractive_fallback",
        }


safety_rag = SafetyRAG()
