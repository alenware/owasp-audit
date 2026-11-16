---
type: llm
focus: trace
weight: 1
---

The report identifies that retrieval.search queries the vector store without a tenant_id filter, so documents of one tenant can reach users of another tenant (LLM08 or LLM02, cross-tenant leak).
