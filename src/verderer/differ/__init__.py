"""The semantic differ (DESIGN §6.2).

Layered, and strictly outside the trust core: every layer feeds the typed diff
taxonomy, which is the alertable unit. M0 ships L0 (structural normalisation) and L1
(term watch). The differ's labels are best-effort and human-reviewable — never a
verified property.
"""
