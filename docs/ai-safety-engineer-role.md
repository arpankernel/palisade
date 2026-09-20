# Reference: the AI Safety Engineer role (product spec)

Palisade's north star is to *be* this role as a pluggable agent. This job
description is treated as the requirements doc; `typesafe-integration.md` maps
each duty to a capability.

## About the role
We're looking for an engineer to make our AI systems measurably safer to deploy.
You'll build the evaluations, guardrails, and monitoring that catch failures
before users do, and turn safety from a review step into infrastructure. This
role sits between research and production: you'll translate safety concerns into
systems that run at scale.

## What you'll do
- Design and build evaluations that measure model and agent behavior: harmful
  outputs, jailbreak resistance, tool-use safety, and failure modes under
  adversarial pressure.
- Build red-teaming pipelines and automated adversarial testing to surface
  vulnerabilities before release.
- Develop runtime guardrails: input/output filtering, policy enforcement,
  sandboxing and isolation for agent execution, and circuit-breaking for runaway
  or high-cost behavior.
- Build monitoring and observability for deployed systems, so unsafe or anomalous
  behavior is detected and traced in production.
- Write and maintain safety cases: clear, evidence-backed arguments for why a
  system is safe enough to ship.
- Partner with research on alignment techniques (RLHF/RLAIF, fine-tuning for
  refusal behavior, robustness) and turn findings into shippable systems.
- Investigate incidents, do root-cause analysis on safety failures, and close the
  loop with concrete fixes and regression tests.

## Required qualifications
- Strong software engineering fundamentals: design, build, and ship reliable
  systems in production, not just prototypes.
- Proficiency in Python, plus one systems language (Go, Rust, or C++) for the
  infrastructure layer.
- Working understanding of modern LLMs and agents: how they're trained, prompted,
  tooled, and where they break.
- Experience building evaluation, testing, or monitoring systems for ML models or
  complex distributed systems.
- A rigorous, adversarial mindset: you instinctively look for how something
  fails, not just whether it works.
- Clear written communication, especially an evidence-backed argument about risk.

## Nice to have
- Red-teaming, security engineering, or sandboxing/isolation (containers,
  microVMs, syscall filtering).
- Familiarity with agent frameworks and the failure modes specific to multi-step,
  tool-using agents.
- Exposure to interpretability, robustness, or alignment research.
- Track record of open-source contributions to AI safety, evals, or infra tooling.

## What success looks like
In the first six months, unsafe behaviors that would have shipped are being
caught automatically, deployment decisions are backed by real evidence rather
than intuition, and safety is something the team builds on top of rather than
bolts on at the end.
