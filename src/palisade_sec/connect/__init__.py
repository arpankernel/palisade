"""Connected surfaces: GitHub, Slack and LLM providers.

Everything in this package can touch the network, and nothing in the offline
core (scan, map, baseline, fix) imports it. That split is what keeps the
scanner's "no network, no key" guarantee true and testable.
"""
