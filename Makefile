.PHONY: m7 m7-full plots
m7:
	QUICK=1 CLEAN_LEGACY=1 USE_PARALLEL=no bash tools/scripts/reproduce.sh
	python tools/scripts/checks.py docs/eval/out/runs/$$(git rev-parse --short HEAD)

m7-full:
	OPS="1000,10000,50000" PEERS="1,3,5" SEEDS="1 2 3 4 5 6 7 8 9 10" USE_PARALLEL=yes \
	bash tools/scripts/reproduce.sh
	python tools/scripts/checks.py docs/eval/out/runs/$$(git rev-parse --short HEAD)

plots:
	python tools/scripts/plot.py docs/eval/out/runs/$$(git rev-parse --short HEAD) docs/eval/plots

.PHONY: repro verify-golden sbom audit

repro:
	SOURCE_DATE_EPOCH=1 scripts/reproduce.sh

verify-golden:
	SOURCE_DATE_EPOCH=1 scripts/verify_golden.sh

sbom:
	cargo cyclonedx --format json --output docs/eval/out/sbom.json

audit:
	cargo audit
	cargo deny check
