.PHONY: test check demo
test:
	python3 -B -m unittest discover -s tests -v
check: test
	git diff --check
demo:
	python3 -B -m observer --config config.example.json
